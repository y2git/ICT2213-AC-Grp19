from datetime import datetime
import socket
import threading
import sqlite3
import elgalmal

server_PORT = 60
server_IP = '127.0.0.1'
BUF_SIZE = 4096
encrypted_locations = {}
server_public_key = None
server_private_key = None
connected_clients = {}
client_public_keys = {}  # Store client public keys


def init_db():
    conn = sqlite3.connect('test.db', check_same_thread=False)
    try:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS user
                         (username TEXT PRIMARY KEY, 
                          password TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS friendships
                         (user1 TEXT, 
                          user2 TEXT,
                          PRIMARY KEY(user1, user2),
                          FOREIGN KEY(user1) REFERENCES user(username),
                          FOREIGN KEY(user2) REFERENCES user(username))''')
        # New table for friend requests
        cursor.execute('''CREATE TABLE IF NOT EXISTS friend_requests
                         (sender TEXT, 
                          receiver TEXT,
                          status TEXT DEFAULT 'pending',
                          timestamp TEXT,
                          PRIMARY KEY(sender, receiver),
                          FOREIGN KEY(sender) REFERENCES user(username),
                          FOREIGN KEY(receiver) REFERENCES user(username))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS public_keys
                         (username TEXT PRIMARY KEY,
                          p TEXT,
                          g TEXT,
                          h TEXT,
                          FOREIGN KEY(username) REFERENCES user(username))''')
        conn.commit()
    finally:
        conn.close()


def generate_global_keys():
    global server_public_key, server_private_key
    server_public_key, server_private_key = elgalmal.generate_keys()


generate_global_keys()


def get_db_connection():
    conn = sqlite3.connect('test.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def login_user(username, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ? AND password = ?', (username, password))
        return cursor.fetchone() is not None
    finally:
        conn.close()


def create_user(username, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO user (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def update_location(username, enc_x, enc_y):
    encrypted_locations[username] = (enc_x, enc_y)


def handle_proximity_request(sender, target, con):
    try:
        # [1] Verify friendship
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM friendships 
                        WHERE (user1=? AND user2=?) 
                        OR (user1=? AND user2=?)''',
                       (sender, target, target, sender))
        if not cursor.fetchone():
            con.send("ERROR:Not friends\n".encode())
            return

        # [2] Get encrypted locations
        sender_loc = encrypted_locations.get(sender)
        target_loc = encrypted_locations.get(target)
        if not sender_loc or not target_loc:
            con.send("ERROR:Location unavailable\n".encode())
            return

        # [3] Parse coordinates - remove debug prints
        p = server_public_key[0]
        try:
            # Parse sender coordinates
            s_x_parts = sender_loc[0].split(',')
            s_y_parts = sender_loc[1].split(',')
            s_x = (int(s_x_parts[0]), int(s_x_parts[1]))
            s_y = (int(s_y_parts[0]), int(s_y_parts[1]))

            # Parse target coordinates
            t_x_parts = target_loc[0].split(',')
            t_y_parts = target_loc[1].split(',')
            t_x = (int(t_x_parts[0]), int(t_x_parts[1]))
            t_y = (int(t_y_parts[0]), int(t_y_parts[1]))

        except Exception as e:
            # Remove debug print
            con.send(f"ERROR:Invalid coordinate format\n".encode())
            return

        # [4] Decrypt coordinates to get actual values
        s_x_val = elgalmal.decrypt(server_private_key, s_x[0], s_x[1])
        s_y_val = elgalmal.decrypt(server_private_key, s_y[0], s_y[1])
        t_x_val = elgalmal.decrypt(server_private_key, t_x[0], t_x[1])
        t_y_val = elgalmal.decrypt(server_private_key, t_y[0], t_y[1])

        # [5] Calculate grid cell positions (each cell is 1000x1000 units)
        # Make sure all values are integers
        s_x_val = int(s_x_val)
        s_y_val = int(s_y_val)
        t_x_val = int(t_x_val)
        t_y_val = int(t_y_val)

        s_cell_x = s_x_val // 1000
        s_cell_y = s_y_val // 1000
        t_cell_x = t_x_val // 1000
        t_cell_y = t_y_val // 1000

        # [6] Users are nearby if they are in the same grid cell
        is_near = (s_cell_x == t_cell_x) and (s_cell_y == t_cell_y)

        con.send(f"PROXIMITY:{str(is_near).upper()}\n".encode())

    except Exception as e:
        # Keep error logging for server admin, but remove traceback
        print(f"Error in proximity check: {str(e)}")
        con.send(f"ERROR:{str(e)}\n".encode())
    finally:
        conn.close()


def handle_friend_request(sender, target, con):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # Check if user is trying to add themselves
        if sender == target:
            con.send("ERROR:Cannot add yourself as a friend\n".encode())
            return

        # Check if target user exists
        cursor.execute('SELECT * FROM user WHERE username = ?', (target,))
        if not cursor.fetchone():
            con.send("ERROR:User not found\n".encode())
            return

        # Check if they are already friends
        cursor.execute('''SELECT * FROM friendships 
                         WHERE (user1 = ? AND user2 = ?)
                         OR (user1 = ? AND user2 = ?)''',
                       (sender, target, target, sender))
        if cursor.fetchone():
            con.send("ERROR:Already friends\n".encode())
            return

        # Check for existing request in either direction
        cursor.execute('''SELECT * FROM friend_requests 
                         WHERE (sender = ? AND receiver = ?)''',
                       (sender, target))
        if cursor.fetchone():
            con.send("ERROR:Friend request already sent\n".encode())
            return

        # Check if there's a pending request from target to sender
        cursor.execute('''SELECT * FROM friend_requests 
                         WHERE (sender = ? AND receiver = ? AND status = 'pending')''',
                       (target, sender))
        if cursor.fetchone():
            # Auto-accept since the other person already sent a request
            cursor.execute('DELETE FROM friend_requests WHERE sender = ? AND receiver = ?',
                           (target, sender))
            cursor.execute('INSERT INTO friendships VALUES (?, ?)', (sender, target))
            conn.commit()
            con.send("SUCCESS:Friend request accepted automatically\n".encode())

            # Notify the other user if they're online
            if target in connected_clients:
                connected_clients[target][0].send(f"NOTIFICATION:{sender} accepted your friend request\n".encode())
            return

        # Create a new friend request
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('INSERT INTO friend_requests VALUES (?, ?, ?, ?)',
                       (sender, target, 'pending', timestamp))
        conn.commit()
        con.send("SUCCESS:Friend request sent\n".encode())

        # Notify the target user if they're online
        if target in connected_clients:
            connected_clients[target][0].send(f"NOTIFICATION:New friend request from {sender}\n".encode())
    except Exception as e:
        con.send(f"ERROR:{str(e)}\n".encode())
    finally:
        conn.close()


def handle_friend_response(username, sender, response, con):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Check if there is a pending request
        cursor.execute('''SELECT * FROM friend_requests 
                         WHERE sender = ? AND receiver = ? AND status = 'pending' ''',
                       (sender, username))
        if not cursor.fetchone():
            con.send("ERROR:No pending request from this user\n".encode())
            return

        if response.upper() == 'ACCEPT':
            # Add to friendships
            cursor.execute('INSERT INTO friendships VALUES (?, ?)', (sender, username))
            # Remove from requests
            cursor.execute('DELETE FROM friend_requests WHERE sender = ? AND receiver = ?',
                           (sender, username))
            conn.commit()
            con.send("SUCCESS:Friend request accepted\n".encode())

            # Notify the sender if they're online
            if sender in connected_clients:
                connected_clients[sender][0].send(f"NOTIFICATION:{username} accepted your friend request\n".encode())
        else:
            # Just remove the request
            cursor.execute('DELETE FROM friend_requests WHERE sender = ? AND receiver = ?',
                           (sender, username))
            conn.commit()
            con.send("SUCCESS:Friend request declined\n".encode())
    except Exception as e:
        con.send(f"ERROR:{str(e)}\n".encode())
    finally:
        conn.close()


def get_pending_requests(username, con):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT sender FROM friend_requests WHERE receiver = ? AND status = "pending"',
                       (username,))
        requests = [row['sender'] for row in cursor.fetchall()]
        con.send(f"REQUESTS:{','.join(requests)}\n".encode())
    except Exception as e:
        con.send(f"ERROR:{str(e)}\n".encode())
    finally:
        conn.close()


def get_friends_list(username, con):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''SELECT user2 as friend FROM friendships WHERE user1 = ?
                         UNION
                         SELECT user1 as friend FROM friendships WHERE user2 = ?''',
                       (username, username))
        friends = [row['friend'] for row in cursor.fetchall()]
        con.send(f"FRIENDS:{','.join(friends)}\n".encode())
    except Exception as e:
        con.send(f"ERROR:{str(e)}\n".encode())
    finally:
        conn.close()


def save_public_key(username, pubkey):
    p, g, h = map(str, pubkey)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO public_keys (username, p, g, h) VALUES (?, ?, ?, ?)',
            (username, p, g, h)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving public key: {str(e)}")
        return False
    finally:
        conn.close()


def get_public_key(username):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT p, g, h FROM public_keys WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result:
            return (int(result['p']), int(result['g']), int(result['h']))
        return None
    finally:
        conn.close()


def handle_message(sender, receiver, ciphertext, con):
    if receiver not in connected_clients:
        con.send("ERROR:User offline\n".encode())
        return

    try:
        connected_clients[receiver][0].send(f"MESSAGE:{sender}:{ciphertext}\n".encode())
        con.send("SUCCESS:Message sent\n".encode())
    except Exception as e:
        con.send(f"ERROR:Failed to send: {str(e)}\n".encode())


def log_action(username, action, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] USER: {username.ljust(15)} ACTION: {action.ljust(20)} DETAILS: {details}")


def client_handler(con, addr):
    print(f'New connection from {addr}')
    username = None
    buffer = ""

    try:
        con.send(f"HELLO:{server_public_key[0]},{server_public_key[1]},{server_public_key[2]}\n".encode())

        while True:
            data = con.recv(BUF_SIZE).decode()
            if not data:
                break
            buffer += data

            while '\n' in buffer:
                msg, buffer = buffer.split('\n', 1)
                parts = msg.strip().split(':', 2)

                if not parts:
                    continue

                command = parts[0].upper()

                try:
                    if command == 'REGISTER':
                        if len(parts) < 3:
                            con.send("ERROR:Missing fields\n".encode())
                            continue
                        username, password = parts[1], parts[2]
                        if create_user(username, password):
                            con.send("SUCCESS:Registered\n".encode())
                        else:
                            con.send("ERROR:Username exists\n".encode())

                    elif command == 'LOGIN':
                        if len(parts) < 3:
                            con.send("ERROR:Missing fields\n".encode())
                            continue
                        username_attempt, password = parts[1], parts[2]
                        # Check if user is already logged in
                        if username_attempt in connected_clients:
                            con.send("ERROR:User already logged in\n".encode())
                            continue
                        if login_user(username_attempt, password):
                            username = username_attempt
                            connected_clients[username] = (con, addr)
                            con.send("SUCCESS:Logged in\n".encode())
                            print(f"User {username} logged in from {addr}")
                        else:
                            con.send("ERROR:Invalid credentials\n".encode())

                    elif command == 'LOGOUT':
                        if username and username in connected_clients:
                            del connected_clients[username]
                            con.send("SUCCESS:Logged out\n".encode())
                            print(f"User {username} logged out")
                            username = None
                        else:
                            con.send("ERROR:Not logged in\n".encode())

                    elif command == 'GET_LOCATION':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue

                        # Get encrypted location
                        user_loc = encrypted_locations.get(username)
                        if not user_loc:
                            con.send("ERROR:No location set\n".encode())
                            continue

                        try:
                            # Parse coordinates
                            x_enc = tuple(map(int, user_loc[0].split(',')))
                            y_enc = tuple(map(int, user_loc[1].split(',')))

                            # Decrypt coordinates
                            x_val = elgalmal.decrypt(server_private_key, x_enc[0], x_enc[1])
                            y_val = elgalmal.decrypt(server_private_key, y_enc[0], y_enc[1])

                            # Calculate grid cell
                            cell_x = x_val // 1000
                            cell_y = y_val // 1000

                            # Send response
                            response = f"LOCATION:{x_val},{y_val}:{cell_x},{cell_y}\n"
                            con.send(response.encode())

                        except Exception as e:
                            con.send(f"ERROR:Could not retrieve location: {str(e)}\n".encode())

                    elif command == 'REGISTER_PUBKEY':
                        if not username or len(parts) < 2:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        pubkey_parts = parts[1].split(',')
                        if len(pubkey_parts) != 3:
                            con.send("ERROR:Invalid public key format\n".encode())
                            continue
                        pubkey = tuple(map(int, pubkey_parts))
                        client_public_keys[username] = pubkey
                        if save_public_key(username, pubkey):
                            con.send("SUCCESS:Public key registered\n".encode())
                        else:
                            con.send("ERROR:Failed to save public key\n".encode())

                    elif command == 'GET_PUBKEY':
                        if not username or len(parts) < 2:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        target = parts[1]
                        pubkey = get_public_key(target)
                        if pubkey:
                            con.send(f"PUBKEY:{target}:{pubkey[0]},{pubkey[1]},{pubkey[2]}\n".encode())
                        else:
                            con.send(f"ERROR:No public key for {target}\n".encode())

                    elif command == 'ADD_FRIEND':
                        if not username or len(parts) < 2:
                            con.send("ERROR:Invalid request\n".encode())
                            continue
                        handle_friend_request(username, parts[1], con)

                    elif command == 'FRIEND_RESPONSE':
                        if not username or len(parts) < 3:
                            con.send("ERROR:Invalid request\n".encode())
                            continue
                        handle_friend_response(username, parts[1], parts[2], con)

                    elif command == 'GET_REQUESTS':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        get_pending_requests(username, con)

                    elif command == 'GET_FRIENDS':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        get_friends_list(username, con)

                    elif command == 'UPDATE_LOCATION':
                        if not username or len(parts) < 3:
                            con.send("ERROR:Invalid coordinates\n".encode())
                            continue

                        x_str, y_str = parts[1], parts[2]

                        try:
                            update_location(username, x_str, y_str)
                            con.send("SUCCESS:Location updated\n".encode())
                        except Exception as e:
                            con.send(f"ERROR:Processing error: {str(e)}\n".encode())

                    elif command == 'PROXIMITY':
                        if not username or len(parts) < 2:
                            con.send("ERROR:Invalid request\n".encode())
                            continue
                        handle_proximity_request(username, parts[1], con)

                    elif command == 'SEND_MSG':
                        if not username or len(parts) < 3:
                            con.send("ERROR:Invalid message\n".encode())
                            continue
                        handle_message(username, parts[1], parts[2], con)

                    else:
                        con.send("ERROR:Invalid command\n".encode())

                except Exception as e:
                    con.send(f"ERROR:Processing error: {str(e)}\n".encode())

    finally:
        if username and username in connected_clients:
            del connected_clients[username]
        con.close()
        print(f"{addr} disconnected")


if __name__ == "__main__":
    init_db()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((server_IP, server_PORT))
    s.listen(5)
    print("Server Online")

    try:
        while True:
            con, addr = s.accept()
            threading.Thread(target=client_handler, args=(con, addr)).start()
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        s.close()