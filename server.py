from datetime import datetime
import socket
import threading
import sqlite3
import elgamal
import hashlib
import os
import base64
import json
import queue
from hmac_utils import compute_hmac, verify_hmac

server_PORT = 60
server_IP = '127.0.0.1'
BUF_SIZE = 65536

encrypted_locations = {}  # Stores plain coordinates

# ElGamal encryption for general use
server_public_key = None
server_private_key = None

connected_clients = {}
client_public_keys = {}  # Store client public keys

def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    storage_format = base64.b64encode(salt + key).decode('utf-8')
    return storage_format

def verify_password(stored_password, provided_password):
    try:
        decoded = base64.b64decode(stored_password.encode('utf-8'))
        salt = decoded[:32]
        stored_key = decoded[32:]
        key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return hashlib.compare_digest(key, stored_key)
    except Exception:
        return False

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
        # Remove bgn_public_keys table as proximity code is removed
        conn.commit()
    finally:
        conn.close()

def generate_global_keys():
    global server_public_key, server_private_key
    server_public_key, server_private_key = elgamal.generate_keys()
    print("Encryption keys generated: ElGamal keys for general encryption")

def get_db_connection():
    conn = sqlite3.connect('test.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def login_user(username, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM user WHERE username = ?', (username,))
        result = cursor.fetchone()
        if not result:
            return False
        stored_password = result['password']
        # Direct match for plaintext (to be upgraded)
        if password == stored_password:
            try:
                hashed_password = hash_password(password)
                cursor.execute('UPDATE user SET password = ? WHERE username = ?', (hashed_password, username))
                conn.commit()
            except Exception as e:
                print(f"Warning: Failed to upgrade password: {e}")
            return True
        if len(stored_password) > 40:
            try:
                raw_data = base64.b64decode(stored_password)
                if len(raw_data) >= 64:
                    salt = raw_data[:32]
                    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
                    expected_hash = base64.b64encode(salt + key).decode('utf-8')
                    if expected_hash == stored_password:
                        return True
                    if hashlib.compare_digest(raw_data[32:], key):
                        return True
            except Exception as e:
                print(f"Hash verification attempt failed: {e}")
        return False
    finally:
        conn.close()

def create_user(username, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO user (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_location(username, location_data):
    try:
        # Assume simple "x,y" coordinates format
        coordinates = location_data.split(',')
        if len(coordinates) != 2:
            raise ValueError("Coordinates must be in format: x,y")
        x, y = map(int, coordinates)
        if not (0 <= x <= 99999 and 0 <= y <= 99999):
            raise ValueError("Coordinates must be between 0 and 99999")
        location_data = f"{x},{y}"
        encrypted_locations[username] = {
            "data": location_data,
            "encrypted": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return True
    except Exception as e:
        print(f"Error updating location for {username}: {e}")
        return False

def handle_get_friend_location(username, friend, con):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM friendships 
                          WHERE (user1=? AND user2=?) OR (user1=? AND user2=?)''',
                       (username, friend, friend, username))
        if not cursor.fetchone():
            con.send("ERROR:Not friends\n".encode())
            return
        friend_location = encrypted_locations.get(friend)
        if not friend_location:
            con.send("ERROR:Friend's location unavailable\n".encode())
            return
        con.send(f"LOCATION:{friend_location['data']}\n".encode())
    except Exception as e:
        con.send(f"ERROR:{str(e)}\n".encode())
    finally:
        if 'conn' in locals():
            conn.close()

def handle_proximity_message(from_user, to_user, message_type, session_id, data, con=None):
    # Proximity functionality has been removed.
    if con:
        con.send("ERROR:Proximity functionality removed\n".encode())
    return False

def handle_friend_request(sender, target, con):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if sender == target:
            con.send("ERROR:Cannot add yourself as a friend\n".encode())
            return
        cursor.execute('SELECT * FROM user WHERE username = ?', (target,))
        if not cursor.fetchone():
            con.send("ERROR:User not found\n".encode())
            return
        cursor.execute('''SELECT * FROM friendships 
                          WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)''',
                       (sender, target, target, sender))
        if cursor.fetchone():
            con.send("ERROR:Already friends\n".encode())
            return
        cursor.execute('''SELECT * FROM friend_requests 
                          WHERE (sender = ? AND receiver = ?)''', (sender, target))
        if cursor.fetchone():
            con.send("ERROR:Friend request already sent\n".encode())
            return
        cursor.execute('''SELECT * FROM friend_requests 
                          WHERE (sender = ? AND receiver = ? AND status = 'pending')''', (target, sender))
        if cursor.fetchone():
            cursor.execute('DELETE FROM friend_requests WHERE sender = ? AND receiver = ?', (target, sender))
            cursor.execute('INSERT INTO friendships VALUES (?, ?)', (sender, target))
            conn.commit()
            con.send("SUCCESS:Friend request accepted automatically\n".encode())
            if target in connected_clients:
                connected_clients[target][0].send(f"NOTIFICATION:{sender} accepted your friend request\n".encode())
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('INSERT INTO friend_requests VALUES (?, ?, ?, ?)', (sender, target, 'pending', timestamp))
        conn.commit()
        con.send("SUCCESS:Friend request sent\n".encode())
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
        cursor.execute('''SELECT * FROM friend_requests 
                          WHERE sender = ? AND receiver = ? AND status = 'pending' ''', (sender, username))
        if not cursor.fetchone():
            con.send("ERROR:No pending request from this user\n".encode())
            return
        if response.upper() == 'ACCEPT':
            cursor.execute('INSERT INTO friendships VALUES (?, ?)', (sender, username))
            cursor.execute('DELETE FROM friend_requests WHERE sender = ? AND receiver = ?', (sender, username))
            conn.commit()
            con.send("SUCCESS:Friend request accepted\n".encode())
            if sender in connected_clients:
                connected_clients[sender][0].send(f"NOTIFICATION:{username} accepted your friend request\n".encode())
        else:
            cursor.execute('DELETE FROM friend_requests WHERE sender = ? AND receiver = ?', (sender, username))
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
        cursor.execute('SELECT sender FROM friend_requests WHERE receiver = ? AND status = "pending"', (username,))
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
                          SELECT user1 as friend FROM friendships WHERE user2 = ?''', (username, username))
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
        cursor.execute('INSERT OR REPLACE INTO public_keys (username, p, g, h) VALUES (?, ?, ?, ?)',
                       (username, p, g, h))
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
                msg = msg.strip()
                # Special handling for UPDATE_LOCATION to capture the entire data string
                if msg.startswith("UPDATE_LOCATION:"):
                    command = "UPDATE_LOCATION"
                    location_data = msg[len("UPDATE_LOCATION:"):]
                    parts = [command, location_data]
                # Proximity-related commands now return an error immediately.
                elif msg.startswith(("PROXIMITY_REQUEST:", "PROXIMITY_RESPONSE:", "YAO_CIRCUIT:",
                                      "YAO_OT_INIT:", "YAO_OT_COMPLETE:", "YAO_INPUTS:", "YAO_RESULT:")):
                    parts = msg.split(':', 3)
                    con.send("ERROR:Proximity functionality removed\n".encode())
                    continue
                else:
                    parts = msg.strip().split(':', 2)
                if not parts:
                    continue
                command = parts[0].upper()
                try:
                    if command == 'REGISTER':
                        if len(parts) < 3:
                            con.send("ERROR:Missing fields\n".encode())
                            continue
                        username_attempt, password = parts[1], parts[2]
                        if create_user(username_attempt, password):
                            con.send("SUCCESS:Registered\n".encode())
                        else:
                            con.send("ERROR:Username exists\n".encode())
                    elif command == 'LOGIN':
                        if len(parts) < 3:
                            con.send("ERROR:Missing fields\n".encode())
                            continue
                        username_attempt, password = parts[1], parts[2]
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
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        if len(parts) < 2:
                            con.send("ERROR:Missing location data\n".encode())
                            continue
                        location_data = parts[1]
                        try:
                            if update_location(username, location_data):
                                con.send("SUCCESS:Location updated\n".encode())
                            else:
                                con.send("ERROR:Failed to update location\n".encode())
                        except Exception as e:
                            con.send(f"ERROR:Processing error: {str(e)}\n".encode())
                    elif command == 'GET_LOCATION':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        if username in encrypted_locations:
                            con.send("SUCCESS:Location available\n".encode())
                        else:
                            con.send("ERROR:No location set\n".encode())
                    elif command == 'GET_FRIEND_LOCATION':
                        if not username or len(parts) < 2:
                            con.send("ERROR:Invalid request\n".encode())
                            continue
                        handle_get_friend_location(username, parts[1], con)
                    else:
                        con.send("ERROR:Invalid command\n".encode())
                except Exception as e:
                    con.send(f"ERROR:Processing error: {str(e)}\n".encode())
    except Exception as e:
        print(f"Error handling client: {str(e)}")
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
    generate_global_keys()
    print("\nHybrid Encryption Location Sharing Server")
    print("=========================================")
    print("ElGamal: Used for general encryption (login, friend requests)")
    print("Proximity functionality removed")
    print("Server Online - Waiting for connections...")

    try:
        while True:
            con, addr = s.accept()
            threading.Thread(target=client_handler, args=(con, addr)).start()
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        s.close()
