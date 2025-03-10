from datetime import datetime
import socket
import threading
import sqlite3
import crypto_utils
import elgamal
import hashlib
import os
import base64
from crypto_utils import deserialize_ciphertext, int_to_string, string_to_int, serialize_ciphertext


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
        cursor.execute('''CREATE TABLE IF NOT EXISTS paillier_public_keys
                         (username TEXT PRIMARY KEY,
                          n TEXT,
                          g TEXT,
                          FOREIGN KEY(username) REFERENCES user(username))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS offline_friend_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            encrypted_payload TEXT,
            timestamp TEXT
        )''')
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

def store_offline_friend_response(sender, receiver, encrypted_payload):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('INSERT INTO offline_friend_responses (sender, receiver, encrypted_payload, timestamp) VALUES (?, ?, ?, ?)',
                       (sender, receiver, encrypted_payload, timestamp))
        conn.commit()
    except Exception as e:
        print("Error storing offline friend response:", e)
    finally:
        conn.close()


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


def handle_proximity_request(sender, target, encrypted_loc_str, paillier_pubkey_str, con):
    """Route a proximity request from sender to target with improved handling for large data"""
    log_action(sender, "PROXIMITY_REQUEST", f"to {target}")

    # Check if target is a friend
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM friendships 
                         WHERE (user1=? AND user2=?) OR (user1=? AND user2=?)''',
                       (sender, target, target, sender))
        if not cursor.fetchone():
            con.send("ERROR:You are not friends with this user\n".encode())
            return False

        # Check if target is online
        if target in connected_clients:
            # Forward the request to the target
            to_con = connected_clients[target][0]

            # For large payloads, we should construct and send the message carefully
            message_to_forward = f"PROXIMITY_REQUEST:{sender}:{encrypted_loc_str}:{paillier_pubkey_str}\n"

            try:
                print(f"Forwarding proximity request from {sender} to {target}")
                print(f"Message length: {len(message_to_forward)}")

                # Send the message in chunks if it's very large
                if len(message_to_forward) > 60000:  # If approaching buffer size limit
                    print(f"WARNING: Very large proximity request message ({len(message_to_forward)} bytes)")

                to_con.send(message_to_forward.encode())
                con.send("SUCCESS:Proximity request sent\n".encode())
                return True
            except Exception as e:
                print(f"Error forwarding proximity request: {e}")
                con.send(f"ERROR:Failed to forward request: {str(e)}\n".encode())
                return False
        else:
            con.send("ERROR:Friend is not online\n".encode())
            return False
    except Exception as e:
        con.send(f"ERROR:{str(e)}\n".encode())
        return False
    finally:
        conn.close()


def handle_proximity_result(sender, target, encrypted_result_str, con):
    """Route a proximity calculation result from sender back to the requester (target)"""
    log_action(sender, "PROXIMITY_RESULT", f"to {target}")

    # Only forward to the target if they're online
    if target in connected_clients:
        to_con = connected_clients[target][0]
        message_to_forward = f"PROXIMITY_RESULT:{sender}:{encrypted_result_str}\n"
        to_con.send(message_to_forward.encode())
        con.send("SUCCESS:Proximity result sent\n".encode())
        return True
    else:
        con.send("ERROR:Recipient is no longer online\n".encode())
        return False


def handle_friend_request(sender, target, con):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        print(f"DEBUG: Processing friend request from {sender} to {target}")
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
                sender_pubkey = client_public_keys.get(sender)
                if sender_pubkey:
                    plaintext_notification = f"{username} accepted your friend request"
                    plaintext_int = crypto_utils.string_to_int(plaintext_notification)
                    ciphertext = elgamal.encrypt(sender_pubkey, plaintext_int)
                    encrypted_notification = crypto_utils.serialize_ciphertext(ciphertext)
                    connected_clients[sender][0].send(f"NOTIFICATION:{encrypted_notification}\n".encode())
                else:
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
        query = 'SELECT sender FROM friend_requests WHERE receiver = ? AND status = "pending"'
        print(f"DEBUG: Executing query: {query} with username: {username}")
        cursor.execute(query, (username,))
        requests = [row['sender'] for row in cursor.fetchall()]
        print(f"DEBUG: Found friend requests: {requests}")
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


def save_paillier_public_key(username, pubkey):
    n, g = map(str, pubkey)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO paillier_public_keys (username, n, g) VALUES (?, ?, ?)',
                      (username, n, g))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving Paillier public key: {str(e)}")
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


def get_paillier_public_key(username):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT n, g FROM paillier_public_keys WHERE username = ?', (username,))
        result = cursor.fetchone()
        if result:
            return (int(result['n']), int(result['g']))
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
        # Send server's ElGamal public key for key exchange
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
                # Handle encrypted login commands
                elif msg.startswith("ELOGIN:"):
                    # Extract the encrypted payload
                    _, encrypted_payload = msg.split(":", 1)
                    # Deserialize ciphertext and decrypt credentials
                    from crypto_utils import deserialize_ciphertext, int_to_string
                    ciphertext = deserialize_ciphertext(encrypted_payload)
                    # Decrypt using the server's private key
                    plaintext_int = elgamal.decrypt(server_private_key, ciphertext[0], ciphertext[1])
                    credentials = int_to_string(plaintext_int)  # Expected format: "username:password"
                    try:
                        username_attempt, password = credentials.split(":", 1)
                    except Exception as e:
                        con.send("ERROR:Invalid credentials format\n".encode())
                        continue
                    # Process login using the plain credentials
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
                    continue

                elif msg.startswith("EREGISTER:"):
                    # Extract the encrypted payload
                    _, encrypted_payload = msg.split(":", 1)
                    # Deserialize ciphertext and decrypt credentials
                    from crypto_utils import deserialize_ciphertext, int_to_string
                    ciphertext = deserialize_ciphertext(encrypted_payload)
                    plaintext_int = elgamal.decrypt(server_private_key, ciphertext[0], ciphertext[1])
                    credentials = int_to_string(plaintext_int)  # Expected format: "username:password"

                    try:
                        username_attempt, password = credentials.split(":", 1)
                    except Exception:
                        con.send("ERROR:Invalid credentials format\n".encode())
                        continue

                    # Attempt to register the user
                    if create_user(username_attempt, password):
                        con.send("SUCCESS:Registered\n".encode())
                    else:
                        con.send("ERROR:Username exists\n".encode())
                    continue

                elif msg.startswith("EUPDATE_LOCATION:"):
                    try:
                        # Extract the encrypted payload (the part after the command prefix)
                        _, encrypted_payload = msg.split(":", 1)
                        # Deserialize and decrypt the ciphertext
                        ciphertext = crypto_utils.deserialize_ciphertext(encrypted_payload)
                        plaintext_int = elgamal.decrypt(server_private_key, ciphertext[0], ciphertext[1])
                        location_str = crypto_utils.int_to_string(plaintext_int)
                        # Update the location using the decrypted coordinates
                        if update_location(username, location_str):
                            con.send("SUCCESS:Location updated\n".encode())
                        else:
                            con.send("ERROR:Failed to update location\n".encode())
                    except Exception as e:
                        con.send(f"ERROR:Failed to process encrypted location update: {str(e)}\n".encode())

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
                        # Plain LOGIN command can still be supported if needed.
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
                        print(f"REGISTER_PUBKEY branch reached. Current username: {username}")
                        if not username or len(parts) < 2:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        # Assume the client sends its public key as a comma-separated string: "p,g,h"
                        client_pubkey_str = parts[1]
                        try:
                            pubkey_parts = client_pubkey_str.split(',')
                            if len(pubkey_parts) != 3:
                                con.send("ERROR:Invalid public key format\n".encode())
                                continue
                            client_pubkey = tuple(map(int, pubkey_parts))
                        except Exception as e:
                            con.send("ERROR:Invalid public key values\n".encode())
                            continue

                        client_public_keys[username] = client_pubkey
                        if save_public_key(username, client_pubkey):
                            con.send(f"SUCCESS:Public key registered:{client_pubkey_str}\n".encode())
                        else:
                            con.send("ERROR:Failed to save public key\n".encode())

                    elif command == 'REGISTER_PAILLIER_PUBKEY':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        # Parse the Paillier public key from the message
                        paillier_pubkey_str = parts[1]
                        try:
                            pubkey_parts = paillier_pubkey_str.split(',')
                            if len(pubkey_parts) != 2:
                                con.send("ERROR:Invalid Paillier public key format\n".encode())
                                continue
                            paillier_pubkey = tuple(map(int, pubkey_parts))
                            if save_paillier_public_key(username, paillier_pubkey):
                                con.send(f"SUCCESS:Paillier public key registered\n".encode())
                                log_action(username, "REGISTER_PAILLIER_PUBKEY")
                            else:
                                con.send("ERROR:Failed to save Paillier public key\n".encode())
                        except Exception as e:
                            con.send(f"ERROR:Invalid Paillier public key values: {str(e)}\n".encode())

                    elif command == 'GET_PUBKEY':
                        if not username or len(parts) < 2:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        target = parts[1]
                        pubkey = get_public_key(target)
                        if pubkey:
                            client_pubkey_str = f"{pubkey[0]},{pubkey[1]},{pubkey[2]}"
                            con.send(f"PUBKEY:{target}:{client_pubkey_str}\n".encode())
                        else:
                            con.send(f"ERROR:No public key for {target}\n".encode())

                    elif command == 'GET_PAILLIER_PUBKEY':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        if len(parts) < 2:
                            con.send("ERROR:Missing target username\n".encode())
                            continue
                        target = parts[1]
                        pubkey = get_paillier_public_key(target)
                        if pubkey:
                            paillier_pubkey_str = f"{pubkey[0]},{pubkey[1]}"
                            con.send(f"PAILLIER_PUBKEY:{target}:{paillier_pubkey_str}\n".encode())
                            log_action(username, "GET_PAILLIER_PUBKEY", f"for {target}")
                        else:
                            con.send(f"ERROR:No Paillier public key for {target}\n".encode())

                    elif command == "EFRIEND_RESPONSE":
                        print("DEBUG: Raw friend management message:", msg)
                        parts = msg.split(":", 2)
                        print("DEBUG: Split parts:", parts, "Length:", len(parts))
                        if len(parts) < 3:
                            con.send("ERROR:Invalid request format\n".encode())
                            continue
                        friend_request_sender = parts[1].strip()  # The user who originally sent the friend request.
                        encrypted_payload = parts[2].strip()  # The encrypted friend response.

                        try:
                            # Decrypt the payload using the server's private key.
                            from crypto_utils import deserialize_ciphertext, int_to_string
                            ciphertext = deserialize_ciphertext(encrypted_payload)
                            decrypted_int = elgamal.decrypt(server_private_key, ciphertext[0], ciphertext[1])
                            friend_response = int_to_string(decrypted_int).strip()  # Should be "ACCEPT" or "DECLINE"
                            print(f"DEBUG: Decrypted friend response: {friend_response}")
                        except Exception as e:
                            con.send(f"ERROR:Failed to decrypt friend response: {str(e)}\n".encode())
                            continue

                            # Process the friend response by updating the friendships table.
                            # Here, 'username' is the user (e.g. aaa) responding to a friend request from friend_request_sender (e.g. bbb).
                        handle_friend_response(username, friend_request_sender, friend_response, con)
                        con.send("SUCCESS:Friend response processed\n".encode())
                        continue

                    elif command == "EADD_FRIEND":
                        if len(parts) < 3:
                            con.send("ERROR:Invalid request format\n".encode())
                            continue
                        target = parts[1]
                        encrypted_payload = parts[2]
                        print(f"DEBUG: EADD_FRIEND request from {username} to {target}")
                        # Always handle the friend request to add it to the database
                        handle_friend_request(username, target, con)
                        # Additionally forward the encrypted message if the target is online
                        if target in connected_clients:
                            to_con = connected_clients[target][0]
                            message_to_forward = f"EADD_FRIEND:{username}:{encrypted_payload}\n"
                            print(f"DEBUG: Forwarding to {target}: {message_to_forward}")
                            to_con.send(message_to_forward.encode())

                    elif command == "EGET_FRIEND_RESPONSES":
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        try:
                            # Expect an encrypted query in the format: EGET_FRIEND_RESPONSES:<encrypted_payload>
                            _, encrypted_payload = msg.split(":", 1)
                        except Exception as e:
                            con.send("ERROR:Invalid request format\n".encode())
                            continue
                        try:
                            # Decrypt the encrypted query using the server's private key.
                            ciphertext = deserialize_ciphertext(encrypted_payload)
                            plaintext_int = elgamal.decrypt(server_private_key, ciphertext[0], ciphertext[1])
                            query = int_to_string(plaintext_int)

                            # Optionally, verify that the query is exactly what you expect.
                            if query != "GET_FRIEND_RESPONSES":
                                con.send("ERROR:Invalid query\n".encode())

                                continue

                        except Exception as e:
                            con.send("ERROR:Decryption failed\n".encode())
                            continue

                        # Retrieve offline friend responses for the logged-in user.
                        conn = get_db_connection()
                        try:
                            cursor = conn.cursor()

                            # offline_friend_responses table should store sender, receiver, encrypted_payload, timestamp
                            cursor.execute(
                                'SELECT sender, encrypted_payload FROM offline_friend_responses WHERE receiver = ?',
                                (username,))

                            responses = cursor.fetchall()

                            # Combine responses into a single string with a delimiter; e.g. "sender1:payload1;sender2:payload2"
                            response_list = []

                            for row in responses:
                                sender = row['sender']
                                payload = row['encrypted_payload']
                                response_list.append(f"{sender}:{payload}")
                            responses_str = ";".join(response_list)

                        finally:
                            conn.close()

                        # Encrypt the responses string using the client's public key.

                        if username in client_public_keys:
                            client_pubkey = client_public_keys[username]
                            ciphertext_resp = elgamal.encrypt(client_pubkey, string_to_int(responses_str))
                            encrypted_response = serialize_ciphertext(ciphertext_resp)
                            con.send(f"EGET_FRIEND_RESPONSES_RESP:{encrypted_response}\n".encode())

                        else:
                            con.send("ERROR:No public key registered\n".encode())

                        continue

                    elif command == "EGET_REQUESTS":
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        try:
                            # The encrypted request is expected to be in the format:
                            # EGET_REQUESTS:<encrypted_payload>
                            _, encrypted_payload = msg.split(":", 1)
                        except Exception as e:
                            con.send("ERROR:Invalid request format\n".encode())
                            continue
                        try:
                            # Decrypt the encrypted payload using the server's private key.
                            ciphertext = deserialize_ciphertext(encrypted_payload)
                            plaintext_int = elgamal.decrypt(server_private_key, ciphertext[0], ciphertext[1])
                            query = int_to_string(plaintext_int)  # Expected to be "GET_REQUESTS"
                        except Exception as e:
                            con.send("ERROR:Decryption failed\n".encode())
                            continue
                        # Retrieve pending friend requests for the authenticated user.
                        conn = get_db_connection()
                        try:
                            cursor = conn.cursor()
                            cursor.execute(
                                'SELECT sender FROM friend_requests WHERE receiver = ? AND status = "pending"',
                                (username,))
                            requests = [row['sender'] for row in cursor.fetchall()]
                            requests_str = ",".join(requests)
                        finally:
                            conn.close()

                        # Encrypt the response using the client's public key.
                        if username in client_public_keys:
                            client_pubkey = client_public_keys[username]
                            ciphertext_resp = elgamal.encrypt(client_pubkey, string_to_int(requests_str))
                            encrypted_response = serialize_ciphertext(ciphertext_resp)
                            con.send(f"EGET_REQUESTS_RESP:{encrypted_response}\n".encode())
                        else:
                            con.send("ERROR:No public key registered\n".encode())
                        continue

                    elif command == "EGET_FRIENDS":
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        try:
                            # Expect the encrypted query in the format: EGET_FRIENDS:<encrypted_payload>
                            _, encrypted_payload = msg.split(":", 1)
                        except Exception as e:
                            con.send("ERROR:Invalid request format\n".encode())
                            continue
                        try:
                            # Decrypt the payload using the server's private key.
                            ciphertext = deserialize_ciphertext(encrypted_payload)
                            plaintext_int = elgamal.decrypt(server_private_key, ciphertext[0], ciphertext[1])
                            query = int_to_string(plaintext_int)  # Should be "GET_FRIENDS"
                            if query != "GET_FRIENDS":
                                con.send("ERROR:Invalid query\n".encode())
                                continue

                        except Exception as e:
                            con.send("ERROR:Decryption failed\n".encode())
                            continue
                        # Retrieve the friends list for the authenticated user.
                        conn = get_db_connection()
                        try:
                            cursor = conn.cursor()
                            cursor.execute('''SELECT user2 as friend FROM friendships WHERE user1 = ?
                                              UNION
                                              SELECT user1 as friend FROM friendships WHERE user2 = ?''',
                                           (username, username))
                            friends = [row['friend'] for row in cursor.fetchall()]
                            friends_str = ",".join(friends)
                        finally:
                            conn.close()

                        # Encrypt the response using the client's public key.
                        if username in client_public_keys:
                            client_pubkey = client_public_keys[username]
                            ciphertext_resp = elgamal.encrypt(client_pubkey, string_to_int(friends_str))
                            encrypted_response = serialize_ciphertext(ciphertext_resp)
                            con.send(f"EGET_FRIENDS_RESP:{encrypted_response}\n".encode())
                        else:
                            con.send("ERROR:No public key registered\n".encode())
                        continue

                    elif command == 'PROXIMITY_REQUEST':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        try:
                            if len(parts) < 2:
                                con.send("ERROR:Missing target friend\n".encode())
                                continue
                            target = parts[1]
                            original_msg = msg.strip()
                            prefix = f"PROXIMITY_REQUEST:{target}:"

                            if not original_msg.startswith(prefix):
                                con.send("ERROR:Invalid message format\n".encode())
                                continue

                            rest_of_msg = original_msg[len(prefix):]
                            last_colon_pos = rest_of_msg.rfind(':')

                            if last_colon_pos == -1:
                                con.send("ERROR:Invalid proximity request format - missing data\n".encode())
                                continue

                            encrypted_loc_str = rest_of_msg[:last_colon_pos]
                            paillier_pubkey_str = rest_of_msg[last_colon_pos + 1:]
                            print(f"Proximity request from {username} to {target}")
                            print(f"Encrypted location length: {len(encrypted_loc_str)}")
                            print(f"Public key length: {len(paillier_pubkey_str)}")

                            # Forward the request
                            handle_proximity_request(username, target, encrypted_loc_str, paillier_pubkey_str, con)

                        except Exception as e:
                            print(f"Error handling proximity request: {e}")
                            con.send(f"ERROR:Processing error: {str(e)}\n".encode())

                    elif command == 'PROXIMITY_RESULT':
                        if not username:
                            con.send("ERROR:Login required\n".encode())
                            continue
                        if len(parts) < 3:
                            con.send("ERROR:Invalid proximity result format\n".encode())
                            continue

                        target = parts[1]
                        encrypted_result_str = parts[2]

                        handle_proximity_result(username, target, encrypted_result_str, con)

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
    print("\nSecure Location Sharing Server")
    print("=========================================")
    print("ElGamal: Used for general encryption (login, friend requests)")
    print("Paillier: Used for privacy-preserving proximity checks")
    print("Server acts as a relay for encrypted messages")
    print("Server Online - Waiting for connections...")

    try:
        while True:
            con, addr = s.accept()
            threading.Thread(target=client_handler, args=(con, addr)).start()
    except KeyboardInterrupt:
        print("Shutting down server")
    finally:
        s.close()
