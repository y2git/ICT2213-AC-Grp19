import socket
import threading
import queue
import time
import getpass
import sys
import json
import base64
import elgamal
import crypto_utils
import os

target_PORT = 60
target_IP = '127.0.0.1'
BUF_SIZE = 65536

class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None

        # ElGamal encryption (for general use)
        self.server_pubkey = None  # Server's ElGamal public key
        self.public_key = None     # Client's ElGamal public key
        self.private_key = None    # Client's ElGamal private key

        if self.public_key and self.private_key:
            print(f"DEBUG: Generated private key: {self.private_key}")
            print(f"DEBUG: Generated public key: {self.public_key}")

        # Friend's public keys
        self.friend_pubkeys = {}

        # Location state
        self.current_location = None
        self.current_grid_cell = None

        self.running = True
        self.response_queue = queue.Queue()
        self.message_queue = queue.Queue()
        self.lock = threading.Lock()
        self.start_message_listener()

    def start_message_listener(self):
        def listener():
            while self.running:
                self.print_messages()
                time.sleep(0.1)
        threading.Thread(target=listener, daemon=True).start()

    def connect(self):
        try:
            self.sock.connect((target_IP, target_PORT))
            data = self.sock.recv(BUF_SIZE).decode()
            if data.startswith("HELLO:"):
                # Get server's ElGamal public key
                p, g, h = map(int, data.split(':')[1].split(','))
                self.server_pubkey = (p, g, h)


                # Add the ElGamal self-test code here
                # # Test ElGamal encryption/decryption
                # test_message = "Test message"
                # test_int = crypto_utils.string_to_int(test_message)
                # print(f"Test message as int: {test_int}")
                #
                # # Encrypt with own public key
                # test_encrypted = elgamal.encrypt(self.public_key, test_int)
                # print(f"Encrypted with own public key: {test_encrypted}")
                #
                # # Decrypt with own private key
                # test_decrypted = elgamal.decrypt(self.private_key, test_encrypted[0], test_encrypted[1])
                # print(f"Decrypted int: {test_decrypted}")
                # test_decrypted_str = crypto_utils.int_to_string(test_decrypted)
                # print(f"Decrypted message: {test_decrypted_str}")
                #
                # if test_decrypted_str == test_message:
                #     print("ElGamal self-test PASSED")
                # else:
                #     print("ElGamal self-test FAILED")
            return True
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False

    def load_keys(self, username):
        """Load saved keys for a username if they exist"""
        key_file = f"{username}_keys.json"
        try:
            if os.path.exists(key_file):
                with open(key_file, 'r') as f:
                    keys = json.load(f)
                    self.public_key = tuple(keys['public_key'])
                    self.private_key = tuple(keys['private_key'])
                    print(f"Loaded existing keys for {username}")
                    return True
            return False
        except Exception as e:
            print(f"Error loading keys: {e}")
            return False

    def save_keys(self):
        """Save keys for the current user"""
        if not self.username or not self.public_key or not self.private_key:
            return False

        key_file = f"{self.username}_keys.json"
        try:
            with open(key_file, 'w') as f:
                keys = {
                    'public_key': list(self.public_key),
                    'private_key': list(self.private_key)
                }
                json.dump(keys, f)
                print(f"Saved keys for {self.username}")
            return True
        except Exception as e:
            print(f"Error saving keys: {e}")
            return False


    def receive_handler(self):
        buffer = ""
        while self.running:
            try:
                data = self.sock.recv(BUF_SIZE).decode()
                if not data:
                    break
                buffer += data
                while '\n' in buffer:
                    msg, buffer = buffer.split('\n', 1)
                    msg = msg.strip()
                    print(f"DEBUG: Received raw message: {msg}")  # Add this line
                    # Check for encrypted friend management commands.
                    if msg.startswith("EADD_FRIEND:") or msg.startswith("EFRIEND_RESPONSE:"):
                        parts = msg.split(":", 2)
                        print(f"DEBUG: Friend command parts: {parts}, length: {len(parts)}")
                        if len(parts) < 3:
                            print("Invalid friend management command format.")
                            continue
                        # parts[0] is the command prefix, parts[1] is the target, parts[2] is the encrypted payload.
                        encrypted_payload = parts[2]
                        try:  # Add this try-except block
                            # Deserialize the ciphertext.
                            ciphertext = crypto_utils.deserialize_ciphertext(encrypted_payload)
                            print(f"DEBUG: Deserialized ciphertext: {ciphertext}")

                            # Decrypt using your private key.
                            print(f"DEBUG: Private key used for decryption: {self.private_key}")
                            plaintext_int = elgamal.decrypt(self.private_key, ciphertext[0], ciphertext[1])
                            print(f"DEBUG: Decrypted integer value: {plaintext_int}")

                            # Convert integer to string
                            decrypted_message = crypto_utils.int_to_string(plaintext_int)
                            print(f"Decrypted friend management command: {decrypted_message}")
                        except Exception as e:
                            print(f"DEBUG: Decryption error: {str(e)}")
                            print(f"DEBUG: Error details: {e}")
                            continue

                        if decrypted_message.startswith("ADD_FRIEND:"):
                            # Extract the sender username
                            sender = parts[1]
                            print(f"\n[DEBUG] Processing friend request from {sender}")
                            self.message_queue.put(f"NOTIFICATION:New friend request from {sender}")
                        elif decrypted_message.startswith("FRIEND_RESPONSE:"):
                            # Extract response parts
                            _, sender, response = decrypted_message.split(":", 2)
                            notification = f"NOTIFICATION:{sender} has {response.lower()}ed your friend request"
                            print(f"\n[{notification}]")
                            self.message_queue.put(notification)
                        with self.lock:
                            self.response_queue.put(decrypted_message)

                    # Check for encrypted GET_REQUESTS_RESP and GET_FRIENDS_RESP responses.
                    elif msg.startswith("EGET_REQUESTS_RESP:") or msg.startswith("EGET_FRIENDS_RESP:"):
                        with self.lock:
                            self.response_queue.put(msg)
                    # Check for other standard responses.
                    elif msg.startswith(("SUCCESS:", "ERROR:", "PUBKEY:", "REQUESTS:", "FRIENDS:", "LOCATION:")):
                        with self.lock:
                            self.response_queue.put(msg)
                    elif msg.startswith("NOTIFICATION:"):
                        self.message_queue.put(msg)
                    else:
                        print(f"Unhandled message: {msg}")
            except Exception as e:
                if self.running:
                    print(f"Receive error: {str(e)}")
                break

    def send_command(self, command, timeout=5):
        try:
            with self.lock:
                self.response_queue.queue.clear()
            if isinstance(command, bytes):
                if not command.endswith(b'\n'):
                    command += b'\n'
                self.sock.send(command)
            else:
                if not command.endswith('\n'):
                    command += '\n'
                self.sock.send(command.encode())
            start_time = time.time()
            while time.time() - start_time < timeout:
                with self.lock:
                    if not self.response_queue.empty():
                        return self.response_queue.get()
                time.sleep(0.1)
            return "ERROR:Timeout waiting for response"
        except Exception as e:
            return f"ERROR:{str(e)}"

    # Authentication Functions
    def register(self, username, password):
        # Encrypt "username:password" with server's public key
        encrypted_payload = self.encrypt_credentials(username, password)

        return self.send_command(f"EREGISTER:{encrypted_payload}\n".encode())

    def login(self, username, password):
        # Encrypt the credentials before sending
        encrypted_credentials = self.encrypt_credentials(username, password)

        # Send with a special prefix to indicate encryption, e.g., "ELOGIN:"
        response = self.send_command(f"ELOGIN:{encrypted_credentials}\n".encode())
        if response.startswith("SUCCESS"):
            self.username = username

            # Try to load existing keys
            if not self.load_keys(username):
                # If no keys exist, generate new ones
                self.public_key, self.private_key = elgamal.generate_keys()
                print(f"Generated new keys for {username}")
                print(f"DEBUG: Private key: {self.private_key}")
                print(f"DEBUG: Public key: {self.public_key}")
                # Save the newly generated keys
                self.save_keys()

            # Always register the public key with the server after login
            pubkey_str = f"{self.public_key[0]},{self.public_key[1]},{self.public_key[2]}"
            print("Sending REGISTER_PUBKEY with:", pubkey_str)
            self.send_command(f"REGISTER_PUBKEY:{pubkey_str}")
            return True
        elif response.startswith("ERROR"):
            error_msg = response.split(':', 1)[1] if ':' in response else "Login failed"
            print(f"Error: {error_msg}")
            return False
        return False

    def logout(self):
        if self.username:
            response = self.send_command("LOGOUT:\n".encode())
            self.username = None
            return response
        return "ERROR:Not logged in"

    # Friend Management Functions
    def get_friend_pubkey(self, friend):
        if friend in self.friend_pubkeys:
            print(f"DEBUG: Using cached public key for {friend}: {self.friend_pubkeys[friend]}")
            return self.friend_pubkeys[friend]

        print(f"DEBUG: Requesting public key for {friend} from server")
        response = self.send_command(f"GET_PUBKEY:{friend}\n".encode())
        print(f"DEBUG: Server response: {response}")
        if response.startswith("PUBKEY:"):
            parts = response.split(':')
            if len(parts) < 3:
                print("Error: Invalid public key format")
                return None
            public_key_str = parts[2]
            try:
                friend_pubkey = tuple(map(int, public_key_str.split(',')))
                print(f"DEBUG: Received public key for {friend}: {friend_pubkey}")
                self.friend_pubkeys[friend] = friend_pubkey
                return friend_pubkey
            except Exception as e:
                print("Error parsing public key:", e)
                return None
        return None

    def add_friend(self, friend):
        friend_pubkey = self.get_friend_pubkey(friend)
        if not friend_pubkey:
            print(f"Error: No public key available for {friend}")
            return "ERROR:No public key"
        command_str = f"ADD_FRIEND:{friend}"
        encrypted_command = self.encrypt_command(command_str, friend_pubkey)
        # Include the target username in the message header
        return self.send_command(f"EADD_FRIEND:{friend}:{encrypted_command}\n".encode())

    def get_friend_requests(self):
        # Prepare the query string.
        query = "GET_REQUESTS"
        # Encrypt the query using the server's public key.
        encrypted_query = self.encrypt_credentials("", query)
        # Send the encrypted query with the prefix EGET_REQUESTS:
        response = self.send_command(f"EGET_REQUESTS:{encrypted_query}\n".encode())
        if response.startswith("EGET_REQUESTS_RESP:"):
            # Extract the encrypted payload from the response.
            _, encrypted_payload = response.split(":", 1)
            # Deserialize and decrypt using the client's private key.
            ciphertext = crypto_utils.deserialize_ciphertext(encrypted_payload)
            plaintext_int = elgamal.decrypt(self.private_key, ciphertext[0], ciphertext[1])
            decrypted_response = crypto_utils.int_to_string(plaintext_int)
            return decrypted_response
        return response

    def respond_to_request(self, sender, response):
        """
        Respond to a friend request by encrypting the plaintext response (e.g., "ACCEPT" or "DECLINE")
        using the server's public key.
        """
        print(f"DEBUG: Responding to friend request from {sender} with response: {response}")
        if not self.server_pubkey:
            print("ERROR: No server public key available.")
            return "ERROR:No server public key"

        # Encrypt the response using the server's public key.
        # Convert the plaintext response to an integer.
        plaintext_int = crypto_utils.string_to_int(response)
        ciphertext = elgamal.encrypt(self.server_pubkey, plaintext_int)
        encrypted_response = crypto_utils.serialize_ciphertext(ciphertext)

        print(f"DEBUG: Encrypted friend response: {encrypted_response}")
        # Send the command formatted as:
        # "EFRIEND_RESPONSE:<friend_request_sender>:<encrypted_response>"
        return self.send_command(f"EFRIEND_RESPONSE:{sender}:{encrypted_response}\n".encode())

    def get_friends_list(self):
        query = "GET_FRIENDS"

        plaintext_int = crypto_utils.string_to_int(query)
        ciphertext = elgamal.encrypt(self.server_pubkey, plaintext_int)
        encrypted_query = crypto_utils.serialize_ciphertext(ciphertext)
        response = self.send_command(f"EGET_FRIENDS:{encrypted_query}\n".encode())
        if response.startswith("EGET_FRIENDS_RESP:"):
            _, encrypted_payload = response.split(":", 1)
            ciphertext = crypto_utils.deserialize_ciphertext(encrypted_payload)
            plaintext_int = elgamal.decrypt(self.private_key, ciphertext[0], ciphertext[1])
            decrypted_response = crypto_utils.int_to_string(plaintext_int)
            return decrypted_response
        return response

    def encrypt_command(self, command_str, recipient_pubkey):
        """Encrypt a command using the recipient's public key."""
        print(f"DEBUG: Encrypting command: '{command_str}'")
        print(f"DEBUG: Using recipient public key: {recipient_pubkey}")
        # Convert the command string into an integer.
        print(f"DEBUG: Private key used for operations: {self.private_key}")
        plaintext_int = crypto_utils.string_to_int(command_str)
        print(f"DEBUG: Command as integer: {plaintext_int}")
        # Encrypt the integer using the recipient's public key.
        ciphertext = elgamal.encrypt(recipient_pubkey, plaintext_int)
        print(f"DEBUG: Raw ciphertext: {ciphertext}")
        # Serialize the ciphertext for transmission.
        serialized = crypto_utils.serialize_ciphertext(ciphertext)
        print(f"DEBUG: Serialized ciphertext: {serialized}")
        return crypto_utils.serialize_ciphertext(ciphertext)

    def encrypt_credentials(self, username, password):
        # Combine credentials into one message; you could also encrypt them separately.
        message = f"{username}:{password}"
        plaintext_int = crypto_utils.string_to_int(message)
        # Encrypt with the server's public key
        ciphertext = elgamal.encrypt(self.server_pubkey, plaintext_int)
        return crypto_utils.serialize_ciphertext(ciphertext)

    # Location Management Functions
    def update_location(self, x, y):
        try:
            x = int(x)
            y = int(y)
            if not (0 <= x <= 99999 and 0 <= y <= 99999):
                return "ERROR:Coordinates must be between 0 and 99999"
            self.current_location = (x, y)
            self.current_grid_cell = (x // 1000, y // 1000)
            response = self.send_command(f"UPDATE_LOCATION:{x},{y}\n".encode())
            print(response)
            return response
        except ValueError:
            return "ERROR:Coordinates must be valid numbers"
        except Exception as e:
            return f"ERROR:{str(e)}"

    def get_current_location(self):
        if not self.username:
            return "ERROR:Not logged in"
        response = self.send_command("GET_LOCATION:\n".encode())
        if response.startswith("SUCCESS") and self.current_location:
            x, y = self.current_location
            grid_x, grid_y = self.current_grid_cell if self.current_grid_cell else (x // 1000, y // 1000)
            print(f"Your current location:")
            print(f"Coordinates: ({x}, {y})")
            print(f"Grid cell: ({grid_x}, {grid_y})")
            return response
        return response

    # Proximity functionality removed
    def initiate_proximity_check(self, friend):
        print("ERROR: Proximity functionality has been removed")
        return False

    def print_messages(self):
        while not self.message_queue.empty():
            msg = self.message_queue.get()
            if msg.startswith("NOTIFICATION:"):
                content = msg.split(":", 1)[1].strip()
                # Attempt to decrypt the notification
                try:
                    # If the notification is an encrypted payload, it should contain a delimiter (e.g., '|')
                    if '|' in content:
                        ciphertext = crypto_utils.deserialize_ciphertext(content)
                        plaintext_int = elgamal.decrypt(self.private_key, ciphertext[0], ciphertext[1])
                        decrypted_message = crypto_utils.int_to_string(plaintext_int)
                        print(f"[!] {decrypted_message}")
                    else:
                        # If no delimiter is found, assume it's plaintext
                        print(f"[!] {content}")
                except Exception as e:
                    print(f"[!] (Decryption failed, raw: {content})")
            else:
                print(msg)


def masked_input():
    password = ""
    print("Password: ", end="", flush=True)
    if sys.platform == 'win32':
        import msvcrt
        while True:
            key = msvcrt.getch()
            key_decoded = key.decode('utf-8') if hasattr(key, 'decode') else key
            if key in (b'\r', b'\n') or key_decoded in ('\r', '\n'):
                print()
                break
            elif key in (b'\b',) or key_decoded == '\b':
                if password:
                    password = password[:-1]
                    print('\b \b', end='', flush=True)
            elif key_decoded in ('\x03', '\x04'):
                raise KeyboardInterrupt
            else:
                password += key_decoded
                print('*', end='', flush=True)
    else:
        import termios, tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                key = sys.stdin.read(1)
                if key in ('\r', '\n'):
                    print()
                    break
                elif key == '\x7f':
                    if password:
                        password = password[:-1]
                        print('\b \b', end='', flush=True)
                elif key in ('\x03', '\x04'):
                    raise KeyboardInterrupt
                else:
                    password += key
                    print('*', end='', flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return password

def main():
    client = Client()
    if not client.connect():
        return

    threading.Thread(target=client.receive_handler, daemon=True).start()

    print("\nHybrid Encryption Location Sharing Client")
    print("ElGamal for general encryption")
    print("Proximity functionality removed")
    print("=================================================================")

    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choice: ").strip()
        if choice == '1':
            username = input("Username: ").strip()
            try:
                password = getpass.getpass("Password: ")
            except Exception:
                password = masked_input()
            print(client.register(username, password))
        elif choice == '2':
            username = input("Username: ").strip()
            try:
                password = getpass.getpass("Password: ")
            except Exception:
                password = masked_input()
            if client.login(username, password):
                print("Login successful!")
                while True:
                    try:
                        print("Please enter coordinates (0-99999):")
                        x = int(input("X: "))
                        y = int(input("Y: "))
                        if not (0 <= x <= 99999 and 0 <= y <= 99999):
                            print("Error: Coordinates must be between 0 and 99999")
                            continue
                        result = client.update_location(x, y)
                        if "SUCCESS" in result:
                            break
                        else:
                            print(result)
                    except ValueError:
                        print("Invalid coordinates. Please enter numeric values.")
                break
        elif choice == '3':
            client.running = False
            return
        else:
            print("Invalid choice")

    while client.running:
        client.print_messages()
        print("\n1. Friend Management\n2. Update Location\n3. Check Proximity\n4. Check My Location\n5. Logout")
        choice = input("Choice: ").strip()
        if choice == '1':
            print("\nFriend Management:")
            print("1. Send Friend Request")
            print("2. View Friend Requests")
            print("3. View Friends List")
            print("4. Back to Main Menu")
            friend_choice = input("Choice: ").strip()
            if friend_choice == '1':
                friend = input("Friend's username: ").strip()
                response = client.add_friend(friend)
                print(response)
            elif friend_choice == '2':
                # Retrieve pending friend requests (encrypted version)
                response = client.get_friend_requests()
                if response.startswith("ERROR"):
                    print(response)
                else:
                    requests_list = [req for req in response.split(',') if req]
                    if not requests_list:
                        print("No pending friend requests.")
                    else:
                        print("\nPending Friend Requests:")
                        for idx, req in enumerate(requests_list, 1):
                            print(f"{idx}. {req}")
                        print("\nWould you like to respond to a friend request? (y/n)")
                        sub_choice = input().strip().lower()
                        if sub_choice == 'y':
                            sender = input("Enter username to respond to: ").strip()
                            if sender not in requests_list:
                                print("Error: No friend request from that user.")
                            else:
                                print(f"Accept friend request from {sender}? (y/n)")
                                resp_choice = input().strip().lower()
                                response_text = "ACCEPT" if resp_choice == 'y' else "DECLINE"
                                friend_response = client.respond_to_request(sender, response_text)
                                print(friend_response)
            elif friend_choice == '3':
                response = client.get_friends_list()
                if response.startswith("FRIENDS:"):
                    friends = response.split(':', 1)[1].strip()
                    if not friends:
                        print("You don't have any friends yet.")
                    else:
                        friends_list = friends.split(',')
                        print("\nYour Friends:")
                        for i, friend in enumerate(friends_list, 1):
                            print(f"{i}. {friend}")
                else:
                    print(response)
        elif choice == '2':
            try:
                print("Please enter coordinates (0-99999):")
                x = int(input("X: "))
                y = int(input("Y: "))
                if not (0 <= x <= 99999 and 0 <= y <= 99999):
                    print("Error: Coordinates must be between 0 and 99999")
                    continue
                result = client.update_location(x, y)
                print(result)
                if "SUCCESS" in result:
                    print(f"Your location is set to coordinates ({x}, {y})")
            except ValueError:
                print("Invalid coordinates. Please enter numeric values.")
        elif choice == '3':
            friend_name = input("Enter friend's username for proximity check: ").strip()
            print(client.initiate_proximity_check(friend_name))
        elif choice == '4':
            print("Checking your location status...")
            client.get_current_location()
        elif choice == '5':
            if client.username:
                logout_response = client.send_command("LOGOUT:\n".encode())
                print(f"Logging out: {logout_response}")
            client.running = False
            client.sock.close()
            print("Goodbye!")


if __name__ == "__main__":
    main()
