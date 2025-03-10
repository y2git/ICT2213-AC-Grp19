import socket
import threading
import queue
import time
import getpass
import sys
import json
import elgamal
import crypto_utils
import os
import paillier

target_PORT = 60
target_IP = '127.0.0.1'
BUF_SIZE = 65536
PROXIMITY_THRESHOLD = 2500  # Proximity threshold for Euclidean distance squared


def parse_paillier_pubkey(key_str):
    """Safely parse a Paillier public key string into a tuple (n, g)"""
    try:
        # Clean up the string
        key_str = key_str.strip()

        # The key string might have newlines or spaces - remove them
        key_str = key_str.replace('\n', '').replace(' ', '')

        # Split by comma
        parts = key_str.split(',')
        if len(parts) != 2:
            print(f"Error: Expected 2 parts in Paillier key, got {len(parts)}")
            return None

        # Parse integers
        n = int(parts[0])
        g = int(parts[1])
        return (n, g)
    except ValueError as e:
        print(f"Error parsing Paillier key integers: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error parsing Paillier key: {e}")
        return None

class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None

        # ElGamal encryption (for general use)
        self.server_pubkey = None  # Server's ElGamal public key
        self.public_key = None     # Client's ElGamal public key
        self.private_key = None    # Client's ElGamal private key

        # Paillier encryption (for proximity checks)
        self.paillier_public_key = None
        self.paillier_private_key = None

        # Friend's public keys
        self.friend_pubkeys = {}  # ElGamal
        self.friend_paillier_pubkeys = {}  # Paillier

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
                    self.public_key = tuple(keys['elgamal_public_key'])
                    self.private_key = tuple(keys['elgamal_private_key'])

                    # Load Paillier keys if they exist
                    if 'paillier_public_key' in keys and 'paillier_private_key' in keys:
                        self.paillier_public_key = tuple(keys['paillier_public_key'])
                        self.paillier_private_key = tuple(keys['paillier_private_key'])
                        print(f"Loaded existing ElGamal and Paillier keys for {username}")
                    else:
                        print(f"Loaded existing ElGamal keys for {username}, but no Paillier keys")
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
            keys = {
                'elgamal_public_key': list(self.public_key),
                'elgamal_private_key': list(self.private_key),
            }

            # Add Paillier keys if they exist
            if self.paillier_public_key and self.paillier_private_key:
                keys['paillier_public_key'] = list(self.paillier_public_key)
                keys['paillier_private_key'] = list(self.paillier_private_key)

            with open(key_file, 'w') as f:
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
                    print(f"DEBUG: Received raw message: {msg}")

                    # Handle proximity check messages
                    if msg.startswith("PROXIMITY_REQUEST:"):
                        parts = msg.split(":", 3)
                        if len(parts) < 4:
                            print("Invalid proximity request format")
                            continue
                        sender = parts[1]
                        encrypted_loc_str = parts[2]
                        paillier_pubkey_str = parts[3]

                        print(f"\nReceived proximity check request from {sender}")
                        self.handle_proximity_request(sender, encrypted_loc_str, paillier_pubkey_str)
                        continue

                    elif msg.startswith("PROXIMITY_RESULT:"):
                        parts = msg.split(":", 2)
                        if len(parts) < 3:
                            print("Invalid proximity result format")
                            continue
                        sender = parts[1]
                        encrypted_result_str = parts[2]

                        print(f"\nReceived proximity check result from {sender}")
                        self.handle_proximity_result(sender, encrypted_result_str)
                        continue


                    elif msg.startswith("PAILLIER_PUBKEY:"):
                        try:
                            parts = msg.split(":", 3)  # Allow for more parts in case key contains colons
                            if len(parts) < 3:
                                print("Invalid Paillier public key format")
                                continue
                            friend = parts[1]
                            # The key might be split across multiple parts if it contains colons
                            pubkey_str = ':'.join(parts[2:])
                            # Try to parse the key to validate it
                            key_parts = pubkey_str.strip().split(',')
                            if len(key_parts) == 2:
                                try:
                                    n = int(key_parts[0])
                                    g = int(key_parts[1])
                                    self.friend_paillier_pubkeys[friend] = (n, g)
                                    print(f"Received and cached Paillier public key for {friend}")
                                    self.message_queue.put(f"Received Paillier public key for {friend}")
                                    # Also put the message in the response queue for send_command to find
                                    with self.lock:
                                        self.response_queue.put(msg)
                                except ValueError:
                                    print("Failed to parse Paillier key integers")
                            else:
                                print(f"Invalid Paillier key format: expected 2 parts, got {len(key_parts)}")
                        except Exception as e:
                            print(f"Error processing Paillier public key: {e}")
                        continue

                    # Handle other message types
                    elif msg.startswith("EADD_FRIEND:") or msg.startswith("EFRIEND_RESPONSE:"):
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

            # Convert command to string for easier handling
            if isinstance(command, bytes):
                cmd_str = command.decode('utf-8')
                if not cmd_str.endswith('\n'):
                    cmd_str += '\n'
                command_bytes = cmd_str.encode('utf-8')
            else:
                cmd_str = command
                if not cmd_str.endswith('\n'):
                    cmd_str += '\n'
                command_bytes = cmd_str.encode('utf-8')

            # Send the command
            self.sock.send(command_bytes)

            # Special handling for GET_PAILLIER_PUBKEY
            if "GET_PAILLIER_PUBKEY:" in cmd_str:
                print("Waiting for PAILLIER_PUBKEY response...")
                # Extract the friend name from the command
                friend = cmd_str.split(":")[1].strip()
                if friend.endswith('\n'):
                    friend = friend[:-1]

                start_time = time.time()
                while time.time() - start_time < timeout:
                    with self.lock:
                        if not self.response_queue.empty():
                            response = self.response_queue.get()
                            # Check if this is the response we're looking for
                            if isinstance(response, str) and response.startswith(f"PAILLIER_PUBKEY:{friend}:"):
                                return response
                    time.sleep(0.1)

                # If we reach here, we've timed out waiting for the specific response
                if friend in self.friend_paillier_pubkeys:
                    # If we have a cached key, construct a response manually
                    pubkey = self.friend_paillier_pubkeys[friend]
                    pubkey_str = f"{pubkey[0]},{pubkey[1]}"
                    return f"PAILLIER_PUBKEY:{friend}:{pubkey_str}"
                return "ERROR:Timeout waiting for PAILLIER_PUBKEY response"

            # For other commands, use the standard response handling
            start_time = time.time()
            while time.time() - start_time < timeout:
                with self.lock:
                    if not self.response_queue.empty():
                        return self.response_queue.get()
                time.sleep(0.1)
            return "ERROR:Timeout waiting for response"
        except Exception as e:
            print(f"Exception in send_command: {e}")
            import traceback
            traceback.print_exc()
            return f"ERROR:{str(e)}"

    # Authentication Functions
    def register(self, username, password):
        # Encrypt "username:password" with server's public key
        encrypted_payload = self.encrypt_credentials(username, password)

        return self.send_command(f"EREGISTER:{encrypted_payload}\n".encode())

    def login(self, username, password):
        """Login with improved error handling"""
        try:
            # Encrypt the credentials before sending
            encrypted_credentials = self.encrypt_credentials(username, password)

            # Send with a special prefix to indicate encryption, e.g., "ELOGIN:"
            response = self.send_command(f"ELOGIN:{encrypted_credentials}")

            print(f"DEBUG: Login response: {response}")

            # Ensure response is a string
            if not isinstance(response, str):
                print(f"ERROR: Expected string response, got {type(response)}")
                return False

            if response.startswith("SUCCESS"):
                self.username = username

                # Try to load existing keys
                if not self.load_keys(username):
                    # If no keys exist, generate new ones
                    self.public_key, self.private_key = elgamal.generate_keys()
                    # Generate Paillier keys for proximity checks
                    self.paillier_public_key, self.paillier_private_key = paillier.generate_keys()
                    print(f"Generated new ElGamal and Paillier keys for {username}")
                    # Save the newly generated keys
                    self.save_keys()

                # Always register the public keys with the server after login

                # Register ElGamal public key
                pubkey_str = f"{self.public_key[0]},{self.public_key[1]},{self.public_key[2]}"
                print("Sending REGISTER_PUBKEY with:", pubkey_str)
                self.send_command(f"REGISTER_PUBKEY:{pubkey_str}")

                # Register Paillier public key
                if self.paillier_public_key:
                    paillier_pubkey_str = f"{self.paillier_public_key[0]},{self.paillier_public_key[1]}"
                    print("Sending REGISTER_PAILLIER_PUBKEY with:", paillier_pubkey_str)
                    self.send_command(f"REGISTER_PAILLIER_PUBKEY:{paillier_pubkey_str}")

                return True
            elif response.startswith("ERROR"):
                error_msg = response.split(':', 1)[1] if ':' in response else "Login failed"
                print(f"Error: {error_msg}")
                return False
            else:
                print(f"Unexpected response format: {response}")
                return False
        except Exception as e:
            print(f"Exception during login: {e}")
            import traceback
            traceback.print_exc()
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

    def get_friend_paillier_pubkey(self, friend):
        """Get a friend's Paillier public key with improved parsing"""
        if friend in self.friend_paillier_pubkeys:
            print(f"DEBUG: Using cached Paillier public key for {friend}")
            return self.friend_paillier_pubkeys[friend]

        print(f"DEBUG: Requesting Paillier public key for {friend} from server")
        response = self.send_command(f"GET_PAILLIER_PUBKEY:{friend}\n".encode())
        print(f"DEBUG: Raw PAILLIER_PUBKEY response: {response}")

        if response.startswith("PAILLIER_PUBKEY:"):
            try:
                # Split only on the first two colons - the key itself might contain colons
                parts = response.split(':', 2)
                if len(parts) < 3:
                    print(f"Error: Invalid Paillier public key format - not enough parts")
                    return None

                public_key_str = parts[2]
                print(f"DEBUG: Attempting to parse public key string...")

                # Use our safe parsing function
                friend_pubkey = parse_paillier_pubkey(public_key_str)
                if friend_pubkey:
                    print(f"DEBUG: Successfully parsed Paillier public key for {friend}")
                    self.friend_paillier_pubkeys[friend] = friend_pubkey
                    return friend_pubkey
                else:
                    print(f"Failed to parse Paillier public key")
                    return None

            except Exception as e:
                print(f"Error processing Paillier public key: {e}")
                import traceback
                traceback.print_exc()
                return None

        print(f"Error: Server did not return a valid Paillier public key. Response: {response}")
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
        """Get the list of friends with improved debugging"""
        print("Requesting friends list from server...")

        query = "GET_FRIENDS"

        # Encrypt the query
        plaintext_int = crypto_utils.string_to_int(query)
        ciphertext = elgamal.encrypt(self.server_pubkey, plaintext_int)
        encrypted_query = crypto_utils.serialize_ciphertext(ciphertext)

        # Send the encrypted query
        print("Sending encrypted EGET_FRIENDS request...")
        response = self.send_command(f"EGET_FRIENDS:{encrypted_query}\n".encode())
        print(f"DEBUG: Raw response from server: {response}")

        # Process the response
        if response.startswith("EGET_FRIENDS_RESP:"):
            try:
                # Extract and decrypt the encrypted payload
                _, encrypted_payload = response.split(":", 1)
                print("DEBUG: Encrypted payload received, attempting to decrypt...")

                ciphertext = crypto_utils.deserialize_ciphertext(encrypted_payload)
                print(f"DEBUG: Deserialized ciphertext: {ciphertext}")

                plaintext_int = elgamal.decrypt(self.private_key, ciphertext[0], ciphertext[1])
                print(f"DEBUG: Decrypted integer: {plaintext_int}")

                decrypted_response = crypto_utils.int_to_string(plaintext_int)
                print(f"DEBUG: Decrypted string: {decrypted_response}")

                # Convert to FRIENDS: format for consistency
                return f"FRIENDS:{decrypted_response}"
            except Exception as e:
                print(f"ERROR decrypting friends list: {e}")
                return f"ERROR:Failed to decrypt friends list: {e}"

        # If we didn't get an encrypted response, return whatever we got
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
            # Create a string representation of the location
            location_str = f"{x},{y}"
            # Encrypt the location using the server's public key
            plaintext_int = crypto_utils.string_to_int(location_str)
            ciphertext = elgamal.encrypt(self.server_pubkey, plaintext_int)
            encrypted_location = crypto_utils.serialize_ciphertext(ciphertext)
            # Send the encrypted location update with a new command prefix
            response = self.send_command(f"EUPDATE_LOCATION:{encrypted_location}\n".encode())
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
        """Initiate a proximity check with a friend using your own Paillier public key."""
        if not self.username:
            return "ERROR:Not logged in"

        if not self.current_location:
            return "ERROR:You need to set your location first"

        self.proximity_start_time = time.perf_counter()

        # Ensure our Paillier keys are available; regenerate if necessary.
        if not self.paillier_public_key or not self.paillier_private_key:
            print("ERROR: Your Paillier keys are not available. Trying to regenerate...")
            try:
                self.paillier_public_key, self.paillier_private_key = paillier.generate_keys()
                print("Generated new Paillier keys")
                self.save_keys()  # Save the newly generated keys

                # Register with server
                paillier_pubkey_str = f"{self.paillier_public_key[0]},{self.paillier_public_key[1]}"
                print(f"Registering new Paillier public key with server: {paillier_pubkey_str[:50]}...")
                self.send_command(f"REGISTER_PAILLIER_PUBKEY:{paillier_pubkey_str}")
            except Exception as e:
                return f"ERROR:Failed to generate Paillier keys: {e}"

        # Retrieve friend's Paillier public key for potential other operations (if needed)
        # (Not used for encrypting our own location)
        print(f"Retrieving Paillier public key for {friend}...")
        friend_pubkey = self.get_friend_paillier_pubkey(friend)
        if not friend_pubkey:
            print(f"ERROR: Could not retrieve Paillier public key for {friend}")
            return "ERROR:Could not retrieve friend's Paillier public key"

        print(f"Successfully retrieved Paillier public key for {friend}")
        print(f"Friend's key: {str(friend_pubkey)[:50]}...")

        try:
            # Extract current location
            x, y = self.current_location
            print(f"Using your location: ({x}, {y})")

            # IMPORTANT: Encrypt your location using YOUR own Paillier public key
            print("Encrypting your location using your own Paillier public key...")
            encrypted_loc = paillier.encrypt_location(self.paillier_public_key, x, y)

            # Serialize for transmission
            encrypted_loc_str = paillier.serialize_encrypted_location(encrypted_loc)
            print(f"Location encrypted successfully. Length: {len(encrypted_loc_str)}")

            # Include your Paillier public key in the request
            paillier_pubkey_str = f"{self.paillier_public_key[0]},{self.paillier_public_key[1]}"

            # Construct and send the proximity request command
            command = f"PROXIMITY_REQUEST:{friend}:{encrypted_loc_str}:{paillier_pubkey_str}"
            response = self.send_command(command)
            if response.startswith("SUCCESS"):
                print(f"Proximity check request sent to {friend}")
                return "SUCCESS:Proximity check request sent"
            else:
                print(f"Server response: {response}")
                return response
        except Exception as e:
            print(f"Error initiating proximity check: {e}")
            import traceback
            traceback.print_exc()
            return f"ERROR:{str(e)}"

    def handle_proximity_request(self, sender, encrypted_loc_str, paillier_pubkey_str):
        """Handle an incoming proximity check request with enhanced debugging"""
        try:
            print("\n===== DEBUG: HANDLING PROXIMITY REQUEST =====")
            if not self.current_location:
                print("DEBUG: Cannot perform proximity check: location not set")
                return

            # Parse friend's Paillier public key
            try:
                print(f"DEBUG: Parsing sender's Paillier public key")
                n, g = map(int, paillier_pubkey_str.split(','))
                sender_pubkey = (n, g)
                print(f"DEBUG: Parsed sender public key successfully")
                # Cache it for future use
                self.friend_paillier_pubkeys[sender] = sender_pubkey
            except Exception as e:
                print(f"DEBUG: Error parsing Paillier public key: {e}")
                return

            # Deserialize encrypted location
            try:
                print(f"DEBUG: Deserializing encrypted location from sender")
                encrypted_loc = paillier.deserialize_encrypted_location(encrypted_loc_str)
                print(f"DEBUG: Successfully deserialized encrypted location")
            except Exception as e:
                print(f"DEBUG: Error deserializing location: {e}")
                return

            # Get my location
            my_x, my_y = self.current_location
            print(f"DEBUG: My location: ({my_x}, {my_y})")

            # Log the threshold
            print(f"DEBUG: Using proximity threshold: {PROXIMITY_THRESHOLD}")
            print(f"DEBUG: This means users are 'nearby' if squared Euclidean distance ≤ {PROXIMITY_THRESHOLD}")

            # Compute proximity result (encrypted)
            try:
                print(f"DEBUG: Computing proximity using homomorphic operations")
                encrypted_result = paillier.compute_proximity(
                    sender_pubkey,
                    encrypted_loc,
                    my_x,
                    my_y,
                    PROXIMITY_THRESHOLD
                )
                print(f"DEBUG: Successfully computed encrypted proximity result")
            except Exception as e:
                print(f"DEBUG: Error in compute_proximity: {e}")
                import traceback
                traceback.print_exc()
                return

            # Serialize for transmission
            try:
                print(f"DEBUG: Serializing result for transmission")
                encrypted_result_str = paillier.serialize_ciphertext(encrypted_result)
                print(f"DEBUG: Result serialized. Length: {len(encrypted_result_str)}")
            except Exception as e:
                print(f"DEBUG: Error serializing result: {e}")
                return

            # Send result back
            try:
                print(f"DEBUG: Sending result back to {sender}")
                self.send_command(f"PROXIMITY_RESULT:{sender}:{encrypted_result_str}\n".encode())
                print(f"DEBUG: Sent proximity check result to {sender}")
            except Exception as e:
                print(f"DEBUG: Error sending result: {e}")

            print("===== END DEBUG: HANDLING PROXIMITY REQUEST =====\n")

        except Exception as e:
            print(f"DEBUG: Unexpected error handling proximity request: {e}")
            import traceback
            traceback.print_exc()

    def handle_proximity_result(self, sender, encrypted_result_str):
        """Handle a proximity check result with improved negative number handling"""
        try:
            print("\n===== DEBUG: HANDLING PROXIMITY RESULT =====")
            print(f"Received encrypted result from {sender}")

            # Deserialize encrypted result
            try:
                print(f"DEBUG: Deserializing encrypted result")
                encrypted_result = paillier.deserialize_ciphertext(encrypted_result_str)
                print(f"DEBUG: Successfully deserialized result")
            except Exception as e:
                print(f"DEBUG: Error deserializing result: {e}")
                import traceback
                traceback.print_exc()
                return

            # Decrypt the result using my private key
            try:
                print(f"DEBUG: Decrypting result with my private key")
                decrypted_result = paillier.decrypt(
                    self.paillier_private_key,
                    self.paillier_public_key,
                    encrypted_result
                )
                print(f"DEBUG: Successfully decrypted result: {decrypted_result}")

                # For Paillier with very large values, we need to interpret correctly
                n = self.paillier_public_key[0]

                # Print both possible interpretations for debugging
                print(f"DEBUG: Raw decrypted result: {decrypted_result}")
                print(f"DEBUG: As negative (if applicable): {decrypted_result - n}")
                print(f"DEBUG: Modulus n: {n}")

                # In Paillier, a negative number -x is represented as (n - x)
                # For our proximity test, a negative result means "nearby"

                # If the value is closer to n than to 0, treat it as negative
                if decrypted_result > n / 2:
                    adjusted_result = decrypted_result - n
                    print(f"DEBUG: Interpreting as negative: {adjusted_result}")
                else:
                    adjusted_result = decrypted_result
                    print(f"DEBUG: Interpreting as positive: {adjusted_result}")

                # If adjusted result ≤ 0, users are nearby (distance² ≤ threshold)
                nearby = adjusted_result <= 0
                print(f"DEBUG: Final interpretation - Is nearby: {nearby}")

                if nearby:
                    result_msg = f"{sender} is nearby (within threshold)"
                else:
                    result_msg = f"{sender} is not nearby (outside threshold)"

                print(f"DEBUG: Final result message: {result_msg}")
                self.message_queue.put(f"NOTIFICATION:{result_msg}")

            except Exception as e:
                print(f"DEBUG: Error decrypting result: {e}")
                import traceback
                traceback.print_exc()
                return

            # Compute and display the round-trip CPU overhead
            if hasattr(self, 'proximity_start_time'):
                elapsed = time.perf_counter() - self.proximity_start_time
                print(f"Proximity check round-trip CPU time: {elapsed:.6f} seconds")
                # Optionally, remove the attribute after using it
                del self.proximity_start_time

            print("===== END DEBUG: HANDLING PROXIMITY RESULT =====\n")

        except Exception as e:
            print(f"DEBUG: Unexpected error processing proximity result: {e}")
            import traceback
            traceback.print_exc()
            self.message_queue.put(f"NOTIFICATION:Error processing proximity result from {sender}")

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

    def display_friends_for_proximity(self):
        """Display friend list and allow user to select for proximity check"""
        print("\nRetrieving your friends list...")
        response = self.get_friends_list()

        # Debug output to see exactly what response we're getting
        print(f"DEBUG: Response from get_friends_list: {response}")

        if not response.startswith("FRIENDS:"):
            print(f"Error retrieving friends list: {response}")
            return None

        # Extract friends list
        friends_str = response.split(':', 1)[1].strip()

        # Check if friends list is empty
        if not friends_str:
            print("You don't have any friends yet. Add friends first to use proximity check.")
            return None

        # Parse friends list
        friends = friends_str.split(',')

        print("\nYour Friends:")
        for i, friend in enumerate(friends, 1):
            print(f"{i}. {friend}")

        # Get selection from user
        while True:
            try:
                choice = input("\nSelect a friend to check proximity (0 to cancel): ")
                choice = int(choice.strip())

                if choice == 0:
                    return None

                if 1 <= choice <= len(friends):
                    return friends[choice - 1]

                print(f"Invalid selection. Please enter a number between 0 and {len(friends)}.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except Exception as e:
                print(f"Error: {e}")
                return None

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

    print("\nSecure Location Sharing Client")
    print("ElGamal encryption for authentication and messaging")
    print("Paillier homomorphic encryption for privacy-preserving proximity checks")
    print("=================================================================")

    logged_in = False
    while not logged_in:
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

            print("Attempting to login...")
            login_success = client.login(username, password)

            if login_success:
                print("Login successful!")
                logged_in = True
            else:
                print("Login failed. Please try again.")

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
            print("\nPrivacy-Preserving Proximity Check")
            print("This will check if your friend is within √2500 ≈ 50 units of your location")
            print("Your exact coordinates will remain private\n")

            # Check if location is set before allowing proximity check
            if not client.current_location:
                print("Error: You need to update your location before you can check proximity.")
                print("Please use option 2 (Update Location) first.")
                continue

            try:
                print("Displaying friends list for proximity check...")
                # Display friend selection menu
                selected_friend = client.display_friends_for_proximity()

                if selected_friend:
                    print(f"Initiating proximity check with {selected_friend}...")
                    try:
                        response = client.initiate_proximity_check(selected_friend)
                        if response.startswith("ERROR"):
                            print(f"Error during proximity check: {response}")
                        else:
                            print("Proximity check request sent. You'll be notified of the result.")
                    except Exception as e:
                        print(f"Exception during proximity check: {e}")
                else:
                    print("Proximity check cancelled or no friend was selected.")
            except Exception as e:
                print(f"Error in proximity check menu: {e}")
                import traceback
                traceback.print_exc()

            # Wait for user to acknowledge before returning to main menu
            input("\nPress Enter to return to main menu...")

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
