import socket
import threading
import queue
import time
import getpass
import sys
import json
import base64
import elgamal

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
                # Generate client's ElGamal key pair
                self.public_key, self.private_key = elgamal.generate_keys()
            return True
        except Exception as e:
            print(f"Connection error: {str(e)}")
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
                    if msg:
                        # Standard responses and notifications
                        if msg.startswith(("SUCCESS:", "ERROR:", "PUBKEY:", "REQUESTS:", "FRIENDS:", "LOCATION:")):
                            with self.lock:
                                self.response_queue.put(msg)
                        elif msg.startswith("NOTIFICATION:"):
                            self.message_queue.put(msg)
                        else:
                            # Unhandled messages
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
        return self.send_command(f"REGISTER:{username}:{password}\n".encode())

    def login(self, username, password):
        response = self.send_command(f"LOGIN:{username}:{password}")
        if response.startswith("SUCCESS"):
            self.username = username
            pubkey_str = f"{self.public_key[0]},{self.public_key[1]},{self.public_key[2]}"
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
            return self.friend_pubkeys[friend]
        response = self.send_command(f"GET_PUBKEY:{friend}\n".encode())
        if response.startswith("PUBKEY:"):
            _, _, key_data = response.split(':', 2)
            p, g, h = map(int, key_data.split(','))
            self.friend_pubkeys[friend] = (p, g, h)
            return (p, g, h)
        return None

    def add_friend(self, friend):
        return self.send_command(f"ADD_FRIEND:{friend}\n".encode())

    def get_friend_requests(self):
        return self.send_command("GET_REQUESTS:\n".encode())

    def respond_to_request(self, sender, response):
        return self.send_command(f"FRIEND_RESPONSE:{sender}:{response}\n".encode())

    def get_friends_list(self):
        return self.send_command("GET_FRIENDS:\n".encode())

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
                print(f"[!] {msg.split(':', 1)[1]}")

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
                response = client.get_friend_requests()
                if response.startswith("REQUESTS:"):
                    requests = response.split(':', 1)[1].strip()
                    if not requests:
                        print("No pending friend requests.")
                    else:
                        requests_list = requests.split(',')
                        print("\nPending Friend Requests:")
                        for req in requests_list:
                            print(f"- {req}")
                        if requests_list:
                            print("\nRespond to a request? (y/n)")
                            if input().strip().lower() == 'y':
                                sender = input("Enter username to respond to: ").strip()
                                if sender in requests_list:
                                    print(f"Accept request from {sender}? (y/n)")
                                    resp = "ACCEPT" if input().strip().lower() == 'y' else "DECLINE"
                                    print(client.respond_to_request(sender, resp))
                                else:
                                    print(f"Error: No pending request from {sender}.")
                else:
                    print(response)
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
