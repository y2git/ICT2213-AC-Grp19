import socket
import elgalmal
import threading
import queue
import time
import getpass
import sys

target_PORT = 60
target_IP = '127.0.0.1'
BUF_SIZE = 4096


class Client:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = None
        self.server_pubkey = None
        self.public_key = None
        self.private_key = None
        self.friend_pubkeys = {}
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
                p, g, h = map(int, data.split(':')[1].split(','))
                self.server_pubkey = (p, g, h)
                self.public_key, self.private_key = elgalmal.generate_keys()
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
                        if msg.startswith(("SUCCESS:", "ERROR:", "PROXIMITY:", "PUBKEY:", "REQUESTS:", "FRIENDS:")):
                            with self.lock:
                                self.response_queue.put(msg)
                        elif msg.startswith(("MESSAGE:", "NOTIFICATION:")):
                            self.message_queue.put(msg)
            except Exception as e:
                if self.running:
                    print(f"Receive error: {str(e)}")
                break

    def send_command(self, command, timeout=5):
        try:
            with self.lock:
                self.response_queue.queue.clear()
            self.sock.send(command)
            start_time = time.time()
            while time.time() - start_time < timeout:
                with self.lock:
                    if not self.response_queue.empty():
                        return self.response_queue.get()
                time.sleep(0.1)
            return "ERROR:Timeout waiting for response"
        except Exception as e:
            return f"ERROR:{str(e)}"

    def register(self, username, password):
        return self.send_command(f"REGISTER:{username}:{password}\n".encode())

    def login(self, username, password):
        response = self.send_command(f"LOGIN:{username}:{password}\n".encode())
        if response.startswith("SUCCESS"):
            self.username = username
            pubkey_str = f"{self.public_key[0]},{self.public_key[1]},{self.public_key[2]}"
            self.send_command(f"REGISTER_PUBKEY:{pubkey_str}\n".encode())
            return True
        elif response.startswith("ERROR"):
            # Extract and print the error message from the server
            error_msg = response.split(':', 1)[1] if ':' in response else "Login failed"
            print(f"Error: {error_msg}")
            return False
        return False

    def logout(self):
        if self.username:
            response = self.send_command(f"LOGOUT:\n".encode())
            self.username = None
            return response.startswith("SUCCESS")
        return False

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
        return self.send_command(f"GET_REQUESTS:\n".encode())

    def respond_to_request(self, sender, response):
        return self.send_command(f"FRIEND_RESPONSE:{sender}:{response}\n".encode())

    def get_friends_list(self):
        return self.send_command(f"GET_FRIENDS:\n".encode())

    def update_location(self, x, y):
        try:
            c1, c2 = elgalmal.encrypt(self.server_pubkey, x)
            c3, c4 = elgalmal.encrypt(self.server_pubkey, y)
            return self.send_command(f"UPDATE_LOCATION:{c1},{c2}:{c3},{c4}\n".encode())
        except Exception as e:
            return f"ERROR:{str(e)}"

    def check_proximity(self, friend):
        response = self.send_command(f"PROXIMITY:{friend}\n".encode())
        if response.startswith("PROXIMITY:"):
            status = response.split(':')[1].upper()
            print(f"\nProximity: {'Nearby' if status == 'TRUE' else 'Not nearby'}")
        else:
            print(f"\nError: {response.split(':', 1)[-1]}")

    def send_message(self, friend, message):
        try:
            pubkey = self.get_friend_pubkey(friend)
            if not pubkey:
                return "ERROR:No public key found"

            p = pubkey[0]
            encrypted_chars = []
            for char in message:
                # Convert character to ASCII code
                char_code = ord(char)
                # Encrypt each character separately
                c1, c2 = elgalmal.encrypt(pubkey, char_code)
                encrypted_chars.append(f"{c1},{c2}")

            # Join encrypted characters with a separator
            ciphertext = ';'.join(encrypted_chars)
            return self.send_command(f"SEND_MSG:{friend}:{ciphertext}\n".encode())
        except Exception as e:
            return f"ERROR:{str(e)}"

    def print_messages(self):
        while not self.message_queue.empty():
            msg = self.message_queue.get()
            if msg.startswith("MESSAGE:"):
                parts = msg.split(':', 2)
                if len(parts) >= 3:
                    sender = parts[1]
                    encrypted_chars = parts[2].split(';')
                    decrypted = []
                    for ec in encrypted_chars:
                        try:
                            c1, c2 = map(int, ec.split(','))
                            char_code = elgalmal.decrypt(self.private_key, c1, c2)
                            decrypted.append(chr(char_code))
                        except Exception as e:
                            decrypted.append(f'[?]')
                    print(f"\n{sender}: {''.join(decrypted)}")
            elif msg.startswith("NOTIFICATION:"):
                print(f"\n[!] {msg.split(':', 1)[1]}")


def masked_input():
    """Custom function to handle password input with masking characters"""
    password = ""
    print("Password: ", end="", flush=True)

    # For Windows
    if sys.platform == 'win32':
        import msvcrt
        while True:
            key = msvcrt.getch()
            # Convert bytes to string
            key_decoded = key.decode('utf-8') if hasattr(key, 'decode') else key

            # Check for Enter key
            if key == b'\r' or key == b'\n' or key_decoded == '\r' or key_decoded == '\n':
                print()
                break
            # Check for backspace
            elif key == b'\b' or key_decoded == '\b':
                if len(password) > 0:
                    password = password[:-1]
                    # Erase the last * from screen
                    print('\b \b', end='', flush=True)
            # Check for Ctrl+C or other control characters
            elif key_decoded in ('\x03', '\x04'):  # Ctrl+C, Ctrl+D
                raise KeyboardInterrupt
            else:
                password += key_decoded
                print('*', end='', flush=True)
    # For Unix/Linux/MacOS
    else:
        import termios, tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                key = sys.stdin.read(1)
                # Check for Enter key
                if key == '\r' or key == '\n':
                    print()
                    break
                # Check for backspace
                elif key == '\x7f':  # backspace
                    if len(password) > 0:
                        password = password[:-1]
                        # Erase the last * from screen
                        print('\b \b', end='', flush=True)
                # Check for Ctrl+C or other control characters
                elif key in ('\x03', '\x04'):  # Ctrl+C, Ctrl+D
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

    # Authentication flow
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Choice: ").strip()

        if choice == '1':
            username = input("Username: ").strip()
            # Try to use getpass, fall back to input if it fails
            try:
                print("Password: ", end='', flush=True)
                password = getpass.getpass("")
            except Exception:
                # If getpass fails, use input with a custom masking function
                password = masked_input()
            print(client.register(username, password))


        elif choice == '2':
            username = input("Username: ").strip()
            # Try to use getpass, fall back to input if it fails
            try:
                print("Password: ", end='', flush=True)
                password = getpass.getpass("")
            except Exception:
                # If getpass fails, use input with a custom masking function
                password = masked_input()
            if client.login(username, password):
                print("Login successful!")
                while True:
                    try:
                        x = int(input("Initial X: "))
                        y = int(input("Initial Y: "))
                        if "SUCCESS" in client.update_location(x, y):
                            break
                    except ValueError:
                        print("Invalid coordinates")
                break

        elif choice == '3':
            client.running = False
            return
        else:
            print("Invalid choice")

    # Main menu
    while client.running:
        client.print_messages()
        print("\n1. Friend Management\n2. Update Location\n3. Check Proximity\n4. Send Message\n5. Exit")
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
                                sender = input("Enter username of the request to respond to: ").strip()
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

            elif friend_choice == '4':
                continue

            else:
                print("Invalid choice")

        elif choice == '2':
            try:
                x = int(input("X: "))
                y = int(input("Y: "))
                print(client.update_location(x, y))
            except ValueError:
                print("Invalid coordinates")

        elif choice == '3':
            # First, get the list of friends
            response = client.get_friends_list()
            if response.startswith("FRIENDS:"):
                friends = response.split(':', 1)[1].strip()
                if not friends:
                    print("You don't have any friends yet.")
                else:
                    friends_list = friends.split(',')
                    print("\nYour Friends:")
                    for friend in friends_list:
                        print(f"- {friend}")

                    friend_name = input("\nEnter friend's username to check proximity: ").strip()
                    if friend_name in friends_list:
                        client.check_proximity(friend_name)
                    else:
                        print(f"Error: {friend_name} is not in your friends list.")
            else:
                print(response)

        elif choice == '4':
            # First, get the list of friends
            response = client.get_friends_list()
            if response.startswith("FRIENDS:"):
                friends = response.split(':', 1)[1].strip()
                if not friends:
                    print("You don't have any friends yet.")
                else:
                    friends_list = friends.split(',')
                    print("\nYour Friends:")
                    for friend in friends_list:
                        print(f"- {friend}")

                    friend_name = input("\nEnter friend's username to message: ").strip()
                    if friend_name in friends_list:
                        message = input(f"Message for {friend_name}: ").strip()
                        print(client.send_message(friend_name, message))
                    else:
                        print(f"Error: {friend_name} is not in your friends list.")
            else:
                print(response)

        elif choice == '5':
            client.running = False
            client.sock.close()
            print("Goodbye!")

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()