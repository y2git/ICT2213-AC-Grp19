import socket
import elgalmal
import threading
import queue
import time

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
                        if msg.startswith(("SUCCESS:", "ERROR:", "PROXIMITY:", "PUBKEY:")):
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
            password = input("Password: ").strip()
            print(client.register(username, password))

        elif choice == '2':
            username = input("Username: ").strip()
            password = input("Password: ").strip()
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
        print("\n1. Add Friend\n2. Update Location\n3. Check Proximity\n4. Send Message\n5. Exit")
        choice = input("Choice: ").strip()

        if choice == '1':
            friend = input("Friend's username: ").strip()
            print(client.add_friend(friend))

        elif choice == '2':
            try:
                x = int(input("X: "))
                y = int(input("Y: "))
                print(client.update_location(x, y))
            except ValueError:
                print("Invalid coordinates")

        elif choice == '3':
            friend = input("Friend's username: ").strip()
            client.check_proximity(friend)

        elif choice == '4':
            friend = input("Friend: ").strip()
            message = input("Message: ").strip()
            print(client.send_message(friend, message))

        elif choice == '5':
            client.running = False
            client.sock.close()
            print("Goodbye!")

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()