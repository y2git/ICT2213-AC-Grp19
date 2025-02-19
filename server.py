import socket
import threading
import sqlite3

def login_user(username,password):
    # Connect to the SQLite database
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()

    # Execute the query to check for matching username and password
    cursor.execute('''SELECT * FROM user WHERE username = ? AND password = ?''', (username, password))
    data = cursor.fetchall()

    # Close the connection
    conn.close()

    # True if there is only 1 entry
    if len(data) == 1:
        print(f'Account {username} logged in.')
        return True
    
    return False

def create_user(username, password):
    # Connect to the SQLite database
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()

    # Check if the username already exists
    cursor.execute('''SELECT * FROM user WHERE username = ?''', (username,))
    if cursor.fetchone() is not None:
        conn.close()
        return False  # Username already exists

    # Insert the new username and password into the table
    cursor.execute('''INSERT INTO user (username, password) VALUES (?, ?)''', (username, password))
    conn.commit()

    # Close the connection
    conn.close()

    print(f'New account {username} created.')
    return True  # User successfully created

# Server will be hosted under:
server_PORT = 60
server_IP = '127.0.0.1'
# Establish buffer size of the data to be received:
BUF_SIZE = 1024

# Create a socket object named 's'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((server_IP, server_PORT))

# Socket listen (backlog = number of pending connections that can be queued)
s.listen(2)
print("Server Online.")

def client_handler(con, addr):
    print(f'New connection from {addr}')
    login_status = False
    con.send("Welcome! Type 'login' to login or 'register' to create a new account:".encode())
    # Ask for login or registration
    while login_status==False:
        
        ddata = con.recv(BUF_SIZE).decode()
        # Client login
        if ddata == 'login':
            con.send("Enter your username:".encode())
            username = con.recv(BUF_SIZE).decode()
            con.send("Enter your password:".encode())
            password = con.recv(BUF_SIZE).decode()

            if login_user(username, password):
                con.send("Login successful!".encode())
                login_status = True
            else:
                con.send("Login failed! Incorrect username or password.".encode())
        # Client registers account
        elif ddata == 'register':
            con.send("Enter a username for your new account:".encode())
            username = con.recv(BUF_SIZE).decode()
            con.send("Enter a password for your new account:".encode())
            password = con.recv(BUF_SIZE).decode()

            if create_user(username, password):
                con.send("Account created successfully!".encode())
            else:
                con.send("Username already exists. Try again with a different username.".encode())
        # Client disconnect
        elif ddata == '.exit':
            print(f"{addr} disconnected.")
            con.send("disconnecting...".encode())
            con.close()
        # Invalid command
        else:
            con.send("Invalid action. Please choose 'login' or 'register'.".encode())

    # After login
    while login_status==True:
        ddata = con.recv(BUF_SIZE).decode()

        if not ddata:
            print("Nothing received.")
            continue
        elif ddata == '.logout':
            print(f"{addr} logged out!")
            con.send("logging out...".encode())
            con.close()
            break  # exit the inner while loop to stop receiving messages
        else:
            print(f"Received data from {addr}: {ddata}")
            # Send alert that data was successfully received
            con.send("Optimal".encode())
    
    print(f"Connection with {addr} closed.")

while True:
    # con is a new socket object created after a connection is accepted
    con, addr = s.accept()
    # Start a new thread for each client connection
    threading.Thread(target=client_handler, args=(con, addr)).start()

# close server
s.close()
