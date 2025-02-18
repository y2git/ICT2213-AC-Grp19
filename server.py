import socket
import threading

def check_login(username,password):
    return False


# Server will be hosted under:
server_PORT = 60
server_IP = '127.0.0.1'
# Establish buffer size of the data to be received:
BUF_SIZE = 30

# Create a socket object named 's'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((server_IP, server_PORT))

# Socket listen (backlog = number of pending connections that can be queued)
s.listen(2)
print("Server Online.")

def client_handler(con, addr):
    print(f'New connection from {addr}')
    
    while True:
        data = con.recv(BUF_SIZE)
        ddata = data.decode()

        if not ddata:
            print("Nothing received.")
            continue
        elif ddata == 'x':
            print(f"Server Shutting Down for {addr}!")
            con.send("Server Shutting Down!".encode())
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