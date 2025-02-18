#! python3
import socket

import sys
print("Python version")
print(sys.version)
print("Version info:", sys.version_info)

#target detials where the client will connect to: 
target_PORT = 60
target_IP = '127.0.0.1'
#establish buffer size of the data to be sent:
BUF_SIZE = 1024

#create a socket object named 's'
s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((target_IP, target_PORT))
    print("Connection successful!")
    print("'x' to shutdown server.")
    print("'.exit' to close connection.")

    while True:
        #user input data:
        data = input("Data to send => ")
        #check if data is null, else send
        if not data:
            print("No data sent.")
        elif data == ".exit":
            print("Client exiting...")
            break
        else:
            #encode data as unencoded data in Python 3+ will result in error
            s.send(data.encode())
            #recieve server response to data sent
            data = s.recv(BUF_SIZE)
            print("Server: ", data.decode())
#except Exception as e:
#    print("An error occurred: " + str(e))
finally:
    # Ensure the socket is closed properly
    s.close()
    print("Connection closed.")