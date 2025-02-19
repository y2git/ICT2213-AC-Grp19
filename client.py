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
    connection = True
    while connection == True:
        sdata = s.recv(BUF_SIZE)    
        print("Server: ", sdata.decode())
        #user input data:
        data = input("Data to send => ")
        #check if data is null, else send
        if not data:
            s.send("-".encode())
        else:
            #encode data as unencoded data in Python 3+ will result in erroR
            s.send(data.encode())
#except Exception as e:
#    print("An error occurred: " + str(e))
finally:
    # Ensure the socket is closed properly
    s.close()
    print("Connection closed.")