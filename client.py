import socket
#target detials where the client will connect to: 
target_PORT = 60
target_IP = '127.0.0.1'
#establish buffer size of the data to be sent:
BUF_SIZE = 1024

#create a socket object named 's'
s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_IP, target_PORT))
#user input data:
data = input("Data to send ['x' to shutdown server]=> ")
#check if data is null, else send
if not data:
    print("No data sent.")
else:
    #encode data as unencoded data in Python 3+ will result in error
    s.send(data.encode())
    #recieve server response to data sent
    data = s.recv(BUF_SIZE)
    print("Server: ", data.decode())
#close connection after sending
s.close