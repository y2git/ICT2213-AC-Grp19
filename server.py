import socket
#server will hosted under:
server_PORT = 60
server_IP = '127.0.0.1'
#establish buffer size of the data to be recieved:
BUF_SIZE = 30

#create a socket object named 's'
s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.bind((server_IP, server_PORT))
#socket.listen(backlog), backlog = number of pending connections that can be queued
s.listen(1)
print("Server Online.")
while True :
    #con is a new socket object created after a connection is accepted
    con, addr = s.accept()
    print ('Connection Address is: ', addr)
    data = con.recv(BUF_SIZE)
    #decode data recieved
    ddata = data.decode()
    if not ddata:
        print("Nothing recieved.")
    elif ddata == 'x':
        print("Server Shutting Down!")
        con.close()
        break
    else:
        print("Received data:", ddata)
        #send alert that data successfully recieved
        con.send("Optimal".encode())
#close server socket once 'x' recieved
s.close()