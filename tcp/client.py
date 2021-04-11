# Code references https://realpython.com/python-sockets
#!/usr/bin/env python3

import socket

# The server's hostname or IP address
HOST = '127.0.0.1'  
# The port used by the server
PORT = int(input("Port? "))

# Create socket object s
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Connect to server
    s.connect((HOST, PORT))

    while True:
        data = input("Data? ")
        # data = f"{str(len(data))}:{data}"
        data = str.encode(data)
        
        # Send data to server
        s.sendall(data)

        # Receive data from server
        data = s.recv(1024)

        # Print received data from server
        print('Received', repr(data))