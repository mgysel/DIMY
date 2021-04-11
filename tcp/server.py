# Code references: https://stackoverflow.com/questions/23828264/how-to-make-a-simple-multithreaded-socket-server-in-python-that-remembers-client
import socket
import threading

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port

        # Create a LISTENING socket object
        # AF_INET specifies IPV4 internet address family, SOCK_STREAM specifies connection type for TCP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Allows reuse of local addresses
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Associate socket with a host/port
        # Because IPV4 address family, s.bind expects (host, port)
        self.sock.bind((self.host, self.port))

    def listen(self):
        '''
        Creates TCP connection with new client
        Creates new thread for each new client
        '''
        # listen() enables server to accept connections
        #self.sock.listen(5)
        self.sock.listen()
        while True:
            # accept() blocks and waits for incoming connections
            # When a client connects, returns new CONNECTION socket object and address tuple (host, port) of client
            client, address = self.sock.accept()

            # Socket closes if no data transfered in 60 seconds
            client.settimeout(60)

            # Creates new thread for each connection
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        '''
        Sends and receives data from client
        '''
        size = 1024
        buffer = ''
        # Infinite loop to send/receive data from client
        while True:
            try:
                data = client.recv(size)
                if data:
                    print(f"Received {data}")
                    # Respond to client with same data
                    response = data
                    client.send(response)
                else:
                    raise Exception('Client disconnected')
            except:
                # If error, close connection
                client.close()
                return False

if __name__ == "__main__":
    while True:
        port_num = input("Port? ")
        try:
            port_num = int(port_num)
            break
        except ValueError:
            pass

    ThreadedServer('',port_num).listen()