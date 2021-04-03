#! /usr/bin/env python3

# EphID and Shamir Secret Sharing Mechanism
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import hashlib


# UDP Programming
import socket
import time

import binascii

#import ecdsa
from ecdsa import ECDH, SECP128r1
#from ecdh import ECDH


# Threading
import threading

server = None
client = None

# Variable to hold shares along with hash of EphID



# Task 1: Generate a 16-Byte Ephemeral ID (EphID) after every 1 minute.
def compress(pubKey):
    '''
    Displays public key in hex format
    '''
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

def genEphID():
    '''
    Generates a 16-Byte Ephemeral ID
    Returns ephID
    '''
    ecdh = ECDH(curve=SECP128r1)
    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()

    ephID = public_key.to_string('compressed')[1:]

    print(f"Ephemeral ID: {ephID}")
    print(f"Number of Bytes: {len(ephID)}")
    
    return ephID

ephID = None
# Test
def task1():
    global ephID
    ephID = genEphID()

# Task 2: Prepare n shares of the EphID by using k-out-of-n Shamir Secret Sharing mechanism. 
# For this implementation, we use the values of k and n to be 3 and 6 respectively.
def genShares(ephID):
    '''
    Prepares 6 chunks of an ephemeral ID (ephID)
    Returns list of 6 chunks
    '''
    shares = Shamir.split(3, 6, ephID)
    print(f"Shares: {shares}")
    return shares

shares = None
# Test
def task2():
    global shares
    shares = genShares(ephID)

# Task 3: Broadcast these n shares @ 1 unique share per 10 seconds. 
# For this implementation, you do not need to implement the simultaneous advertisement of EphIDs proposed in the reference paper [1].
########## SENDER ##########
# UDP socket programming references https://github.com/ninedraft/python-udp
def user_send(ephID):
    '''
    User broadcasts one share of the EphID every 10 seconds to another user
    '''
    # Determine Hash of EphID
    hash_ephID = hashlib.sha256(ephID).hexdigest()

    # Determine shares of EphID
    ephID_shares = genShares(ephID)

    i = 0
    while True:
        # Convert share to bytes
        print("********** SHARES SENT **********")
        print(f"SHARE NUMBER: {i}")
        print(ephID_shares[i][1])
        print(hash_ephID)
        share = (ephID_shares[i][0], binascii.hexlify(ephID_shares[i][1]), hash_ephID)
        share_bytes = str.encode(str(share))

        server.sendto(share_bytes, ('<broadcast>', 37025))

        # Increment to next share
        if (i < 5):
            i += 1
        else:
            i = 0

        # Send every 10 seconds
        # TODO - UPDATE TO 10 SECONDS, 1 SECOND BETTER FOR TESTING
        time.sleep(1)

########## RECEIVER ##########
def add_share(rec_hash, rec_share):
    '''
    Adds a share (share_num, share_bytes) to the receiver's global shares variable
    '''
    # Shares data structure should look like:
    # shares = [
    #     {
    #         "hash": str,
    #         "shares": [share1, share2, share3, etc.]
    #     }
    # ]
    global shares

    print("********** INSIDE ADD_SHARE **********")
    print(f"rec_hash: {rec_hash}")
    print(f"rec_share: {rec_share}")

    is_hash_in_shares = False

    for share in shares:
        # Check if hash is already in shares
        if share['hash'] == rec_hash:
            is_hash_in_shares = True
            # If hash already in shares, append non-duplicate shares
            if rec_share not in share['shares']:
                share['shares'].append(rec_share)
    
    if not is_hash_in_shares:
        # If hash not in shares, create new object with this share
        shares.append(
            {
                "hash": rec_hash,
                "shares": [rec_share]
            }
        )

def has_k_shares(k, rec_hash):
    '''
    Determines if the receiver has enough of rec_hash shares 
    to reconstruct the sender's EphID
    '''
    global shares

    for share in shares:
        if share['hash'] == rec_hash:
            return len(share['shares']) >= k

    return False

def reconstruct_eph_id(rec_hash):
    '''
    Reconstructs a sender's ephID from the received shares
    '''
    global shares
    ephID = None

    for share in shares:
        if share['hash'] == rec_hash:
            ephID = Shamir.combine(share['shares'])
    
    return ephID

def user_receive():
    '''
    User receives broadcast from another user
    '''
    global shares
    shares = []
    hash_ephID = None

    while True:
        # Receive data
        data, addr = client.recvfrom(1024)

        # Convert data to (share number, share)
        data_str = data.decode()
        share_num = int(data_str.split(',')[0].replace("(", ""))
        share_hex = data_str.split(', b')[1].split(',')[0].replace(")", "").replace(" ", "").replace("'", "")
        hash_ephID = data_str.split(', b')[1].split(',')[1].replace(")", "").replace(" ", "").replace("'", "")
        print("**** SHARE HEX *****")
        print(share_hex)
        print(hash_ephID)
        print(type(hash_ephID))
        share_bytes = binascii.unhexlify(share_hex)
        share = (share_num, share_bytes)

        print("********** SHARE RECEIVED **********")
        print(share)
        
        # Add to shares
        add_share(hash_ephID, share)
        print("********** SHARES DATA STRUCTURE **********")
        print(shares)

        # If have atleast 3 shares, reconstruct EphID
        if has_k_shares(3, hash_ephID):
            ephID = reconstruct_eph_id(hash_ephID)
            print("Reconstructing")
            print(f"Reconstructed EphID: {ephID}")

            print("Is hash the same?")
            print(hashlib.sha256(ephID).hexdigest() == hash_ephID)
            print(hashlib.sha256(ephID))
            print(hash_ephID)

def task3():
    global server
    global client
    ########## SENDER ##########
    # UDP socket programming references https://github.com/ninedraft/python-udp

    # Create UDP socket for sender
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Enable port reusage so we can run multiple clients/servers on single (host/port)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Enable broadcasting mode
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Set a timeout so the socket does not block indefinitely when trying to receive data.
    server.settimeout(0.2)
    # Bind socket to localhost port 44444
    server.bind(("", 44444))

    # Create thread for user to broadcast chunks of the EphID
    message = ephID
    send_broadcast = threading.Thread(target=user_send, args=(ephID,))
    send_broadcast.start()


    ########## RECEIVER ##########

    # Create UDP socket for receiver
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # Enable port reusage so we will be able to run multiple clients and servers on single (host, port).
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # Enable broadcasting mode
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Bind socket to localhost port 37024
    client.bind(("", 37025))

    # Create thread for user to receive broadcasts
    receive_broadcast = threading.Thread(target=user_receive)
    receive_broadcast.start()

# Task 4: 4-A Show the devices attempting re-construction of EphID when these have received at least 3 shares.
# Task 4: 4-B Show the devices verifying the re-constructed EphID by taking the hash of re-constructed EphID and comparing with the hash value received in the advertisement.
def task4():
    pass

# Task 5: 5-A Show the devices computing the shared secret EncID by using Diffie- Hellman key exchange mechanism.
# Task 5: 5-B Show that the devices have arrived at the same EncID value.
def task5():
    pass

# Task 6: Show that the devices are encoding EncID into the DBF and deleting the EncID.
def task6():
    pass

# Task 7: 7-A Show that the devices are encoding multiple EncIDs into the same DBF and show the state of the DBF after each addition.
# Task 7: 7-B Show that a new DBF gets created for the devices after every 10 minutes. A device can only store maximum of 6 DBFs.
def task7():
    pass

# Task 8: Show that after every 60 minutes, the devices combine all the available DBFs into a single QBF.
def task8():
    pass

# Task 9: 9-A Show that the devices send the QBF to the back-end server. For extension, the back-end server is your own centralised server.
# Task 9: 9-B Show that the devices are able to receive the result of risk analysis back from the back-end server. Show the result for a successful as well as an unsuccessful match. For extension, the back-end server is your own centralised server.
def task9():
    pass

# Task 10: Show that a device can combine the available DBF into a CBF and upload the CBF to the back-end server. For extension, the back-end server is your own centralised server.
def task10():
    pass

# Task 11: 11-A Show that the device is able to establish a TCP connection with the centralised server and perform Tasks 9 and 10 successfully.
# Task 11: 11-B Show the terminal for the back-end server performing the QBF-CBF matching operation for risk analysis.
def task11():
    pass

def task12():
    pass

def handle_args():
    import argparse
    parser = argparse.ArgumentParser(description="Runner script for DIMY assignment")
    parser.add_argument("task", type=int, nargs="*", default=99, help="Task number to run.")
    parser.add_argument("--port", "-p", type=int, action="store", nargs=2, help="Port number to run client/server on.")

    args = parser.parse_args()
    
    return args.task, (args.port if args.port else None)


tasks = [
    task1,
    task2,
    task3,
    task4,
    task5,
    task6,
    task7,
    task8,
    task9,
    task10,
    task11,
    task12,
]

if __name__ == "__main__":
    task, empty = handle_args()

    if type(task) is not int and len(task) == 1:
        task = task[0]
    elif type(task) is not int:
        for i in task:
            tasks[i]()

    if task > len(tasks):
        for i, f in enumerate(tasks):
            f()
    else:
        i = 0
        while i < task:
            tasks[i]()
            i += 1
        # tasks[task - 1]()
    while True:
        try:
            num = input("Enter a number to run that task. EOF to end.")
            num = int(num)
            i = 0
            while i < num:
                tasks[i]()
                i += 1
        except EOFError:
            break
