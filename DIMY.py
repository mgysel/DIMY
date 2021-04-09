#! /usr/bin/env python3

# EphID and Shamir Secret Sharing Mechanism
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import hashlib

import base64


# UDP Programming
import socket
import time

import binascii

#import ecdsa
from ecdsa import ECDH, SECP128r1, VerifyingKey
#from ecdh import ECDH

# bloom filter library
# from bloom_filter import BloomFilter
# from pybloomfilter import BloomFilter
import bitarray
import mmh3
import math
from Crypto.Random.random import getrandbits

import requests

# Nicked the base from https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/
class BloomFilter(object):
    '''
    Class for Bloom filter, using murmur3 hash function
    '''
    # p
    fb_prob = None
    # n
    size = None
    # k
    hash_count = None
    # m
    bit_array = None
    
    curr_num = 0

    def __init__(self, size=800000, items_count=1000, fp_prob=0.0000062, num_hashes=3):
        '''
        items_count : int
            Number of items expected to be stored in bloom filter
        fp_prob : float
            False Positive probability in decimal
        '''
        # False posible probability in decimal
        self.fp_prob = fp_prob if fp_prob else 0.0000062

        # Size of bit array to use
        self.size = size if size else self.get_size(items_count, fp_prob)

        # number of hash functions to use
        self.hash_count = num_hashes if num_hashes else self.get_hash_count(self.size, items_count)

        # Bit array of given size
        self.bit_array = bitarray(size, initializer=0) if size else bitarray(self.size, initializer=0)

        # initialize all bits as 0
        self.bit_array.setall(0)
        
        self.curr_num = 0

    def add(self, item, debug=False):
        '''
        Add an item in the filter
        '''
        digests = []
        if debug is True:
            print("Changes: ", end="")
        for i in range(self.hash_count):

            # create digest for given item.
            # i work as seed to mmh3.hash() function
            # With different seed, digest created is different
            digest = mmh3.hash(item, i) % self.size
            digests.append(digest)

            # set the bit True in bit_array
            self.bit_array[digest] = True
            
            if debug is True:
                print(digest, end=" ")
        
        self.curr_num += 1

    def check(self, item):
        '''
        Check for existence of an item in filter
        '''
        for i in range(self.hash_count):
            digest = mmh3.hash(item, i) % self.size
            if self.bit_array[digest] == False:

                # if any of bit is False then,its not present
                # in filter
                # else there is probability that it exist
                return False
        return True

    def intersect(self, other_bloom_filter, inplace=False):
        '''
        Returns intersection/bitwise AND of the current and other_bloom_filter. inplace defaults to False. Not a true inplace operation. Just replaces the internal bitarray.
        '''
        # new_bit_array = bitarray(self.size)
        new_bit_array = self.bit_array & other_bloom_filter
        if inplace is True:
            self.bit_array = new_bit_array
        return new_bit_array

    def union(self, other_bloom_filter, inplace=False):
        '''
        Returns union/bitwise OR of the current and other_bloom_filter. inplace defaults to False. Not a true inplace operation. Just replaces the internal bitarray.
        '''
        # new_bit_array = bitarray(self.size)
        new_bit_array = self.bit_array | other_bloom_filter
        if inplace is True:
            self.bit_array = new_bit_array
        return new_bit_array

    @classmethod
    def get_size(self, n, p):
        '''
        Return the size of bit array(m) to used using
        following formula
        m = -(n * lg(p)) / (lg(2)^2)
        n : int
            number of items expected to be stored in filter
        p : float
            False Positive probability in decimal
        '''
        m = -(n * math.log(p))/(math.log(2)**2)
        return int(m)

    @classmethod
    def get_hash_count(self, m, n):
        '''
        Return the hash function(k) to be used using
        following formula
        k = (m/n) * lg(2)

        m : int
            size of bit array
        n : int
            number of items expected to be stored in filter
        '''
        k = (m/n) * math.log(2)
        return int(k)

    def __and__(self, obj):
        '''
        You shouldn't be using this. This is just to make it so that the class operates with Python's built in operators.
        '''
        if isinstance(BloomFilter, obj):
            return self.bit_array & obj.bit_array
        else:
            raise ValueError(f"{obj} not a {self}")

    def __or__(self, obj):
        '''
        You shouldn't be using this. This is just to make it so that the class operates with Python's built in operators.
        '''
        if isinstance(BloomFilter, obj):
            return self.bit_array | obj.bit_array
        else:
            raise ValueError(f"{obj} not a {self}")

    def __str__(self):
        '''
        You shouldn't be using this. This is just to make it so that the class operates with Python's built in operators.
        '''
        if isinstance(BloomFilter, obj):
            return self.bit_array
        else:
            raise ValueError(f"{obj} not a {self}")

    def __eq__(self, obj):
        '''
        You shouldn't be using this. This is just to make it so that the class operates with Python's built in operators.
        '''
        if isinstance(BloomFilter, obj):
            return self.bit_array == obj.bit_array
        else:
            raise ValueError(f"{obj} not a {self}")
    
    @classmethod
    def serialise(self, bit_array):
        '''
        Returns a base64-serialised, string version of itself.
        '''
        return bitarray.util.ba2base(64, bit_array)
    
    def serialise(self):
        '''
        Returns a base64-serialised, string version of itself.
        '''
        return bitarray.util.ba2base(64, self.bit_array)
    
    # NOTE: These probably won't be used.
    # @classmethod
    # def deserialise(self, base64_string):
    #     '''
    #     Returns a bit_array version of base64_string.
    #     '''
    #     return bitarray.util.base2ba(64, base64_string)

    # @classmethod
    # def deserialise2BloomFilter(self, base64_string):
    #     '''
    #     Returns a bloomfilter version of base64_string.
    #     '''
    #     return bitarray.util.base2ba(64, base64_string)
    
    def pprint(self):
        bitarray.util.pprint(self.bit_array)



# Threading
import threading

server = None
client = None

# Variable to hold shares along with hash of EphID



# Task 1: Generate a 16-Byte Ephemeral ID (EphID) after every 1 minute.
ecdh = None
def genEphID():
    '''
    Generates a 16-Byte Ephemeral ID
    Returns ephID
    '''
    global ecdh
    
    ecdh = ECDH(curve=SECP128r1)
    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()

    ephID = public_key.to_string('compressed')[1:]
    print(f"public key: {public_key.to_string('compressed')}")
    print(f"Ephemeral ID: {ephID}")
    print(f"Number of Bytes: {len(ephID)}")
    
    return ephID

ephID = None
secret = None
# Test
def task1():
    global ephID
    ephID = genEphID()

    print("********** Task 1: Show Generation of EphID **********")
    print(f"EphID: {ephID}")

# Task 2: Prepare n shares of the EphID by using k-out-of-n Shamir Secret Sharing mechanism. 
# For this implementation, we use the values of k and n to be 3 and 6 respectively.
def genShares(ephID):
    '''
    Prepares 6 chunks of an ephemeral ID (ephID)
    Returns list of 6 chunks
    '''
    shares = Shamir.split(3, 6, ephID)
    return shares

shares = None
# Test
def task2():
    global shares
    shares = genShares(ephID)

    print("********** Task 2: Show 6 Shares Generated **********")
    print(f"Shares: {shares}")    


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
        share = (ephID_shares[i][0], binascii.hexlify(ephID_shares[i][1]), hash_ephID)
        share_bytes = str.encode(str(share))

        print("********** Task 3A: Show Sending of Shares at Rate of 1 per 10 seconds over UDP **********")
        print(f"Sending share: {share}")

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
    #         "shares": [share1, share2, share3, etc.],
    #         "ephID": None
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
                "shares": [rec_share],
                "ephID": None
            }
        )

def add_eph_id_to_shares(rec_hash, rec_ephID):
    '''
    Adds ephID to global shares variable
    After ephID is reconstructed
    '''
    global shares

    for share in shares:
        if share['hash'] == rec_hash:
            share['ephID'] = rec_ephID

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
        # print("**** SHARE HEX *****")
        # print(share_hex)
        # print(hash_ephID)
        # print(type(hash_ephID))
        share_bytes = binascii.unhexlify(share_hex)
        share = (share_num, share_bytes)

        print("********** Task 3B: Show the receiving of shares **********")
        print(f"Received Share: {share}")
        
        # Add to shares
        add_share(hash_ephID, share)
        print("********** SHARES DATA STRUCTURE **********")
        print(shares)
        print("********** Task 3C: Keeping track of shares received **********")
        print(f"Num unique shares received from sender: {num_shares_received(hash_ephID)}")

        # Task 4: If have 3 shares, reconstruct ephID and check hash
        task4(hash_ephID)

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

def num_shares_received(rec_hash):
    '''
    Determines number of unique shares received for a given hash of an EphID
    '''
    global shares

    for share in shares:
        if share['hash'] == rec_hash:
            return len(share['shares'])

    return 0

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

def verify_eph_id(ephID, hash_ephID):
    '''
    Verifies ephID by reconstructing the received hash of the ephID
    Returns True if match, False otherwise
    '''
    return hashlib.sha256(ephID).hexdigest() == hash_ephID

def task4(hash_ephID=None):
    global shares

    # Task 4: 4-A Show the devices attempting re-construction of EphID 
    # when these have received at least 3 shares.
    if has_k_shares(3, hash_ephID):
        ephID = reconstruct_eph_id(hash_ephID)
        print("********** Task 4A: Show devices attempting re-construction of EphID when received at least 3 shares **********")
        print(f"Reconstructed EphID: {ephID}")

        # Task 4: 4-B Show the devices verifying the re-constructed EphID by taking the hash of re-constructed EphID and 
        # comparing with the hash value received in the advertisement.
        print("********** Task 4B: Verifying re-constructed EphID **********")
        print(f"Re-constructed EphID: {ephID}")
        print(f"Hash of re-constructed EphID: {hashlib.sha256(ephID).hexdigest()}")
        print(f"Received Hash of EphID: {hash_ephID}")
        print(f"Do they match? {hashlib.sha256(ephID).hexdigest() == hash_ephID}")

        # Store ephID in shares variable
        add_eph_id_to_shares(hash_ephID, ephID)

        # Task 5
        task5(ephID)

    
# Task 5: 5-A Show the devices computing the shared secret EncID by using Diffie- Hellman key exchange mechanism.
# Task 5: 5-B Show that the devices have arrived at the same EncID value.
encID = None

def construct_encID(ephID):
    '''
    Computes encID given an ephID
    '''
    global encID
    global ecdh

    # Need to add 2 or 3 to the beginning of EphID
    ephID = bytes([2]) + ephID

    # Compute EncID
    ecdh.load_received_public_key_bytes(ephID)
    encID = ecdh.generate_sharedsecret_bytes()

    return encID


def task5(ephID):
    '''
    Computes EncID for a given EphID
    '''

    global encID

    encID = construct_encID(ephID)

    print("********** Task 5A: Show the devices computing the shared secret EncID **********")
    print(encID)
    


daily_bloom_filter = None
# Task 6: Show that the devices are encoding EncID into the DBF and deleting the EncID.
def task6(EncID=None):
    '''
    Show that the devices are encoding EncID into the DBF and deleting the EncID.
    '''
    print("********** TASK 6 **********")
    global daily_bloom_filter
    
    # This exists to get the EncID because the generation of the EncID itself isn't a separate function. Basically, just in case.
    EncID = construct_encID(ephID)
    
    # ! May need to move this to global depending on how everything flows.
    # instantiates bloom filter with n=1000, m=800000 bits and a false positive rate of p=0.0000062, k=3 hashes
    daily_bloom_filter = BloomFilter(size=800000, items_count=1000, fp_prob=0.0000062, num_hashes=3)
    
    daily_bloom_filter.add(EncID, debug=True)
    assert EncID in daily_bloom_filter is True
    print(daily_bloom_filter)
    
    EncID = None
    if not encID:
        global encID
        encID = None

# Task 7: 7-A Show that the devices are encoding multiple EncIDs into the same DBF and show the state of the DBF after each addition.
# Task 7: 7-B Show that a new DBF gets created for the devices after every 10 minutes. A device can only store maximum of 6 DBFs.
DBF_list = []
def task7():
    '''
    Show that the devices are encoding multiple EncIDs into the same DBF and show the state of the DBF after each addition.
    Show that a new DBF gets created for the devices after every 10 minutes. A device can only store maximum of 6 DBFs.
    '''
    # start = time.time()
    task6()
    print(daily_bloom_filter)
    # This should cover 7-A
    while True:
        EncID_list = []
        for i in range(10):
            EncID_list.append(task5(genEphID))
            daily_bloom_filter.add(EncID_list[i], debug=True)

        # This should cover 7-B
        # time.sleep(60 * 10)
        time.sleep(6 * 1)
        daily_bloom_filter = BloomFilter(size=800000, items_count=1000, fp_prob=0.0000062, num_hashes=3)
        # Maximum of 6 DBFs
        if len(DBF_list) < 6:
            DBF_list.append(daily_bloom_filter)
        else:
            DBF_list.pop(0)
            DBF_list.append(daily_bloom_filter)

# Task 8: Show that after every 60 minutes, the devices combine all the available DBFs into a single QBF.
qbf = None
def task8():
    global qbf
    while True:
        # NTS: Need more clarification.
        qbf = BloomFilter()
        for dbf in DBF_list:
            qbf.union(dbf, inplace=True)
        # time.sleep(60 * 60)
        time.sleep(6 * 1)

# Task 9: 9-A Show that the devices send the QBF to the back-end server. For extension, the back-end server is your own centralised server.
# Task 9: 9-B Show that the devices are able to receive the result of risk analysis back from the back-end server. Show the result for a successful as well as an unsuccessful match. For extension, the back-end server is your own centralised server.
def task9():
    '''
    Sends QBF to back-end server
    Receives results from back-end server
    '''
    test_qbf = base64.b64encode(b"Test QBF")

    url = 'http://ec2-3-25-246-159.ap-southeast-2.compute.amazonaws.com:9000/comp4337/qbf/query'
    params = {
        'QBF': test_qbf
    }

    print("********** Task 9A: Show the devices send the QBF to the back-end server **********")
    print("Sending the following QBF to the following URL")
    print(f"QBF: {test_qbf}")
    print(f"URL: {url}")

    response = requests.post(url=url, params=params)
    data = response.json()
    
    print("********** Task 9B: Show the devices are able to receive the result of the risk analysis **********")
    print("********** Show the result for a successful as well as unsucessful match **********")
    print(data)


# Task 10: Show that a device can combine the available DBF into a CBF and upload the CBF to the back-end server. For extension, the back-end server is your own centralised server.
def task10():
    '''
    Device can combine available DBF into CBF
    Device uploads the CBF to the backend server
    '''
    # TODO - Show that the devices can combine available DBF into CBF   
    print("********** Task 9B: Show that the devices can combine available DBF into CBF and upload the CBF into the backend server **********")
    test_cbf = base64.b64encode(b"Test CBF")

    print(f"Combined DBF's into one CBF: {test_cbf}")

    url = 'http://ec2-3-25-246-159.ap-southeast-2.compute.amazonaws.com:9000/comp4337/cbf/upload'
    params = {
        'CBF': test_cbf
    }

    print("Devices have uploaded CBF to backend server: ")
    response = requests.post(url=url, params=params)
    data = response.json()
    print(data)



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
