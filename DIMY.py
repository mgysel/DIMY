#! /usr/bin/env python3

# EphID and Shamir Secret Sharing Mechanism
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import hashlib
import base64

# Threading
import threading

from json import dumps

# UDP Programming
import socket
import time

import datetime
import binascii

from ecdsa import ECDH, SECP128r1, VerifyingKey

# bloom filter library
import bitarray
import bitarray.util
import mmh3
import math

from Crypto.Random.random import getrandbits
from random import randint

import requests

server = None
client = None
server_url = 'http://127.0.0.1:55000'




##### Bloom Filter Implementation references https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/
class BloomFilter(object):
    '''
    Class for Bloom filter, using murmur3 hash function
    '''
    # p = probability of false positive
    fb_prob = None
    # n = expected maximum that achieves p
    items_max = None
    # m = Maximum size of array
    size = None
    # k = how many times to hash
    hash_count = None
    bit_array = None

    digests = []
    true_bits = []

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
        
        # self.items_max = items_count if items_count else self.get_items_max(size, fp_prob)
        self.items_max = items_count if items_count else 1000

        # Bit array of given size
        self.bit_array = bitarray.bitarray(size) if size else bitarray.bitarray(self.size)

        # initialize all bits as 0
        self.bit_array.setall(0)
        

    def add(self, item, debug=False):
        '''
        Add an item in the filter
        '''
        self.digests = []
        for i in range(self.hash_count):

            # create digest for given item.
            # i work as seed to mmh3.hash() function
            # With different seed, digest created is different
            digest = mmh3.hash(item, i) % self.size
            self.digests.append(digest)

            # set the bit True in bit_array
            self.bit_array[digest] = True

        self.true_bits.extend(self.digests)
        
        if debug is True:
            print("[ Segment 7-A, insert EncID into DBF at positions: ", end="")
            print(*self.digests, sep=", ", end="")
            print("]")
            print("[ current DBF state after inserting new EncID: ", end="")
            # Need index.
            print(*self.true_bits, sep=", ", end="")
            print("]")
        

    def check(self, item):
        '''
        Check for existence of an item in filter
        '''
        return self.__contains__

    def intersect(self, other_bloom_filter, inplace=False, debug=False):
        '''
        Returns intersection/bitwise AND of the current and other_bloom_filter. inplace defaults to False. Not a true inplace operation. Just replaces the internal bitarray.
        '''
        new_bit_array = self.bit_array & other_bloom_filter.bit_array
        if debug:
            print(new_bit_array.__repr__)
        if inplace is True:
            self.bit_array = new_bit_array
        return new_bit_array

    def union(self, other_bloom_filter, inplace=False, debug=False):
        '''
        Returns union/bitwise OR of the current and other_bloom_filter. inplace defaults to False. Not a true inplace operation. Just replaces the internal bitarray.
        '''
        new_bit_array = self.bit_array | other_bloom_filter.bit_array
        if debug:
            print(new_bit_array.__repr__)
        if inplace is True:
            self.bit_array = new_bit_array
        return new_bit_array

    @classmethod
    def get_size(self, n, p):
        '''
        Return the size of bit array(m) to use using
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
        Return the hash function(k) to be use using
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
        return self.bit_array.to01()

    def __eq__(self, obj):
        '''
        You shouldn't be using this. This is just to make it so that the class operates with Python's built in operators.
        '''
        if isinstance(BloomFilter, obj):
            return self.bit_array == obj.bit_array
        else:
            raise ValueError(f"{obj} not a {self}")
    
    def __contains__(self, item):
        for i in range(self.hash_count):
            digest = mmh3.hash(item, i) % self.size
            if self.bit_array[digest] == False:
                return False
        return True

    @classmethod
    def serialise(self, bit_array):
        '''
        Returns a base64-serialised, string version of itself.
        '''
        if len(self.bit_array) % 6 != 0:
            for i in range(4):
                self.bit_array.append(0)
        return bitarray.util.ba2base(64, bit_array)
    
    def serialise(self):
        '''
        Returns a base64-serialised, string version of itself.
        '''
        if len(self.bit_array) % 6 != 0:
            for i in range(4):
                self.bit_array.append(0)
        return bitarray.util.ba2base(64, self.bit_array)
    
    @classmethod
    def deserialise(self, base64_string):
        '''
        Returns a bit_array version of base64_string.
        '''
        result = bitarray.util.base2ba(64, base64_string)
        result = result[:-4]
        return result

    @classmethod
    def deserialise2BloomFilter(self, base64_string):
        '''
        Returns a bloomfilter version of base64_string.
        '''
        result = bitarray.util.base2ba(64, base64_string)
        result = result[:-4]
        bf = BloomFilter()
        bf.bit_array = result
        return bf
    
    def toString(self):
        """Returns a string of 0s and 1s that represent the bitarray's contents

        Returns:
            string: string of 0s and 1s
        """
        return self.bit_array.to01()
    
    def print_index(self):
        """Used to simplify the printing of the indexes of true bits
        """
        print(*self.true_bits, sep=", ", end="")

    def get_indexes(self):
        for bit in self.true_bits:
            yield bit




############################## Task 1/2 ##############################
# Every 60 seconds, generate new EphID and associated shares

ephID = None
ecdh = None
def genEphID():
    '''
    Generates a 16 Byte ephemeral ID using ECDH
    Stores in global ephID variable
    '''
    global ecdh
    global ephID
    global hash_ephID
    
    ecdh = ECDH(curve=SECP128r1)

    ecdh.generate_private_key()
    public_key = ecdh.get_public_key()
    ephID = public_key.to_string('compressed')[1:]

hash_ephID = None
def genHashEphID():
    '''
    Generates a hash of the ephemeral ID
    Stores hash in global hash_ephID variable
    '''
    global hash_ephID

    hash_ephID = hashlib.sha256(ephID).hexdigest()

# Variable to hold shares, hash of EphID, temporarily store Ephemeral ID
send_shares = None
def genShares():
    '''
    Generates n shares of the EphID by using k-out-of-n Shamir Secret Sharing mechanism
    k = 3, n = 6
    Stores shares in global send_shares variable
    '''
    global send_shares

    send_shares = Shamir.split(3, 6, ephID)

def genEphIDHashShares():
    '''
    Generates a 16-Byte Ephemeral ID, hash of the Ephemeral ID, and Shamir Secret Shares
    Repeats every minute
    Stores in global ephID, hash_ephID, send_shares variables
    '''
    global ephID
    global hash_ephID
    global send_shares

    while (True):
        genEphID()
        genHashEphID()
        genShares()

        print("\n------------------> Segment 1 <------------------")
        print(f"generate EphID: {ephID}")
        print(f"hash value of EphID: {hash_ephID}\n")

        print("------------------> Segment 2 <------------------")
        print("[")
        for share in send_shares:
            print(f"\t{share[1]}")
        print("]")

        time.sleep(60)

# Start thread to generate ephID, hash, and shares every minute
ephID_thread = threading.Thread(target=genEphIDHashShares, args=(), name="Generates Epheremal ID from hash shares.")




############################## TASK 3 ##############################
# Send and receive shares

# Task 3A: Broadcast n shares at rate of 1 unique share per 10 seconds. 
# References UDP socket programming https://github.com/ninedraft/python-udp
def user_send():
    '''
    User broadcasts one share of the EphID every 10 seconds to another user
    '''

    # Determine shares of EphID
    global ephID
    global hash_ephID
    global send_shares

    i = 0
    while True:
        # Convert share to bytes
        share = (send_shares[i][0], binascii.hexlify(send_shares[i][1]), hash_ephID)
        share_bytes = str.encode(str(share))

        print(f"\n[ Segment 3-A, sending share: {share[1]} ]")

        # NOTE: Use for Laptop broadcasts
        server.sendto(share_bytes, ('<broadcast>', 37025))
        # NOTE: Use for Raspberry Pi broadcasts
        # server.sendto(share_bytes, ('192.168.4.255', 37025))

        # Increment to next share
        if (i == 5):
            i = 0
        else:
            i += 1

        # Send every 10 seconds
        time.sleep(10)

# Task 3-B: Receive shares broadcasted by other device
recv_shares = None
def add_share(recv_hash, recv_share):
    '''
    Adds a share (share_num, share_bytes) to the global recv_shares variable
    '''
    global recv_shares

    is_hash_in_shares = False

    for share in recv_shares:
        # Check if hash is already in shares
        if share['hash'] == recv_hash:
            is_hash_in_shares = True
            # If hash already in shares, append non-duplicate shares
            if recv_share not in share['shares']:
                share['shares'].append(recv_share)
    
    if not is_hash_in_shares:
        # If hash not in shares, create new object with this share
        recv_shares.append(
            {
                "hash": recv_hash,
                "shares": [recv_share],
                "ephID": None
            }
        )

def add_eph_id_to_shares(recv_hash, recv_ephID):
    '''
    Adds ephID to global shares variable
    After ephID is reconstructed
    '''
    global recv_shares

    for share in recv_shares:
        if share['hash'] == recv_hash:
            share['ephID'] = recv_ephID

def num_shares_received(recv_hash):
    '''
    Determines number of unique shares received for a given hash of an EphID
    '''
    global recv_shares

    for share in recv_shares:
        if share['hash'] == recv_hash:
            return len(share['shares'])

    return 0

def has_k_shares(k, recv_hash):
    '''
    Determines if the receiver has enough of rec_hash shares 
    to reconstruct the sender's EphID
    and if the EphID was not already reconstructed
    '''
    global recv_shares

    for share in recv_shares:
        if share['hash'] == recv_hash:
            if share['ephID'] is None:
                return len(share['shares']) >= k

    return False

def user_receive():
    '''
    User receives broadcast from another user
    '''
    global recv_shares
    recv_shares = []
    recv_hash_ephID = None

    while True:
        # Receive data
        data, addr = client.recvfrom(1024)

        # Convert data to (share number, share)
        data_str = data.decode()
        share_num = int(data_str.split(',')[0].replace("(", ""))
        share_hex = data_str.split(', b')[1].split(',')[0].replace(")", "").replace(" ", "").replace("'", "")
        recv_hash_ephID = data_str.split(', b')[1].split(',')[1].replace(")", "").replace(" ", "").replace("'", "")
        share_bytes = binascii.unhexlify(share_hex)
        share = (share_num, share_bytes)

        # Do not receive own share
        if (recv_hash_ephID != hash_ephID):
            
            print(f"[ Segment 3-B, received share for hash {recv_hash_ephID}: {share[1]} ]")
            
            # Add to shares
            add_share(recv_hash_ephID, share)
            print(f"[ Segment 3-C, total shares received for hash {recv_hash_ephID}: {num_shares_received(recv_hash_ephID)} ]")

            # Task 4: If have 3 shares for that hash and ephID not reconstructed for that hash then
            # reconstruct ephID and check hash
            if has_k_shares(3, recv_hash_ephID):
                reconstruct_verify_ephID(recv_hash_ephID)

def send_recv_threads():
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

    print("\n------------------> Segment 3 <------------------")
    # Create thread for user to broadcast chunks of the EphID
    message = ephID
    send_broadcast_thread = threading.Thread(target=user_send, name="Sending Thread")
    send_broadcast_thread.start()

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
    recv_broadcast_thread = threading.Thread(target=user_receive, name="Receiving Thread")
    recv_broadcast_thread.start()




############################## TASK 4 ##############################
# Reconstruct ephID and verify

# Task 4: 4-A Show the devices attempting re-construction of EphID when these have received at least 3 shares.
# Task 4: 4-B Show the devices verifying the re-constructed EphID by taking the hash of re-constructed EphID and comparing with the hash value received in the advertisement.

def reconstruct_eph_id(rec_hash):
    '''
    Reconstructs a sender's ephID from the received shares
    '''
    global recv_shares
    ephID = None

    for share in recv_shares:
        if share['hash'] == rec_hash:
            ephID = Shamir.combine(share['shares'])
    
    return ephID

def verify_eph_id(ephID, hash_ephID):
    '''
    Verifies ephID by reconstructing the received hash of the ephID
    Returns True if match, False otherwise
    '''
    return hashlib.sha256(ephID).hexdigest() == hash_ephID

def reconstruct_verify_ephID(hash_ephID=None):
    '''
    Reconstructs an ephID from atleast 3 shares
    Verifies hash of that ephID with the hash sent
    '''
    global recv_shares

    # Task 4: 4-A Show the devices attempting re-construction of EphID 
    # when these have received at least 3 shares.
    if has_k_shares(3, hash_ephID):
        ephID = reconstruct_eph_id(hash_ephID)

        print("\n------------------> Segment 4 <------------------")
        print(f"[ Segment 4-A, re-construct EphID: {ephID} ]")
        print(f"[ Segment 4-B, hash value of re-constructed EphID: {hashlib.sha256(ephID).hexdigest()} is equal to hash value of original EphID: {hash_ephID}")

        # Verify hashes equal before storing Ephemeral ID and computing Encounter ID
        if (hashlib.sha256(ephID).hexdigest() == hash_ephID):
            # Store ephID in shares variable
            add_eph_id_to_shares(hash_ephID, ephID)

            # Once we have reconstructed Ephemeral ID, compute the Encounter ID
            construct_encID(ephID)




############################## TASK 5 ##############################
# Compute EncID

# Task 5: 5-A Show the devices computing the shared secret EncID by using Diffie-Hellman key exchange mechanism.
# Task 5: 5-B Show that the devices have arrived at the same EncID value.
encID = None
def construct_encID(ephID):
    '''
    Computes encID given an ephID
    '''
    global ecdh
    global encID

    # Need to add 2 or 3 to the beginning of EphID
    ephID = bytes([2]) + ephID

    # Compute EncID
    ecdh.load_received_public_key_bytes(ephID)
    encID = ecdh.generate_sharedsecret_bytes()

    print("\n------------------> Segment 5 <------------------")
    print(f"[ generate shared secret EncID: {encID} ]")

    # Now encode EncID into a bloom filter called Daily Bloom Filter (DBF) and delete the EncID
    task6(encID)

    


############################## TASK 6 ##############################
# Encode EncID into the Daily Bloom Filter

daily_bloom_filter = None
# Task 6: Show that the devices are encoding EncID into the DBF and deleting the EncID.
def task6(EncID):
    '''
    Show that the devices are encoding EncID into the DBF and deleting the EncID.
    '''
    print("\n------------------> Segment 6 <------------------")
    global daily_bloom_filter
    
    # Add encID to DBF, delete encID
    add_encID_to_DBF()

    print("[ ======== insert into DBF (murmur3 hashing with 3 hashes) ]")
    print("Encounter ID deleted")

    print("\n------------------> Segment 7 <------------------")
    print("[ Segment 7-A, insert EncID into DBF at positions: ", end="")
    print(*daily_bloom_filter.digests, sep=", ", end="")
    print("]")
    print("[ current DBF state after inserting new EncID: ", end="")
    print(*daily_bloom_filter.true_bits, sep=", ", end="")
    print("]")



############################## TASK 7 ##############################
# Encode EncIDs into DBF, Create new DBF every 10 minutes

# Task 7: 7-A Show that the devices are encoding multiple EncIDs into the same DBF and show the state of the DBF after each addition.
# Task 7: 7-B Show that a new DBF gets created for the devices after every 10 minutes. A device can only store maximum of 6 DBFs.
DBF_list = []

def add_encID_to_DBF():
    """Adds received encounter ID to daily bloom filter and deletes the encounter ID.
    """
    global encID
    if encID:
        daily_bloom_filter.add(encID)
        # Deletes encounter ID after generated
        del encID
        encID = None

def stored_DBFs_checker():
    """Ensures the number of stored daily bloom filters doesn't exceed 6. If adding a daily bloom filter causes it to exceed 6, gets rid of oldest one thereby achieving FIFO.
    """
    global DBF_list
    if len(DBF_list) < 6:
        DBF_list.append(daily_bloom_filter)
    else:
        DBF_list.pop(0)
        DBF_list.append(daily_bloom_filter)

def erase_stored_DBFs():
    global DBF_list
    DBF_list = []

def new_DBF():
    """Creates a new daily bloom filter, adding the old one into the list of daily bloom filters if it exists.
    """
    global daily_bloom_filter
    print("\n------------------> Segment 7-B <------------------\nNew DBF created")
    if daily_bloom_filter:
        stored_DBFs_checker()
    daily_bloom_filter = BloomFilter(size=800000, items_count=1000, fp_prob=0.0000062, num_hashes=3)


def EncID_to_DBF():
    """The function that is threaded to add encounter IDs to the daily bloom filter.
    """
    while True:
        if daily_bloom_filter:
            add_encID_to_DBF()

def dbf_checker():
    '''
    The function that is threaded to add generate newdaily bloom filters. The name harks back to when it actually did check the stored daily bloom filters.
    '''
    while True:
        # New dbf every 10 minutes
        new_DBF()
        time.sleep(60 * 10)


# Task 8: Show that after every 60 minutes, the devices combine all the available DBFs into a single QBF.
qbf = None

def combine_bloom_filter(debug=False):
    """Originally used to create query bloom filters. Now used to create both query bloom filters and contact bloom filters. Combines the bloom filters that exist in the list and stores it in the global qbf.

    Args:
        debug (bool, optional): When true, prints a representation of the combined bloom filter. Defaults to False.

    Returns:
        qbf: The resultant combined bloom filter.
    """
    global qbf

    qbf = BloomFilter()

    for dbf in DBF_list:
        qbf.union(dbf, inplace=True)
        if debug:
            print(qbf.__repr__)
    return qbf

last_combine_run = datetime.datetime.now()

gen_QBFs = True
def bloom_filter_combiner():
    """The function that is threaded to periodically combine bloom filters to query bloom filters and send the query bloom filter to the backend to check for matches.
    """
    global last_combine_run

    # Combine every 60 minutes
    combine_interval = 60

    while gen_QBFs:
        time.sleep(60 * combine_interval)
        # Generate QBF after each combine_interval
        if len(DBF_list) > 0 and daily_bloom_filter and gen_QBFs:

            print("\n------------------> Segment 8 <------------------")
            last_combine_run = datetime.datetime.now()
            combine_bloom_filter()
            print(f"[ combine DBFs into a single QBF - {last_combine_run.strftime('%Y-%m-%d:%H:%M:%S')} ]")
            print(f"[ Currently have {len(DBF_list)} DBF, it's state: ", end="")
            print("{", end="")
            DBF_list[0].print_index()
            print("} ]")
            print("[ Single QBF: {", end="")
            daily_bloom_filter.print_index()
            print("} ]")
            print(f"[ NEXT QUERY TIME - {(last_combine_run + datetime.timedelta(hours=1)).strftime('%Y-%m-%d:%H:%M:%S')} ]")

            # After bloom filter combined, send to backend
            sendQBF()
            sendQBFCentralised()




############################## TASK 9 ##############################
# Send QBF to backend server

# Task 9: 9-A Show that the devices send the QBF to the back-end server. For extension, the back-end server is your own centralised server.
# Task 9: 9-B Show that the devices are able to receive the result of risk analysis back from the back-end server. Show the result for a successful as well as an unsuccessful match. For extension, the back-end server is your own centralised server.
def sendQBF():
    '''
    Sends QBF to back-end server
    Receives results from back-end server
    '''
    global qbf

    send_qbf = qbf.serialise()

    url = 'http://ec2-3-26-37-172.ap-southeast-2.compute.amazonaws.com:9000/comp4337/qbf/query'
    data = {
        'QBF': send_qbf
    }

    response = requests.post(url=url, json=data)
    data = response.json()
    
    print(f'''
    \n------------------> Segment 9 <------------------\n
    Uploading QBF to backend server...
    {data['result']}: {data['message']}
    ''')




############################## TASK 10 ##############################
# Upload CBF to server

# Task 10: Show that a device can combine the available DBF into a CBF and upload the CBF to the back-end server. For extension, the back-end server is your own centralised server.
def uploadCBF():
    '''
    Device can combine available DBF into CBF
    Device uploads the CBF to the backend server
    '''
    # Stop sending QBFs after upload CBF
    global gen_QBFs
    gen_QBFs = False

    cbf = combine_bloom_filter()
    cbf = cbf.serialise()

    url = 'http://ec2-3-26-37-172.ap-southeast-2.compute.amazonaws.com:9000/comp4337/cbf/upload'
    data = {
        'CBF': cbf
    }

    response = requests.post(url=url, json=data)
    
    print("\n------------------> Segment 10 <------------------")
    print("uploading CBF to backend server...")
    if (response.status_code == 200):
        print("Upload CBF Success")
    else:
        print("Upload CBF Failure")




############################## TASK 11 ##############################
# Send QBF/Upload CBF to centralised server

# Task 11: 11-A Show that the device is able to establish a TCP connection with the centralised server and perform Tasks 9 and 10 successfully.
# Task 11: 11-B Show the terminal for the back-end server performing the QBF-CBF matching operation for risk analysis.
def sendQBFCentralised():
    '''
    Sends QBF to centralised back-end server
    Receives results from back-end server
    '''
    global server_url
    global qbf

    send_qbf = qbf.serialise()

    # Query QBF with centralized server
    print("\n------------------> Segment 11A <------------------")
    print("Uploading QBF to centralised backend server...")
    
    url = f"{server_url}/query"
    data = {
        'QBF': send_qbf
    }
    response = requests.post(url=url, json=data)
    data = response.json()
    print(f"{data['result']}")

def uploadCBFCentralised():
    '''
    Device can combine available DBF into CBF
    Device uploads the CBF to the centralised backend server
    '''
    # Upload CBF to centralized server
    print("\n------------------> Segment 11A <------------------")
    print("uploading CBF to centralised backend server...")

    # Stop sending QBFs after upload CBF
    global gen_QBFs
    gen_QBFs = False

    url = f"{server_url}/upload"
    new_DBF()
    stored_DBFs_checker()
    test_cbf = combine_bloom_filter()
    test_cbf = test_cbf.serialise()
    data = {
        'CBF': test_cbf
    }
    response = requests.post(url=url, json=data)

    if (response.status_code == 201):
        print("Upload CBF to Centralised Server Success")
    else:
        print("Upload CBF to Centralised Server Failure")

# Thread for creating new dbfs
new_dbf_thread = threading.Thread(target=dbf_checker, name="Ensures only 6 DBFs are stored at a time.")
# Thread for combining dbfs
combine_dbfs_thread = threading.Thread(target=bloom_filter_combiner, name="Task 8: Combine multiple DBFs into a single QBF.")


if __name__ == "__main__":
    # Start ephID thread
    ephID_thread.start()

    time.sleep(1)
    
    # Start sending shares and receiving them
    send_recv_threads()

    # New dbf thread
    new_dbf_thread.start()

    time.sleep(2)
    
    # Combine DBFs thread
    combine_dbfs_thread.start()

    while (True):
        variable = input('')
        if (variable == 'uploadCBF'):
            uploadCBF()
        elif (variable == 'uploadCBFCentralised'):
            uploadCBFCentralised()