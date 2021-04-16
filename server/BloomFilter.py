import bitarray
import bitarray.util
import mmh3
import math
from random import randint


# Nicked the base from https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/
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
        
        # self.items_max = items_count if items_count else self.get_items_max(size, fp_prob)
        self.items_max = items_count if items_count else 1000

        # Bit array of given size
        self.bit_array = bitarray.bitarray(size) if size else bitarray.bitarray(self.size)

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
        return self.__contains__

    def intersect(self, other_bloom_filter, inplace=False, debug=False):
        '''
        Returns intersection/bitwise AND of the current and other_bloom_filter. inplace defaults to False. Not a true inplace operation. Just replaces the internal bitarray.
        '''
        # new_bit_array = bitarray(self.size)
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
        # new_bit_array = bitarray(self.size)
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
    
    # @classmethod
    # def get_items_max(self, m, k):
    #     '''
    #     Return the maximum n that satisfies the formula
    #     n = m * k

    #     m : int
    #         size of bit array
    #     k : int
    #         probability of false positive
    #     '''
    #     n = m * k
    #     return int(n)

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
    
    # def __repr__(self):
    #     '''
    #     You shouldn't be using this. This is just to make it so that the class operates with Python's built in operators.
    #     '''
    #     return f""

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

                # if any of bit is False then,its not present
                # in filter
                # else there is probability that it exist
                return False
        return True

    @classmethod
    def serialise(self, bit_array):
        '''
        Returns a base64-serialised, string version of itself.
        '''
        for i in range(4):
            bit_array.append(0)
        return bitarray.util.ba2base(64, bit_array)
    
    def serialise(self):
        '''
        Returns a base64-serialised, string version of itself.
        '''
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
        return self.bit_array.to01()
    
    def print(self):
        print(self)
