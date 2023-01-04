
import random
import math
import operator
import csv
import os
import hashlib
import libnum
import base64
from re import T
import sys
sys.setrecursionlimit(10000)
sys.set_int_max_str_digits(7000) 
p=32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559
# where p is a prime number on 2048 bits
g=2
 # g is a generator in Zp

def fast_pow(x,n,p): 
    if n == 0:
        return 1
    k = fast_pow(x, n//2,p)
    if n % 2 == 0:
        return (k*k)%p
    else:
        return (x * k * k)%p

###################################################################
def convert(list):
     
    # Converting integer list to string list
    s = [str(i) for i in list]
     
    # Join list items using join()
    res = int("".join(s))
     
    return(res)
 ########################################################

class AES(object):
    '''AES funtions for a single block
    '''
    # Very annoying code:  all is for an object, but no state is kept!
    # Should just be plain functions in a AES modlule.
    
    # valid key sizes
    keySize = dict(SIZE_128=16, SIZE_192=24, SIZE_256=32)

    # Rijndael S-box
    sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    # Rijndael Inverted S-box
    rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

    def getSBoxValue(self,num):
        """Retrieves a given S-Box Value"""
        return self.sbox[num]

    def getSBoxInvert(self,num):
        """Retrieves a given Inverted S-Box Value"""
        return self.rsbox[num]

    def rotate(self, word):
        """ Rijndael's key schedule rotate operation.

        Rotate a word eight bits to the left: eg, rotate(1d2c3a4f) == 2c3a4f1d
        Word is an char list of size 4 (32 bits overall).
        """
        return word[1:] + word[:1]

    # Rijndael Rcon
    Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
            0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
            0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
            0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
            0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
            0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
            0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
            0xe8, 0xcb ]

    def getRconValue(self, num):
        """Retrieves a given Rcon Value"""
        return self.Rcon[num]

    def core(self, word, iteration):
        """Key schedule core."""
        # rotate the 32-bit word 8 bits to the left
        word = self.rotate(word)
        # apply S-Box substitution on all 4 parts of the 32-bit word
        for i in range(4):
            word[i] = self.getSBoxValue(word[i])
        # XOR the output of the rcon operation with i to the first part
        # (leftmost) only
        word[0] = word[0] ^ self.getRconValue(iteration)
        return word

    def expandKey(self, key, size, expandedKeySize):
        """Rijndael's key expansion.

        Expands an 128,192,256 key into an 176,208,240 bytes key

        expandedKey is a char list of large enough size,
        key is the non-expanded key.
        """
        # current expanded keySize, in bytes
        currentSize = 0
        rconIteration = 1
        expandedKey = [0] * expandedKeySize

        # set the 16, 24, 32 bytes of the expanded key to the input key
        for j in range(size):
            expandedKey[j] = key[j]
        currentSize += size

        while currentSize < expandedKeySize:
            # assign the previous 4 bytes to the temporary value t
            t = expandedKey[currentSize-4:currentSize]

            # every 16,24,32 bytes we apply the core schedule to t
            # and increment rconIteration afterwards
            if currentSize % size == 0:
                t = self.core(t, rconIteration)
                rconIteration += 1
            # For 256-bit keys, we add an extra sbox to the calculation
            if size == self.keySize["SIZE_256"] and ((currentSize % size) == 16):
                for l in range(4): t[l] = self.getSBoxValue(t[l])

            # We XOR t with the four-byte block 16,24,32 bytes before the new
            # expanded key.  This becomes the next four bytes in the expanded
            # key.
            for m in range(4):
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ \
                        t[m]
                currentSize += 1

        return expandedKey

    def addRoundKey(self, state, roundKey):
        """Adds (XORs) the round key to the state."""
        for i in range(16):
           #state[i] ^=  roundKey[i]
           if isinstance(state[i], str):
             state[i] = operator.ixor(ord(state[i]), roundKey[i])
           else:
             state[i] = operator.ixor(int(state[i]), roundKey[i])
              
        return state

    def createRoundKey(self, expandedKey, roundKeyPointer):
        """Create a round key.
        Creates a round key from the given expanded key and the
        position within the expanded key.
        """
        roundKey = [0] * 16
        for i in range(4):
            for j in range(4):
                roundKey[j*4+i] = expandedKey[roundKeyPointer + i*4 + j]
        return roundKey

    def galois_multiplication(self, a, b):
        """Galois multiplication of 8 bit characters a and b."""
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            # keep a 8 bit
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    #
    # substitute all the values from the state with the value in the SBox
    # using the state value as index for the SBox
    #
    def subBytes(self, state, isInv):
        if isInv: getter = self.getSBoxInvert
        else: getter = self.getSBoxValue
        for i in range(16): state[i] = getter(state[i])
        return state

    # iterate over the 4 rows and call shiftRow() with that row
    def shiftRows(self, state, isInv):
        for i in range(4):
            state = self.shiftRow(state, i*4, i, isInv)
        return state

    # each iteration shifts the row to the left by 1
    def shiftRow(self, state, statePointer, nbr, isInv):
        for i in range(nbr):
            if isInv:
                state[statePointer:statePointer+4] = \
                        state[statePointer+3:statePointer+4] + \
                        state[statePointer:statePointer+3]
            else:
                state[statePointer:statePointer+4] = \
                        state[statePointer+1:statePointer+4] + \
                        state[statePointer:statePointer+1]
        return state

    # galois multiplication of the 4x4 matrix
    def mixColumns(self, state, isInv):
        # iterate over the 4 columns
        for i in range(4):
            # construct one column by slicing over the 4 rows
            column = state[i:i+16:4]
            # apply the mixColumn on one column
            column = self.mixColumn(column, isInv)
            # put the values back into the state
            state[i:i+16:4] = column

        return state

    # galois multiplication of 1 column of the 4x4 matrix
    def mixColumn(self, column, isInv):
        if isInv: mult = [14, 9, 13, 11]
        else: mult = [2, 1, 1, 3]
        cpy = list(column)
        g = self.galois_multiplication

        column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ \
                    g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
        column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ \
                    g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
        column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ \
                    g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
        column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ \
                    g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])
        return column

    # applies the 4 operations of the forward round in sequence
    def aes_round(self, state, roundKey):
        state = self.subBytes(state, False)
        state = self.shiftRows(state, False)
        state = self.mixColumns(state, False)
        state = self.addRoundKey(state, roundKey)
        return state

    # applies the 4 operations of the inverse round in sequence
    def aes_invRound(self, state, roundKey):
        state = self.shiftRows(state, True)
        state = self.subBytes(state, True)
        state = self.addRoundKey(state, roundKey)
        state = self.mixColumns(state, True)
        return state

    # Perform the initial operations, the standard round, and the final
    # operations of the forward aes, creating a round key for each round
    def aes_main(self, state, expandedKey, nbrRounds):
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        i = 1
        while i < nbrRounds:
            state = self.aes_round(state,
                                   self.createRoundKey(expandedKey, 16*i))
            i += 1
        state = self.subBytes(state, False)
        state = self.shiftRows(state, False)
        state = self.addRoundKey(state,
                                 self.createRoundKey(expandedKey, 16*nbrRounds))
        return state

    # Perform the initial operations, the standard round, and the final
    # operations of the inverse aes, creating a round key for each round
    def aes_invMain(self, state, expandedKey, nbrRounds):
        state = self.addRoundKey(state,
                                 self.createRoundKey(expandedKey, 16*nbrRounds))
        i = nbrRounds - 1
        while i > 0:
            state = self.aes_invRound(state,
                                      self.createRoundKey(expandedKey, 16*i))
            i -= 1
        state = self.shiftRows(state, True)
        state = self.subBytes(state, True)
        state = self.addRoundKey(state, self.createRoundKey(expandedKey, 0))
        return state

    # encrypts a 128 bit input block against the given key of size specified
    def encrypt(self, iput, key, size):
        output = [0] * 16
        # the number of rounds
        nbrRounds = 0
        # the 128 bit block to encode
        block = [0] * 16
        # set the number of rounds
        if size == self.keySize["SIZE_128"]: nbrRounds = 10
        elif size == self.keySize["SIZE_192"]: nbrRounds = 12
        elif size == self.keySize["SIZE_256"]: nbrRounds = 14
        else: return None

        # the expanded keySize
        expandedKeySize = 16*(nbrRounds+1)

        # Set the block values, for the block:
        # a0,0 a0,1 a0,2 a0,3
        # a1,0 a1,1 a1,2 a1,3
        # a2,0 a2,1 a2,2 a2,3
        # a3,0 a3,1 a3,2 a3,3
        # the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3
        #
        # iterate over the columns
        for i in range(4):
            # iterate over the rows
            for j in range(4):
                block[(i+(j*4))] = iput[(i*4)+j]

        # expand the key into an 176, 208, 240 bytes key
        # the expanded key
        expandedKey = self.expandKey(key, size, expandedKeySize)

        # encrypt the block using the expandedKey
        block = self.aes_main(block, expandedKey, nbrRounds)

        # unmap the block again into the output
        for k in range(4):
            # iterate over the rows
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output

    # decrypts a 128 bit input block against the given key of size specified
    def decrypt(self, iput, key, size):
        output = [0] * 16
        # the number of rounds
        nbrRounds = 0
        # the 128 bit block to decode
        block = [0] * 16
        # set the number of rounds
        if size == self.keySize["SIZE_128"]: nbrRounds = 10
        elif size == self.keySize["SIZE_192"]: nbrRounds = 12
        elif size == self.keySize["SIZE_256"]: nbrRounds = 14
        else: return None

        # the expanded keySize
        expandedKeySize = 16*(nbrRounds+1)

        # Set the block values, for the block:
        # a0,0 a0,1 a0,2 a0,3
        # a1,0 a1,1 a1,2 a1,3
        # a2,0 a2,1 a2,2 a2,3
        # a3,0 a3,1 a3,2 a3,3
        # the mapping order is a0,0 a1,0 a2,0 a3,0 a0,1 a1,1 ... a2,3 a3,3

        # iterate over the columns
        for i in range(4):
            # iterate over the rows
            for j in range(4):
                block[(i+(j*4))] = iput[(i*4)+j]
        # expand the key into an 176, 208, 240 bytes key
        expandedKey = self.expandKey(key, size, expandedKeySize)
        # decrypt the block using the expandedKey
        block = self.aes_invMain(block, expandedKey, nbrRounds)
        # unmap the block again into the output
        for k in range(4):
            # iterate over the rows
            for l in range(4):
                output[(k*4)+l] = block[(k+(l*4))]
        return output


class AESModeOfOperation(object):
    '''Handles AES with plaintext consistingof multiple blocks.
    Choice of block encoding modes:  OFT, CFB, CBC
    '''
    # Very annoying code:  all is for an object, but no state is kept!
    # Should just be plain functions in an AES_BlockMode module.
    aes = AES()

    # structure of supported modes of operation
    modeOfOperation = dict(OFB=0, CFB=1, CBC=2)

    # converts a 16 character string into a number array
    def convertString(self, string, start, end, mode):
        if end - start > 16: end = start + 16
        if mode == self.modeOfOperation["CBC"]: ar = [0] * 16
        else: ar = []

        i = start
        j = 0
        while len(ar) < end - start:
            ar.append(0)
        while i < end:
            ar[j] = ord(string[i])
            j += 1
            i += 1
        return ar

    # Mode of Operation Encryption
    # stringIn - Input String
    # mode - mode of type modeOfOperation
    # hexKey - a hex key of the bit length size
    # size - the bit length of the key
    # hexIV - the 128 bit hex Initilization Vector
    def encrypt(self, stringIn, mode, key, size, IV):
        if len(key) % size:
            return None
        if len(IV) % 16:
            return None
        # the AES input/output
        plaintext = []
        iput = [0] * 16
        output = []
        ciphertext = [0] * 16
        # the output cipher string
        cipherOut = []
        # char firstRound
        firstRound = True
        if stringIn != None:
            for j in range(int(math.ceil(float(len(stringIn))/16))):
                start = j*16
                end = j*16+16
                if  end > len(stringIn):
                    end = len(stringIn)
                plaintext = self.convertString(stringIn, start, end, mode)
                # print 'PT@%s:%s' % (j, plaintext)
                if mode == self.modeOfOperation["CFB"]:
                    if firstRound:
                        output = self.aes.encrypt(IV, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(iput, key, size)
                    for i in range(16):
                        if len(plaintext)-1 < i:
                            ciphertext[i] = 0 ^ output[i]
                        elif len(output)-1 < i:
                            ciphertext[i] = plaintext[i] ^ 0
                        elif len(plaintext)-1 < i and len(output) < i:
                            ciphertext[i] = 0 ^ 0
                        else:
                            ciphertext[i] = plaintext[i] ^ output[i]
                    for k in range(end-start):
                        cipherOut.append(ciphertext[k])
                    iput = ciphertext
                elif mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt(IV, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(iput, key, size)
                    for i in range(16):
                        if len(plaintext)-1 < i:
                            ciphertext[i] = 0 ^ output[i]
                        elif len(output)-1 < i:
                            ciphertext[i] = plaintext[i] ^ 0
                        elif len(plaintext)-1 < i and len(output) < i:
                            ciphertext[i] = 0 ^ 0
                        else:
                            ciphertext[i] = plaintext[i] ^ output[i]
                    for k in range(end-start):
                        cipherOut.append(ciphertext[k])
                    iput = output
                elif mode == self.modeOfOperation["CBC"]:
                    for i in range(16):
                        if firstRound:
                            iput[i] =  plaintext[i] ^ IV[i]
                        else:
                            iput[i] =  plaintext[i] ^ ciphertext[i]
                    # print 'IP@%s:%s' % (j, iput)
                    firstRound = False
                    ciphertext = self.aes.encrypt(iput, key, size)
                    # always 16 bytes because of the padding for CBC
                    for k in range(16):
                        cipherOut.append(ciphertext[k])
        return mode, len(stringIn), cipherOut

    # Mode of Operation Decryption
    # cipherIn - Encrypted String
    # originalsize - The unencrypted string length - required for CBC
    # mode - mode of type modeOfOperation
    # key - a number array of the bit length size
    # size - the bit length of the key
    # IV - the 128 bit number array Initilization Vector
    def decrypt(self, cipherIn, originalsize, mode, key, size, IV):
        # cipherIn = unescCtrlChars(cipherIn)
        if len(key) % size:
            return None
        if len(IV) % 16:
            return None
        # the AES input/output
        ciphertext = []
        iput = []
        output = []
        plaintext = [0] * 16
        # the output plain text character list
        chrOut = []
        # char firstRound
        firstRound = True
        if cipherIn != None:
            for j in range(int(math.ceil(float(len(cipherIn))/16))):
                start = j*16
                end = j*16+16
                if j*16+16 > len(cipherIn):
                    end = len(cipherIn)
                ciphertext = cipherIn[start:end]
                if mode == self.modeOfOperation["CFB"]:
                    if firstRound:
                        output = self.aes.encrypt(IV, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(iput, key, size)
                    for i in range(16):
                        if len(output)-1 < i:
                            plaintext[i] = 0 ^ ciphertext[i]
                        elif len(ciphertext)-1 < i:
                            plaintext[i] = output[i] ^ 0
                        elif len(output)-1 < i and len(ciphertext) < i:
                            plaintext[i] = 0 ^ 0
                        else:
                            plaintext[i] = output[i] ^ ciphertext[i]
                    for k in range(end-start):
                        chrOut.append(chr(plaintext[k]))
                    iput = ciphertext
                elif mode == self.modeOfOperation["OFB"]:
                    if firstRound:
                        output = self.aes.encrypt(IV, key, size)
                        firstRound = False
                    else:
                        output = self.aes.encrypt(iput, key, size)
                    for i in range(16):
                        if len(output)-1 < i:
                            plaintext[i] = 0 ^ ciphertext[i]
                        elif len(ciphertext)-1 < i:
                            plaintext[i] = output[i] ^ 0
                        elif len(output)-1 < i and len(ciphertext) < i:
                            plaintext[i] = 0 ^ 0
                        else:
                            plaintext[i] = output[i] ^ ciphertext[i]
                    for k in range(end-start):
                        chrOut.append(chr(plaintext[k]))
                    iput = output
                elif mode == self.modeOfOperation["CBC"]:
                    output = self.aes.decrypt(ciphertext, key, size)
                    for i in range(16):
                        if firstRound:
                             if isinstance(IV[i], str):
                                  plaintext[i] = ord(IV[i]) ^ output[i]
                             else:
                                  plaintext[i] = int(IV[i]) ^ output[i]
                            
                        else:
                             if isinstance(iput[i], str):
                               plaintext[i] = ord(iput[i]) ^ output[i]
                             else:
                                plaintext[i] = int(iput[i]) ^ output[i]
                    firstRound = False
                    if originalsize is not None and originalsize < end:
                        for k in range(originalsize-start):
                            chrOut.append(chr(plaintext[k]))
                    else:
                        for k in range(end-start):
                            chrOut.append(chr(plaintext[k]))
                    iput = ciphertext
        return "".join(chrOut)


def append_PKCS7_padding(s):
    """return s padded to a multiple of 16-bytes by PKCS7 padding"""
    numpads = 16 - (len(s)%16)
    return s + numpads*chr(numpads)

def strip_PKCS7_padding(s):
    """return s stripped of PKCS7 padding"""
    if len(s)%16 or not s:
        raise ValueError("String of len %d can't be PCKS7-padded" % len(s))
    numpads = ord(s[-1])
    if numpads > 16:
        raise ValueError("String ending with %r can't be PCKS7-padded" % s[-1])
    return s[:-numpads]

def encryptData(key, data, mode=AESModeOfOperation.modeOfOperation["CBC"]):
    """encrypt `data` using `key`

    `key` should be a string of bytes.

    returned cipher is a string of bytes prepended with the initialization
    vector.

    """
    #key = map(ord, key)
    if mode == AESModeOfOperation.modeOfOperation["CBC"]:
        data = append_PKCS7_padding(data)
    keysize = len(key)
    assert keysize in AES.keySize.values(), 'invalid key size: %s' % keysize
    # create a new iv using random data
    iv = [i for i in os.urandom(16)]
    moo = AESModeOfOperation()
    (mode, length, ciph) = moo.encrypt(data, mode, key, keysize, iv)
    # With padding, the original length does not need to be known. It's a bad
    # idea to store the original message length.
    # prepend the iv.
    return ''.join(map(chr, iv)) + ''.join(map(chr, ciph))

def decryptData(key, data, mode=AESModeOfOperation.modeOfOperation["CBC"]):
    """decrypt `data` using `key`

    `key` should be a string of bytes.

    `data` should have the initialization vector prepended as a string of
    ordinal values.
    """

    #key = map(ord, key)
    keysize = len(key)
    assert keysize in AES.keySize.values(), 'invalid key size: %s' % keysize
    # iv is first 16 bytes
    iv = data[:16]
    data = data[16:]
    moo = AESModeOfOperation()
    decr = moo.decrypt(data, None, mode, key, keysize, iv)
    if mode == AESModeOfOperation.modeOfOperation["CBC"]:
        decr = strip_PKCS7_padding(decr)
    return decr

def generateRandomKey(keysize):
    """Generates a key from random data of length `keysize`.    
    The returned key is a string of bytes.    
    """
    if keysize not in (16, 24, 32):
        emsg = 'Invalid keysize, %s. Should be one of (16, 24, 32).'
        raise ValueError; emsg % keysize
    return os.urandom(keysize)

# def testStr(cleartext, keysize=32, modeName = "CBC"):
#     '''Test with random key, choice of mode.'''
#     print('Random key test', 'Mode:', modeName)
#     print('cleartext:', cleartext)
#     key =  generateRandomKey(keysize)
#     print('Key:', [x for x in key])
#     mode = AESModeOfOperation.modeOfOperation[modeName]
#     cipher = encryptData(key, cleartext, mode)
#     print('Cipher:', [x for x in cipher])
#     decr = decryptData(key, cipher, mode)
#     print('Decrypted:', decr)


moo = AESModeOfOperation()
mode, orig_len =moo.modeOfOperation["CBC"], moo.aes.keySize["SIZE_256"]
    
###################################################################
###################################################################
####################################################################
##################################################################
###################################################################
###################################################################
####################################################################
##################################################################
###################################################################
###################################################################
####################################################################
##################################################################
#HMAC IMPLEMENTATION

def xor(x, y):
    return bytes(x[i] ^ y[i] for i in range(min(len(x), len(y))))

def hmac_sha256(key_K, data):
    if len(key_K) > 256:
        raise ValueError('The key must be <= 256 bytes in length')
    padded_K = key_K + b'\x00' * (256 - len(key_K))
    ipad = b'\x36' * 256
    opad = b'\x5c' * 256
    h_inner = hashlib.sha256(xor(padded_K, ipad))
    h_inner.update(data)
    h_outer = hashlib.sha256(xor(padded_K, opad))
    h_outer.update(h_inner.digest())
    return h_outer.digest()


#############################################################

def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode('utf-8').strip()

class SymmRatchet(object):
    def __init__(self, key):
        self.state = b'key'

    def next(self,inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        self.state,outkey= hmac_sha256( self.state, b'inp[:32]'),hmac_sha256( self.state, b'inp')
        iv=hmac_sha256( self.state, b'inp[64:]')
        iv=iv[:16]
        outkey, iv
        return outkey, iv

################################################################

#  FUNCTION ELGAMAL

def El_Gamal_Signed(message,key,p,g):
    # message = Sig_PKA_pub / key = IDA_priv
    hash_message = int.from_bytes(hashlib.sha256(str(message).encode()).digest(), byteorder='big')#calculate the hash of the message SHA-256
    #print(hash_message)
    prime=False
    while not prime:
        y = random.randrange(1, p-2)
        pgcd = math.gcd(y,p-1) # the pgcd(y,p-1) should be equal to 1
        if (pgcd == 1):
            prime=True
    signature=[] # composed of s1 and s2
    s1=fast_pow(g,y,p)
    y_1 = libnum.invmod(y,p-1)
    s2= (y_1*(hash_message - key * s1))%(p-1)
    signature.append(s1)
    signature.append(s2)
    return signature 
###############################################################
# # bob checking signature
def El_Gamal_verification(message, signature,key,p,g):
    # message is Sig_PKA_pub
    # signature are s1 and s2
    # key is IDA_pub
    hash_message = int.from_bytes(hashlib.sha256(str(message).encode()).digest(), byteorder='big')#calculate the hash of the message SHA-256
    #print(hash_message)
    s1=signature[0]
    s2=signature[1]
    a = (fast_pow(key, s1,p) * fast_pow(s1,s2,p))%p
    b = fast_pow(g,hash_message,p)
    #print(a)
    #print(b)
    if (a==b):
        print('Signature El Gamal ok!!')
    else:
        print('Failed Signature El Gamal')
###############################################################
# RC4 algo
def KSA(key): # Key-scheduling algorithm 
    S = list(range(0,256)) # the permutation array on 256 bytes
     # key is on 2048 bits/256 bytes --> like S an array on 256 bytes
    j = 0
    #print(key)
    for i in range(32): # 8 bits x 32 = 256 bit
        j= (j + (S[i] + int(key[i])))%256
        #print(j)
        # swiping the values 
        aux = S[j]
        S[j] = S[i]
        S[i] = aux
    return S


def PRGA(S,n): #Pseudo-random generation algorithm
    # S array permutation
    # n is the nb  of iteration or the size of the text to encrypt
    i=0
    j=0
    key_stream = []
    for k in range(n):
        i= (i + 1)%256
        j= (j + S[i])%256
        aux = S [j]
        S[j] = S[i]
        S[i] = aux
        temp = (S[i] + S[j])%256
        key_stream.append(S[temp])
    return key_stream

def RC4_encryption(text, key):
    text = [ord(char) for char in text]
    S = KSA(key)
    key_stream = PRGA(S, len(text)) 
    cipher_text=""
    i=0
    for char in text:
        encoded_char = char ^ key_stream[i]
        cipher_text+=str(chr(encoded_char))
        i+=1
    return cipher_text

def RC4_decyrption(cipher_text,key):
    cipher_text = [ord(char) for char in cipher_text]
    S = KSA(key)
    key_stream = PRGA(S, len(cipher_text))
    plain=""
    i=0
    for char in cipher_text:
        decoded_char = char ^ key_stream[i]
        i+=1
        plain+=str(chr(decoded_char))
    return plain
################################################################

# ...................................................................................................................
#DEFFIE HELLMAN

def DH(a,B,p): # diffie helman exchange key
    return fast_pow(B, a ,p) 

# ...................................................................................................................
###################################################################################

class Bob(object):
    def __init__(self):
       
        self.IDB_priv = random.randrange(2, p) # Private Identity key Bob 
        
        self.IDB_pub = fast_pow(g,self.IDB_priv,p)  # Public Identity key Bob 
        # 2) Pre-signed key Bob
        self.Sig_PKB_priv = random.randrange(2, p) # Private Pre-signed key Bob
        self.Sig_PKB_pub = fast_pow(g,self.Sig_PKB_priv,p) # Public Pre-signed key BOB

        # algorithm to have the signed Sig_PKB_pub by IDB_priv


        self.elgamal_signature_Bob = El_Gamal_Signed(self.Sig_PKB_pub,self.IDB_priv,p,g)

        # 3) Couple of public and private keys for Bob
        N=10
        self.OTPKB_priv = [] # list of the private keys 
        self.OTPKB_pub = [] # list of the pulic keys correspnding with thr private ones (OTPKA_priv)
        for i in range(N):
            private_bob=random.randrange(2, p)
            public_bob=fast_pow(g,private_bob,p)
            self.OTPKB_priv.append(private_bob)
            self.OTPKB_pub.append(public_bob)

        # 4) Ephemere key Bob
        self.EphB_priv=random.randrange(2, p) # Private Ephemere key BOB
        self.EphB_pub=fast_pow(g,self.EphB_priv,p) # Public Ephemere key Bob
        self.elgamal_signature_BOB = El_Gamal_Signed(self.Sig_PKB_pub,self.IDB_priv,p,g)

    def x3dhwithAlice(self):
        li=[]
        with open('Alicekeys.csv', newline='',encoding="utf-8") as csvfile:
            spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
            for row in spamreader:
                li.append(row)
        
        csvfile.close()
        Sig_PKA_pub=convert(li[7])
        IDA_pub=convert(li[3])
        OTPKA_pub_chosen=convert(li[1])
        elgamal_signature_Alice= [int(li[8][0]),int(li[8][1]) ]
        
        # perform the 4 Diffie Hellman exchanges (X3DH)
        # choose a random Ephemere key from alice
        N=10
        index= convert(li[11])
        self.OTPKB_priv_chosen = self.OTPKB_priv[index]
        El_Gamal_verification(Sig_PKA_pub,elgamal_signature_Alice,IDA_pub, p,g)
        DH1_bob = DH(self.IDB_priv,Sig_PKA_pub, p)
       
        DH2_bob = DH(self.EphB_priv,IDA_pub, p)
        
        DH3_bob = DH(self.EphB_priv, Sig_PKA_pub, p)
       
        DH4_bob = DH(self.EphB_priv,OTPKA_pub_chosen, p)
      

        self.sk = int(str(DH1_bob)+str(DH2_bob)+str(DH3_bob)+str(DH4_bob))
        s=self.sk.to_bytes(1028,'big')
        print('[Bob]\tShared key:', b64(s))

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk)
        # initialise the sending and recving chains
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, alice_public):
        self.DHratchet = self.sk
        # perform a DH ratchet rotation using Alice's public key
        dh_recv = DH(self.DHratchet, alice_public, p)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        # use Alice's public and our old private key
        # to get a new recv ratchet
        self.recv_ratchet = SymmRatchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Alice
        self.DHratchet = self.sk
        dh_send = DH(self.DHratchet,alice_public,p)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))

    def sendf(self, server, msg):
        key, iv = self.send_ratchet.next()
        mode, orig_len, cipher = moo.encrypt(msg, moo.modeOfOperation["CBC"],
            key, moo.aes.keySize["SIZE_256"], iv)
        print('[Bob]\tSending ciphertext to Alice:', cipher)
        # send ciphertext and current DH public key
        dhstr=str(self.DHratchet)
        server.recvfFromBob(cipher, dhstr)

    def recvf(self):
        li=[]
        with open('filestobob.csv', newline='',encoding="utf-8") as csvfile:
            spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
            for row in spamreader:
                li.append(row)
        
        csvfile.close()
        
        cipher=list(map(int, li[0]))
        alice_public_key= convert(li[1])

        alice_public_key=int(alice_public_key)

        # receive Alice's new public key and use it to perform a DH
        self.dh_ratchet(alice_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = moo.decrypt(cipher, orig_len, mode, key,
            moo.aes.keySize["SIZE_256"], iv)

        msg=base64.b64decode(msg)
        print('[Bob]\tDecrypted message:', msg)

    def sendm(self, server, msg):

        key, iv = self.send_ratchet.next()
        cipher = RC4_encryption(msg, key)
        cstr=str(cipher)
        dhstr=str(self.DHratchet)

        server.recvmFromBob(cipher, dhstr)

    def recvm(self):
        li=[]
        with open('messagestobob.csv', newline='',encoding="utf-8") as csvfile:
            spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
            for row in spamreader:
                li.append(row)
        
        csvfile.close()
        cipher="".join(li[0])
        alice_public_key= convert(li[1])

        alice_public_key=int(alice_public_key)
        # receive Alice's new public key and use it to perform a DH
        self.dh_ratchet(alice_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg= RC4_decyrption(cipher,key)
        print(msg)



# ...................................................................................................................
# ...................................................................................................................

class Alice(object):
    def __init__(self): 
        self.IDA_priv = random.randrange(2, p) # Private Identity key Alice
        self.IDA_pub = fast_pow(g,self.IDA_priv,p) # Public Identity key Alice 

        # 2) Pre-signed key Alice
        self.Sig_PKA_priv = random.randrange(2, p) # Private Pre-signed key Alice
        self.Sig_PKA_pub = fast_pow(g,self.Sig_PKA_priv,p)  # Public Pre-signed key Alice

        # algorithm to have the signed Sig_PKA_pub by IDA_priv


        self.elgamal_signature_Alice = El_Gamal_Signed(self.Sig_PKA_pub,self.IDA_priv,p,g)

        # 3) Couple of public and private keys for Alice
        N=10
        i=0
        self.OTPKA_priv = [] # list of the private keys 
        self.OTPKA_pub = [] # list of the pulic keys correspnding with thr private ones (OTPKA_priv)
        for i in range(N):
            private_alice=random.randrange(2, p)
            public_alice= fast_pow(g,private_alice,p)
            self.OTPKA_priv.append(private_alice)
            self.OTPKA_pub.append(public_alice)

        # 4) Ephemere key Alice
        self.EphA_priv=random.randrange(2, p) # Private Ephemere key Alice
        self.EphA_pub=fast_pow(g,self.EphA_priv,p) # Public Ephemere key Alice
    
    def x3dhwithBob(self):
        li=[]
        with open('Bobkeys.csv', newline='',encoding="utf-8") as csvfile:
            spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
            for row in spamreader:
                li.append(row)
        
        csvfile.close()
        Sig_PKB_pub=convert(li[7])
        IDB_pub=convert(li[3])
        EphB_pub=convert(li[5])
        elgamal_signature_Bob= [int(li[8][0]),int(li[8][1]) ]
        #print(elgamal_signature_Bob)
        # perform the 4 Diffie Hellman exchanges (X3DH)
        # choose a random Ephemere key from alice
        N=10
        index= convert(li[11])
        self.OTPKA_priv_chosen = self.OTPKA_priv[index] 
        # Key construction for Alice
        El_Gamal_verification(Sig_PKB_pub,elgamal_signature_Bob,IDB_pub, p,g)
        DH1_alice = DH(self.Sig_PKA_priv,IDB_pub,p)
        DH2_alice = DH(self.IDA_priv,EphB_pub, p)
        DH3_alice = DH(self.Sig_PKA_priv,EphB_pub,p)
        DH4_alice = DH(self.OTPKA_priv_chosen,EphB_pub,p)

        self.sk= int(str(DH1_alice)+str(DH2_alice)+str(DH3_alice)+str(DH4_alice))
        f=self.sk.to_bytes(1028,'big')
        print('[Alice]\tShared key:', b64(f))

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymmRatchet(self.sk)
        # initialise the sending and recving chains
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, bob_public):
        # perform a DH ratchet rotation using Bob's public key
        self.DHratchet = self.sk
        if self.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = DH(self.DHratchet,bob_public, p)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.recv_ratchet = SymmRatchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = self.sk
        dh_send = DH(self.DHratchet, bob_public,p)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))

    def sendf(self, server, msg):
        key, iv = self.send_ratchet.next()
        mode, orig_len, cipher = moo.encrypt(msg, moo.modeOfOperation["CBC"],
            key, moo.aes.keySize["SIZE_256"], iv)
        print('[Alice]\tSending ciphertext to Bob:', cipher)
        # send ciphertext and current DH public key
        dhstr=str(self.DHratchet)
        server.recvfFromAlice(cipher, dhstr)

    def recvf(self):
        li=[]
        with open('filestoalice.csv', newline='',encoding="utf-8") as csvfile:
            spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
            for row in spamreader:
                li.append(row)
        
        csvfile.close()
        cipher=list(map(int, li[0]))
        bob_public_key= convert(li[1])

        bob_public_key=int(bob_public_key)
        self.dh_ratchet(bob_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = moo.decrypt(cipher, orig_len, mode, key,
            moo.aes.keySize["SIZE_256"], iv)
        msg=base64.b64decode(msg)
        print('[Alice]\tDecrypted message:', msg)

    def sendm(self, server, msg):
        key, iv = self.send_ratchet.next()
        cipher = RC4_encryption(msg, key)
        cstr=str(cipher)
        dhstr=str(self.DHratchet)

        server.recvmFromAlice(cipher, dhstr)

    def recvm(self):
        li=[]
        with open('messagestoalice.csv', newline='',encoding="utf-8") as csvfile:
            spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
            for row in spamreader:
                li.append(row)
        
        csvfile.close()
        cipher="".join(li[0])
        bob_public_key= convert(li[1])

        bob_public_key=int(bob_public_key)
        # receive Bob's new public key and use it to perform a DH
        self.dh_ratchet(bob_public_key)
        key, iv = self.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg= RC4_decyrption(cipher,key)
        print(msg)



        
class Server(object):
    def __init__(self):
        print("Receiving keys from Alice and Bob:")
        N=10
        self.index= random.randrange(0,N)

    def RcvkeysfromAlice(self):
        #Alice key
        self.OTPKA_pub=alice.OTPKA_pub

        
        
        self.OTPKA_pub_chosen = self.OTPKA_pub[self.index]

        self.IDA_pub=alice.IDA_pub
        
        self.EphA_pub=alice.EphA_pub
        self.Sig_PKA_pub=alice.Sig_PKA_pub
        self.elgamal_signature_Alice=alice.elgamal_signature_Alice
        with open('Alicekeys.csv', 'w', newline='',encoding="utf-8") as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow("OTPKA_pub_chosen")
            spamwriter.writerow(str(self.OTPKA_pub_chosen))
            spamwriter.writerow("IDA_pub")
            spamwriter.writerow(str(self.IDA_pub))
            spamwriter.writerow("EphA_pub")
            spamwriter.writerow(str(self.EphA_pub))
            spamwriter.writerow("Sig_PKA_pub & elgamal_signature_Alice")
            spamwriter.writerow(str(self.Sig_PKA_pub))
            spamwriter.writerow(self.elgamal_signature_Alice)
            spamwriter.writerow("OTPKA_pub")
            spamwriter.writerow(self.OTPKA_pub)
            spamwriter.writerow(str(self.index))

        print("Alice's keys successfully stored!")


    def RcvkeysfromBob(self):
        self.OTPKB_pub=bob.OTPKB_pub

        self.OTPKB_pub_chosen = self.OTPKB_pub[self.index]
        self.IDB_pub=bob.IDB_pub
       
        self.EphB_pub=bob.EphB_pub
       
        self.Sig_PKB_pub=bob.Sig_PKB_pub
        self.elgamal_signature_Bob=bob.elgamal_signature_Bob

        with open('Bobkeys.csv', 'w', newline='',encoding="utf-8") as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow("OTPKB_pub_chosen")
            spamwriter.writerow(str(self.OTPKB_pub_chosen))
            spamwriter.writerow("IDB_pub")
            spamwriter.writerow(str(self.IDB_pub))
            spamwriter.writerow("EphB_pub")
            spamwriter.writerow(str(self.EphB_pub))
            spamwriter.writerow("Sig_PKB_pub & elgamal_signature_Bob")
            spamwriter.writerow(str(self.Sig_PKB_pub))
            spamwriter.writerow(self.elgamal_signature_Bob)
            spamwriter.writerow("OTPKB_pub")
            spamwriter.writerow(self.OTPKB_pub)
            spamwriter.writerow(str(self.index))

        print("Bob's keys successfully stored!")
        

    def recvmFromAlice(self, cipher, DHratchet ):
        with open('messagestobob.csv', 'w', newline='',encoding="utf-8") as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow(cipher)
            spamwriter.writerow(DHratchet)

    def recvmFromBob(self, cipher, DHratchet ):
        with open('messagestoalice.csv', 'w', newline='',encoding="utf-8") as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow(cipher)
            spamwriter.writerow(DHratchet)

    def recvfFromAlice(self, cipher, DHratchet ):
        
        with open('filestobob.csv', 'w', newline='',encoding="utf-8") as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow(cipher)
            spamwriter.writerow(DHratchet)
        
        csvfile.close()

    def recvfFromBob(self, cipher, DHratchet ):
        with open('filestoalice.csv', 'w', newline='',encoding="utf-8") as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow(cipher)
            spamwriter.writerow(DHratchet)

 # ...................................................................................................................
 # ...................................................................................................................
 # ...................................................................................................................

print("\n\n\n\n")
print("Message service: \n\n\n\n")
print("\n\n\n\n")


alice = Alice()
bob = Bob()
server=Server()
print("\n\n")
#Storing public keys in server
server.RcvkeysfromAlice()
print("\n\n")
server.RcvkeysfromBob()
print("\n\n\n\n")
# Alice performs an X3DH while Bob is offline, using his uploaded keys
alice.x3dhwithBob()

# Bob comes online and performs an X3DH using Alice's public keys
bob.x3dhwithAlice()

# Initialize their symmetric ratchets
alice.init_ratchets()
bob.init_ratchets()

# Initialise Alice's sending ratchet with Bob's public key
bob.dh_ratchet(alice.IDA_pub)
alice.dh_ratchet(bob.DHratchet)
while True:
    name=input("Are you Bob or Alice? : ")
    if name=="Alice":
        print("\n Received files:\n ")
        alice.recvf()
        print("\n Received message:\n ")
        alice.recvm()
        print("\n \n")

        type=input("Do you want to send a File or a Message? : ")
        if type=="File":
            alicefile=input("Alice send file: ")
            file = open(alicefile, 'rb')
            file_content = file.read()
            result = base64.b64encode(file_content).decode('ascii')
            alice.sendf(server, result)
        elif type=="Message":
            print("\n \n")
            a=input("Alice send message: ")
            alice.sendm(server, a)
            print("\n \n")

        

    if name=="Bob":
        print("\n Received files:\n")
        bob.recvf()
        print("\n Received message:\n ")
        bob.recvm()
        print("\n \n")
        type=input("Do you want to send a File or a Message? : ")
        if type=="File":
            bobfile=input("Bob send file: ")
            file = open(bobfile, 'rb')
            file_content = file.read()
            result = base64.b64encode(file_content).decode('ascii')
            bob.sendf(server,result)

        elif type=="Message":
            print("\n \n")
            b=input("Bob send message: ")
            bob.sendm(server, b)
            print("\n\n\n\n")

        
        




