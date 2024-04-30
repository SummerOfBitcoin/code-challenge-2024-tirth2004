import json
from merkle_root import calc_merkle_root
import time
import struct
import hashlib

DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"
PREVIOUS_HEADER  = "00000ff000000000000000000000000000000000000000000000000000000000"


def make_header(coinbase):
    header = ""
    header += "20000000"
    header+=PREVIOUS_HEADER
    header+=calc_merkle_root(coinbase).hex()
    unix_time = int(time.time())
    timestamp_hex = struct.pack('<I', unix_time).hex()
    header+=timestamp_hex
    
    header+="FFFF001F"
    return header

def make_hash(coinbase):
    while(True):
        header = make_header(coinbase)
        nonce = 0
        while(True):
            
            hash_result = hashlib.sha256(hashlib.sha256(bytes.fromhex(header+format(nonce, '08x'))).digest()).digest()
            hash_result = hash_result[::-1]

            if(hash_result.hex()<DIFFICULTY_TARGET):
                # print("Nonce used: ", format(nonce, '08x'))
                # print("Header hash: ", hash_result.hex())
                # print("Header: ", header+format(nonce, '08x'))
                # print("Header in bytes: ", bytes.fromhex(header+format(nonce, '08x')))
                # print("Header length: ",len((header+format(nonce, '08x')) ))
                return (header+format(nonce, '08x'))
            
            nonce+=1

# print("Header incomplete", make_header())
            
            


# make_hash()

        
    



