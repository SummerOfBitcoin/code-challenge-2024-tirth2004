import json
from serialise import serialize_transaction
import os
import hashlib

mempool_folder_path = './mempool'


def calculate_txid_array():
    txids = []
    coinbase_hex = "194acdc48eb2eb556b3c788a3fdf4a35c85fd9dec1dcdfc282c25965f443929b"
    coinbase_bytes = bytes.fromhex(coinbase_hex)
    txids.append(coinbase_bytes)
    with open("valid_transactions.txt", "r") as valid_transactions_file:
        for filename in valid_transactions_file:
            filename = filename.strip()  # Remove any leading/trailing whitespaces and newlines
            file_path = os.path.join(mempool_folder_path, filename)
            try:
                with open(file_path, "r") as file:
                    json_obj = json.load(file)
                    message = serialize_transaction(json_obj)
                    message_bytes = bytes.fromhex(message)
                    hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
                    # reversed_hashed_message = hashed_message[::-1]  # Reverse the bytes
                    txids.append(hashed_message)
            except Exception as e:
                print(f"Error occurred while processing file '{filename}': {e}")
    return txids



def calc_merkle_root():
    txids = calculate_txid_array()
    
    while(len(txids)!=1):
        
        txids_temp = []
        n = len(txids)
        
        i = 0
        while(i<n):
            a = txids[i]
            b = txids[i]
            if((i+1)<n):
                b= txids[i+1]
            joined_txid = a.hex() + b.hex()
            message_bytes = bytes.fromhex(joined_txid)
            hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
            txids_temp.append(hashed_message)
            i=i+2
        txids = txids_temp
    # txids[0] = txids[0][::-1]
    return txids[0]

# print("Merkle root: ",calc_merkle_root().hex()+"0000000000000000000000000000000000000000000000000000000000000000" )




            









