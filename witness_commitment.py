import json
import hashlib
import os
from serialise import serialize_transaction
from serialise import serialize_transaction_witness
mempool_folder_path = './mempool'


def calculate_wtxid_array():
    wtxids = []
    coinbase_hex = "0000000000000000000000000000000000000000000000000000000000000000"
    coinbase_bytes = bytes.fromhex(coinbase_hex)
    wtxids.append(coinbase_bytes)
    with open("valid_transactions.txt", "r") as valid_transactions_file:
        for filename in valid_transactions_file:
            filename = filename.strip()  # Remove any leading/trailing whitespaces and newlines
            file_path = os.path.join(mempool_folder_path, filename)
            try:
                with open(file_path, "r") as file:
                    json_obj = json.load(file)
                    if(json_obj["vin"][0]["prevout"]["scriptpubkey_type"]=="p2pkh"):
                        message = serialize_transaction(json_obj)
                        message_bytes = bytes.fromhex(message)
                        hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
                        # reversed_hashed_message = hashed_message[::-1]  # Reverse the bytes
                        wtxids.append(hashed_message)
                    else :
                        message = serialize_transaction_witness(json_obj)
                        message_bytes = bytes.fromhex(message)
                        hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
                        # reversed_hashed_message = hashed_message[::-1]  # Reverse the bytes
                        wtxids.append(hashed_message)
                    
            except Exception as e:
                print(f"Error occurred while processing file '{filename}': {e}")
    return wtxids

def calc_merkle_root():
    txids = calculate_wtxid_array()
    
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
    ans = txids[0].hex() + "0000000000000000000000000000000000000000000000000000000000000000"
    ans_bytes = bytes.fromhex(ans)
    ans_hash = hashlib.sha256(hashlib.sha256(ans_bytes).digest()).digest()
    return ans_hash.hex()



print("Witness commitment: ", calc_merkle_root())

