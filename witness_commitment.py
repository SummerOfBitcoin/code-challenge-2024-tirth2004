import json
import hashlib
import os
from serialise import serialize_transaction

mempool_folder_path = './mempool'


def calculate_wtxid_array(json_obj):
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
                    if(json_obj["vin"]["prevout"]["scriptpubkey_type"]=="p2pkh"):
                        message = serialize_transaction(json_obj)
                        message_bytes = bytes.fromhex(message)
                        hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
                        # reversed_hashed_message = hashed_message[::-1]  # Reverse the bytes
                        wtxids.append(hashed_message)
                    else:
                        break
            except Exception as e:
                print(f"Error occurred while processing file '{filename}': {e}")
    return txids


