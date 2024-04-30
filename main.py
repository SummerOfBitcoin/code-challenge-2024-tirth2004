import os
import json
from p2pkh import verify_signature
from serialise import serialize_transaction
import hashlib
from p2wkh import verify_p2wpkh
from witness_commitment import calc_witness_commitment
from header import make_hash
DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"

mempool_folder_path = './mempool'

def verify_transactions(directory):
    true_p2pkh = 0
    false_p2pkh = 0
    true_p2wpkh = 0
    false_p2wpkh = 0
    count = 0
    with open("valid_transactions.txt", "w") as valid_transactions_file:
        for filename in os.listdir(directory):
            count+=1
            if filename.endswith(".json"):
                filepath = os.path.join(directory, filename)

                # Read the JSON file
                with open(filepath, "r") as file:
                    data = json.load(file)

                
                if(data["vin"][0]["prevout"]["scriptpubkey_type"]=="p2pkh"): 
                    try:
                        ans = verify_signature(data)
                        if(ans==True):
                            true_p2pkh+=1
                            valid_transactions_file.write(filename + "\n")   
                        else:
                            false_p2pkh+=1          
                    except Exception as e:
                        false_p2pkh+=1
                        # print("error occured: ", e)
                        # print("File name ", filename)
                elif(data["vin"][0]["prevout"]["scriptpubkey_type"]=="v0_p2wpkh"):
                    try:
                        ans = verify_p2wpkh(data)
                        if(ans==True):
                            true_p2wpkh+=1
                            valid_transactions_file.write(filename + "\n")
                        else:
                            false_p2wpkh+=1
                    except Exception as e:
                        false_p2wpkh+=1
                        # print("error occured: ", e)
                        # print("File name ", filename)
        if(count>=2741): return
    # print("Correct: ", true_p2pkh)
    # print("False: ", false_p2pkh)
    # print("Correct witness: ", true_p2wpkh)
    # print("False witness: ", false_p2wpkh)
    return



# verify_transactions(mempool_folder_path)


def calculate_txid():
    
    with open("valid_transactions.txt", "r") as valid_transactions_file:
        with open("output.txt", "a") as output_file:
            for filename in valid_transactions_file:
                
                filename = filename.strip()  # Remove any leading/trailing whitespaces and newlines
                file_path = os.path.join(mempool_folder_path, filename)
                try:
                    with open(file_path, "r") as file:
                        json_obj = json.load(file)
                        serialized_tx = serialize_transaction(json_obj)
                        message_bytes = bytes.fromhex(serialized_tx)
                        hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
                        hashed_message = hashed_message[::-1]
                        output_file.write(hashed_message.hex() + "\n")
                except Exception as e:
                    print(f"Error occurred while processing file '{filename}': {e}")
                
                

def make_coinbase():
    coinbase_start = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9ed"
    coinbase_end = "0120000000000000000000000000000000000000000000000000000000000000000000000000"
    witness_comittment = calc_witness_commitment().hex()
    return (coinbase_start+witness_comittment+coinbase_end)

def make_block():
    coinbase = make_coinbase()
    header = make_hash(coinbase)
    coinbase_txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(coinbase)).digest()).digest()[::-1].hex()
    with open("output.txt", "w") as output_file:
        output_file.write(header + "\n")
        output_file.write(coinbase + "\n")
        output_file.write(coinbase_txid + "\n")
    
    calculate_txid()









                
verify_transactions(mempool_folder_path)
make_block()



