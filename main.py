import os
import json
from p2pkh import verify_signature
from serialise import serialize_transaction
DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"

mempool_folder_path = './mempool'

import os
import json

#We will start with finding out how many different types of locking scripts have been use

def get_unique_scriptpubkey_types(directory):
    true_p2pkh = 0
    false_p2pkh = 0
    unique_types = set()

    with open("valid_transactions.txt", "a") as valid_transactions_file:
        count = 0
        locktimes = 0
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
                            if(data["locktime"]==0):
                                true_p2pkh+=1
                                valid_transactions_file.write(filename + "\n")
                            else :
                                false_p2pkh+=1
                        else:
                            false_p2pkh+=1          
                    except Exception as e:
                        false_p2pkh+=1
                        print("error occured: ", e)
                        print("File name ", filename)


                # Extract scriptpubkey_type values from vin array
                for vin_entry in data.get("vin", []):
                    scriptpubkey_type = vin_entry.get("prevout", {}).get("scriptpubkey_type")
                    if scriptpubkey_type:
                        unique_types.add(scriptpubkey_type)
                    else:
                        unique_types.add("Empty")

    # print("Invalid due to locktime: ", locktimes)

    print("Correct: ", true_p2pkh)
    print("False: ", false_p2pkh)
    print("files: ", count)
    return unique_types



# unique_types = get_unique_scriptpubkey_types(mempool_folder_path)
def make_block():
    with open("valid_transactions.txt", "r") as valid_transactions_file:
        with open("output.txt", "a") as output_file:
            for filename in valid_transactions_file:
                filename = filename.strip()  # Remove any leading/trailing whitespaces and newlines
                file_path = os.path.join(mempool_folder_path, filename)
                try:
                    with open(file_path, "r") as file:
                        json_obj = json.load(file)
                        serialized_tx = serialize_transaction(json_obj)
                        output_file.write(serialized_tx + "\n")
                except Exception as e:
                    print(f"Error occurred while processing file '{filename}': {e}")

make_block()



