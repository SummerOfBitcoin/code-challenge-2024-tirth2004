import json

"""Serialise transactions to get txids"""

def serialize_transaction(json_obj):
    version = json_obj["version"]
    version_hex = format(version, '08x')
    version_hex_le = ''.join(reversed([version_hex[i:i+2] for i in range(0, len(version_hex), 2)]))
    serialized_tx = version_hex_le

    # Number of inputs (variable-length integer)
    num_inputs = len(json_obj["vin"])
    serialized_tx +=encode(num_inputs)

    #Processing each input
    for input_tx in json_obj["vin"]:
        txid_hex = input_tx["txid"]
        txid_le = ''.join(reversed([txid_hex[i:i+2] for i in range(0, len(txid_hex), 2)]))
        serialized_tx += txid_le

        vout_hex = format(input_tx["vout"], '08x')
        vout_hex_le = ''.join(reversed([vout_hex[i:i+2] for i in range(0, len(vout_hex), 2)]))
        serialized_tx += vout_hex_le

        script_sig_size = len(input_tx["scriptsig"]) // 2  # Divide by 2 to get bytes from hex string
        # print(len(input_tx["scriptsig"])//2)
        serialized_tx += encode(script_sig_size)
        serialized_tx+=input_tx["scriptsig"]

        sequence = input_tx["sequence"]
        sequence_hex = format(sequence, '08x')  # Convert sequence to hexadecimal
        sequence_hex_le = ''.join(reversed([sequence_hex[i:i+2] for i in range(0, len(sequence_hex), 2)]))
        serialized_tx += sequence_hex_le

    num_inputs = len(json_obj["vout"])
    serialized_tx +=encode(num_inputs)

    #Now let us finally process each output
    for output_tx in json_obj["vout"]:
        sequence = output_tx["value"]
        sequence_hex = format(sequence, '016x')  # Convert sequence to hexadecimal
        sequence_hex_le = ''.join(reversed([sequence_hex[i:i+2] for i in range(0, len(sequence_hex), 2)]))
        serialized_tx += sequence_hex_le

        script_sig_size = len(output_tx["scriptpubkey"]) // 2  # Divide by 2 to get bytes from hex string
        # print(len(input_tx["scriptsig"])//2)
        serialized_tx += encode(script_sig_size)
        serialized_tx+=output_tx["scriptpubkey"]
    
    
    locktime = json_obj["locktime"]
    locktime_hex = format(locktime, '08x')  # Convert locktime to hexadecimal
    locktime_hex_le = ''.join(reversed([locktime_hex[i:i+2] for i in range(0, len(locktime_hex), 2)]))
    serialized_tx += locktime_hex_le
    return serialized_tx

"""Serialise transactions to get wtxids"""

def serialize_transaction_witness(json_obj):
    version = json_obj["version"]
    version_hex = format(version, '08x')
    version_hex_le = ''.join(reversed([version_hex[i:i+2] for i in range(0, len(version_hex), 2)]))
    serialized_tx = version_hex_le
    serialized_tx += "0001"
    # Number of inputs (variable-length integer)
    num_inputs = len(json_obj["vin"])
    serialized_tx +=encode(num_inputs)

    #Processing each input
    for input_tx in json_obj["vin"]:
        txid_hex = input_tx["txid"]
        txid_le = ''.join(reversed([txid_hex[i:i+2] for i in range(0, len(txid_hex), 2)]))
        serialized_tx += txid_le

        vout_hex = format(input_tx["vout"], '08x')
        vout_hex_le = ''.join(reversed([vout_hex[i:i+2] for i in range(0, len(vout_hex), 2)]))
        serialized_tx += vout_hex_le

        script_sig_size = len(input_tx["scriptsig"]) // 2  # Divide by 2 to get bytes from hex string
        # print(len(input_tx["scriptsig"])//2)
        serialized_tx += encode(script_sig_size)
        serialized_tx+=input_tx["scriptsig"]

        sequence = input_tx["sequence"]
        sequence_hex = format(sequence, '08x')  # Convert sequence to hexadecimal
        sequence_hex_le = ''.join(reversed([sequence_hex[i:i+2] for i in range(0, len(sequence_hex), 2)]))
        serialized_tx += sequence_hex_le

    num_inputs = len(json_obj["vout"])
    serialized_tx +=encode(num_inputs)

    #Now let us finally process each output
    for output_tx in json_obj["vout"]:
        sequence = output_tx["value"]
        sequence_hex = format(sequence, '016x')  # Convert sequence to hexadecimal
        sequence_hex_le = ''.join(reversed([sequence_hex[i:i+2] for i in range(0, len(sequence_hex), 2)]))
        serialized_tx += sequence_hex_le

        script_sig_size = len(output_tx["scriptpubkey"]) // 2  # Divide by 2 to get bytes from hex string
        # print(len(input_tx["scriptsig"])//2)
        serialized_tx += encode(script_sig_size)
        serialized_tx+=output_tx["scriptpubkey"]
    
    temp = ""
    for input_tx in json_obj["vin"]:
        temp+="02"
        signature = input_tx["witness"][0]
        script_sig_size = len(signature)//2  # Divide by 2 to get bytes from hex string
        # print(len(input_tx["scriptsig"])//2)
        temp += encode(script_sig_size)
        temp+=input_tx["witness"][0]
        pubkey = input_tx["witness"][1]
        pubkey_size = len(pubkey)//2  # Divide by 2 to get bytes from hex string
        # print(len(input_tx["scriptsig"])//2)
        temp += encode(pubkey_size)
        temp+=input_tx["witness"][1]
        
    serialized_tx+=temp


    locktime = json_obj["locktime"]
    locktime_hex = format(locktime, '08x')  # Convert locktime to hexadecimal
    locktime_hex_le = ''.join(reversed([locktime_hex[i:i+2] for i in range(0, len(locktime_hex), 2)]))
    serialized_tx += locktime_hex_le
    return serialized_tx


#Convert the integer values to compact form
def encode(i):
    if i <= 252:
        compactsize = i.to_bytes(1, byteorder='little').hex()
    elif i <= 65535:
        compactsize = 'fd' + i.to_bytes(2, byteorder='little').hex()
    elif i <= 4294967295:
        compactsize = 'fe' + i.to_bytes(4, byteorder='little').hex()
    else:
        compactsize = 'ff' + i.to_bytes(8, byteorder='little').hex()

    return compactsize



file_path = "mempool/0aac26114009989817ba396fbfcdb0ab2f2a51a30df5d134d3294aacb27e8f69.json"
with open(file_path, "r") as file:
    json_data = json.load(file)


# print("Serialized Transaction:", serialize_transaction_witness(json_data))
# message_bytes = bytes.fromhex(serialize_transaction_witness(json_data))
# hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()[::-1]

# print("Hash: ", hashed_message.hex())
# print(serialize_transaction_witness(json_data))

# hex_string = "e624d51009596f6a296daf3090894d19d084add7c4ed83d48809d824bb5bf658"
# reversed_hex_string = ''.join(reversed([hex_string[i:i+2] for i in range(0, len(hex_string), 2)]))
# print("Reversed Hexadecimal String:", reversed_hex_string)
