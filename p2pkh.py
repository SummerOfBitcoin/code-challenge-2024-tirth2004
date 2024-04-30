import json
import copy
import hashlib, secrets
from serialise import serialize_transaction
from hashlib import sha256

from verify import opchecksig

def hash160(pubkey):
    # Step 1: Perform SHA256 on the pubkey
    sha256_hash = hashlib.sha256(pubkey).digest()
    
    # Step 2: Perform RIPEMD-160 on the SHA256 hash
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    return ripemd160_hash.digest()

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
def decompress_pubkey(pk):
    x = int.from_bytes(pk[1:33], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if y % 2 != pk[0] % 2:
        y = p - y
    y = y.to_bytes(32, byteorder='big')
    return  (pk[1:33], y)

def verify_s(pubKey, signature, msgHash):

    pubkey_dec = decompress_pubkey(pubKey)
    pubkey_int_x = int.from_bytes(pubkey_dec[0], byteorder='big')
    pubkey_int_y = int.from_bytes(pubkey_dec[1], byteorder='big')
    # print("Decompressed public key: ",pubkey_int_y)
    
    valid = verify(generator_secp256k1, (pubkey_int_x, pubkey_int_y), msgHash, signature)
    return valid

file_path = "mempool/0a70cacb1ac276056e57ebfb0587d2091563e098c618eebf4ed205d123a3e8c4.json"
with open(file_path, "r") as file:
    json_data = json.load(file)




    




def parse_element(hex_str, offset, element_size):
    """
    :param hex_str: string to parse the element from.
    :type hex_str: hex str
    :param offset: initial position of the object inside the hex_str.
    :type offset: int
    :param element_size: size of the element to extract.
    :type element_size: int
    :return: The extracted element from the provided string, and the updated offset after extracting it.
    :rtype tuple(str, int)
    """

    return hex_str[offset:offset+element_size], offset+element_size


def dissect_signature(hex_sig):
    """
    Extracts the r, s and ht components from a Bitcoin ECDSA signature.
    :param hex_sig: Signature in  hex format.
    :type hex_sig: hex str
    :return: r, s, t as a tuple.
    :rtype: tuple(str, str, str)
    """
    # print("Hex sig : ", hex_sig)
    offset = 0
    # Check the sig contains at least the size and sequence marker
    assert len(hex_sig) > 4, "Wrong signature format."
    sequence, offset = parse_element(hex_sig, offset, 2)
    # Check sequence marker is correct
    assert sequence == '30', "Wrong sequence marker."
    signature_length, offset = parse_element(hex_sig, offset, 2)
    # Check the length of the remaining part matches the length of the signature + the length of the hashflag (1 byte)
    assert len(hex_sig[offset:])/2 == int(signature_length, 16) + 1, "Wrong length."
    # Get r
    marker, offset = parse_element(hex_sig, offset, 2)
    assert marker == '02', "Wrong r marker."
    len_r, offset = parse_element(hex_sig, offset, 2)
    len_r_int = int(len_r, 16) * 2   # Each byte represents 2 characters
    r, offset = parse_element(hex_sig, offset, len_r_int)
    # Get s
    marker, offset = parse_element(hex_sig, offset, 2)
    assert marker == '02', "Wrong s marker."
    len_s, offset = parse_element(hex_sig, offset, 2)
    len_s_int = int(len_s, 16) * 2  # Each byte represents 2 characters
    s, offset = parse_element(hex_sig, offset, len_s_int)
    # Get ht
    ht, offset = parse_element(hex_sig, offset, 2)
    assert offset == len(hex_sig), "Wrong parsing."

    return r, s, ht


#remove the signature from each input:
def clear_scriptsig(json_obj):
    # Check if the JSON object has the "vin" field
    if "vin" in json_obj:
        # Iterate over each input
        for vin in json_obj["vin"]:
            # Clear the scriptsig field
            vin["scriptsig"] = ""
            



#We dont need any existing signatures when we are creating the message hash

def verify_signature(json_data):
    verified = True
    extra_json_data = copy.deepcopy(json_data)
    clear_scriptsig(json_data)
    for i in range(len(json_data["vin"])):
        input = json_data["vin"][i]
        # print("Input reffered: ", input)
        input["scriptsig"] = input["prevout"]["scriptpubkey"]
        # print(json.dumps(json_data, indent=4))
        s_t = serialize_transaction(json_data)
        s_t+="01000000"
        message_bytes = bytes.fromhex(s_t)
        # print(message_bytes.hex())
        hashed_message = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
        sigscript_hex = extra_json_data["vin"][i]["scriptsig"]
        
        # Decode the signature script
        sigscript_bytes = bytes.fromhex(sigscript_hex)

        # Extract the signature (first part)
        signature_length = sigscript_bytes[0]
        signature = sigscript_bytes[1:signature_length + 1]
        

        # Extract the public key (second part)
        public_key = sigscript_bytes[signature_length + 2:]
        pubkey_script = input["prevout"]["scriptpubkey"]
        pubkey_hash = pubkey_script[6:46]
        # print("Original public key: ", hash160(public_key).hex() )
        # print("Pubkey hash: ", pubkey_hash )
        if(pubkey_hash != hash160(public_key).hex()): return False
        public_key_int = int.from_bytes(public_key, byteorder='big')
        dissected_sig = dissect_signature(signature.hex())
        r_component = bytes.fromhex(dissected_sig[0])
        s_component = bytes.fromhex(dissected_sig[1])
        hash_int = int.from_bytes(hashed_message, byteorder='big' )
        # hash_int = "696969969696969969696969699"
        r_component_int = int.from_bytes(r_component, byteorder='big')
        s_component_int = int.from_bytes(s_component, byteorder='big')
        # ret = public_key.verify((r_component_int,s_component_int), hashed_message, sha256, sigdecode=sigdecode_der)
        # ret = verify_s(public_key, (r_component_int, s_component_int), hash_int) #This is the current working one
        pubkey_dec = decompress_pubkey(public_key)
        pubkey_int_x = int.from_bytes(pubkey_dec[0], byteorder='big')
        pubkey_int_y = int.from_bytes(pubkey_dec[1], byteorder='big')
        ret = opchecksig((pubkey_int_x, pubkey_int_y),(r_component_int, s_component_int), hash_int )
        # ret = verifyECDSAsecp256k1(hashed_message, public_key.hex(), (r_component.hex(), s_component.hex()))
        # print("Answer", ret)
        if(ret == False):  
            return False
        # print("Answer: ", ret)
        input["scriptsig"] = ""
        # print("Signature: ", signature.hex())
        # print("Signature R:", r_component_int)
        # print("Signature S:", s_component_int)
        # print("Public Key:", public_key)
        # print("Message hash: ", hashed_message.hex())
        # print("Script signature: ", sigscript)
        # print("Serialised transaction: ", s_t)
        
    return True
    # print("Is signature correct? ", verified)



# print(verify_signature(json_data))


