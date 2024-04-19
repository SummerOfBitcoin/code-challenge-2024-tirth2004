import hashlib
import json
from verify import opchecksig


#Testing using this file
file_path = "mempool/12e8b2619914eab19db3056ab65eb6f25656d2e607062efcf70c05df1a078eac.json"
with open(file_path, "r") as file:
    json_data = json.load(file)


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
    # print("Hex sig p2wkh: ", hex_sig)
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

def serialise_starting(json_obj):
    pre_image = ""
    version = json_obj["version"]
    version_hex = format(version, '08x')
    version_hex_le = ''.join(reversed([version_hex[i:i+2] for i in range(0, len(version_hex), 2)]))
    pre_image += version_hex_le
    txid_vout = ""
    for input_tx in json_obj["vin"]:
        txid_hex = input_tx["txid"]
        txid_le = ''.join(reversed([txid_hex[i:i+2] for i in range(0, len(txid_hex), 2)]))
        txid_vout += txid_le

        vout_hex = format(input_tx["vout"], '08x')
        vout_hex_le = ''.join(reversed([vout_hex[i:i+2] for i in range(0, len(vout_hex), 2)]))
        txid_vout += vout_hex_le
    
    txid_vout_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(txid_vout)).digest()).digest()
    pre_image+=txid_vout_hash.hex()
    sequences = ""
    for input_tx in json_obj["vin"]:
        sequence = input_tx["sequence"]
        sequence_hex = format(sequence, '08x')  # Convert sequence to hexadecimal
        sequence_hex_le = ''.join(reversed([sequence_hex[i:i+2] for i in range(0, len(sequence_hex), 2)]))
        sequences += sequence_hex_le
    sequences_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(sequences)).digest()).digest()
    pre_image+=sequences_hash.hex()
    return pre_image

def serialise_output(json_obj):
    end = ""
    for output_tx in json_obj["vout"]:
        sequence = output_tx["value"]
        sequence_hex = format(sequence, '016x')  # Convert sequence to hexadecimal
        sequence_hex_le = ''.join(reversed([sequence_hex[i:i+2] for i in range(0, len(sequence_hex), 2)]))
        end += sequence_hex_le

        script_sig_size = len(output_tx["scriptpubkey"]) // 2  # Divide by 2 to get bytes from hex string
        # print(len(input_tx["scriptsig"])//2)
        end += encode(script_sig_size)
        end+=output_tx["scriptpubkey"]
    end_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(end)).digest()).digest()
    # print("Ending serialised transaction: ", end_hash.hex())
    return end_hash.hex()
    

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


def verify_p2wpkh(json_obj):
    pre_image = serialise_starting(json_obj)
    post_image = serialise_output(json_obj)
    for input_tx in json_obj["vin"]:
        msg = pre_image
        txid_hex = input_tx["txid"]
        txid_le = ''.join(reversed([txid_hex[i:i+2] for i in range(0, len(txid_hex), 2)]))
        msg += txid_le

        vout_hex = format(input_tx["vout"], '08x')
        vout_hex_le = ''.join(reversed([vout_hex[i:i+2] for i in range(0, len(vout_hex), 2)]))
        msg += vout_hex_le
        # print("Vout: ", vout_hex_le)

        pubkeyhash = input_tx["prevout"]["scriptpubkey"][4:]
        
        msg+="1976a914"
        msg+=pubkeyhash
        msg+="88ac"

        amount = input_tx["prevout"]["value"]
        amount_hex = format(amount, '016x')  # Convert sequence to hexadecimal
        amount_hex_le = ''.join(reversed([amount_hex[i:i+2] for i in range(0, len(amount_hex), 2)]))
        msg += amount_hex_le
        

        sequence = input_tx["sequence"]
        sequence_hex = format(sequence, '08x')  # Convert sequence to hexadecimal
        sequence_hex_le = ''.join(reversed([sequence_hex[i:i+2] for i in range(0, len(sequence_hex), 2)]))
       
        msg += sequence_hex_le
        msg+=post_image
        locktime = json_obj["locktime"]
        locktime_hex = format(locktime, '08x')  # Convert locktime to hexadecimal
        locktime_hex_le = ''.join(reversed([locktime_hex[i:i+2] for i in range(0, len(locktime_hex), 2)]))
        msg += locktime_hex_le
        msg+="01000000"
        msgHash =  hashlib.sha256(hashlib.sha256(bytes.fromhex(msg)).digest()).digest()
        # print("Message hash: ", msg)
        msgHash_int = int.from_bytes(msgHash, byteorder='big')
        public_key = input_tx["witness"][1]
        signature_temp = input_tx["witness"][0]
        pubkey_bytes = bytes.fromhex(public_key)

        if(pubkeyhash != hash160(pubkey_bytes).hex()): return False
        
        sigscript_bytes = bytes.fromhex(signature_temp)
        dissected_sig = dissect_signature(sigscript_bytes.hex())
        r_component = bytes.fromhex(dissected_sig[0])
        s_component = bytes.fromhex(dissected_sig[1])
        r_component_int = int.from_bytes(r_component, byteorder='big')
        s_component_int = int.from_bytes(s_component, byteorder='big')
        
        pubkey_dec = decompress_pubkey(pubkey_bytes)
        pubkey_int_x = int.from_bytes(pubkey_dec[0], byteorder='big')
        pubkey_int_y = int.from_bytes(pubkey_dec[1], byteorder='big')
        ret = opchecksig((pubkey_int_x, pubkey_int_y),(r_component_int, s_component_int), msgHash_int )
        if(ret == False): return False
    return True



# print("Verified?: ", verify_p2pkh(json_data))

