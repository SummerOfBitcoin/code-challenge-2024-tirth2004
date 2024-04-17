from pycoin.ecdsa import generator_secp256k1, verify
import hashlib, secrets

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424)
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

def sha3_256Hash(msg):
    hashBytes = hashlib.sha3_256(msg.encode("utf8")).digest()
    return int.from_bytes(hashBytes, byteorder="big")

def verifyECDSAsecp256k1(msg, signature, pubKey):
    msgHash = sha3_256Hash(msg)
    # print(msgHash)
    valid = verify(generator_secp256k1, pubKey, msgHash, signature)
    return valid

def gcdExtended(a, b):
    global x, y
 
    # Base Case
    if (a == 0):
        x = 0
        y = 1
        return b
 
    # To store results of recursive call
    gcd = gcdExtended(b % a, a)
    x1 = x
    y1 = y
 
    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1
 
    return gcd
 
 
def inverse(A, M):
    g = gcdExtended(A, M)
    res = (x % M + M) % M
    return res

def double(point):
  # slope = (3x₁² + a) / 2y₁
  slope = (((3 * (point[0] ** 2)) * inverse((2 * point[1]), p))) % p # using inverse to help with division

  # x = slope² - 2x₁
  x = (slope ** 2 - (2 * point[0])) % p

  # y = slope * (x₁ - x) - y₁
  y = (slope * (point[0] - x) - point[1]) % p

  # Return the new point
  return (x, y)

def add(point1, point2):
  # double if both points are the same
  if (point1 == point2):
    return double(point1)

  # slope = (y₁ - y₂) / (x₁ - x₂)
  slope = ((point1[1] - point2[1]) * inverse(point1[0] - point2[0], p)) % p

  # x = slope² - x₁ - x₂
  x = (slope ** 2 - point1[0] - point2[0]) % p

  # y = slope * (x₁ - x) - y₁
  y = ((slope * (point1[0] - x)) - point1[1]) % p

  # Return the new point
  return (x, y)

def multiply(k, point):
  # create a copy the initial starting point (for use in addition later on)
  current = point

  # convert integer to binary representation
  binary = str(bin(k)[2:])

  # double and add algorithm for fast multiplication
  for i in range(len(binary)):
    char = binary[i]
    current = double(current)

    # 1 = double and add
    if (char == "1"):
       current = add(current, point) 

  # return the final point
  return current

def chootverify(pkt, st, hash):
    point1 = multiply(inverse(st[1], n) * hash, G)
    point2 = multiply((inverse(st[1], n) * st[0]), pkt)
    point3 = add(point1, point2)

    return point3[0] == st[0]

msg = "02000000011938f16155220149079a2c812d9af0b9051d3256932f4967a850d77b700b9eaa010000001976a91495e3a864fb90acf50e5b37cb25cb4ae59a71fd7f88acffffffff02c8a90100000000001976a914aa44d6084595a19506ceb0c4115ed8a1a06d831588acad99eb01000000001976a914277e7e47cc38f7c2472f4141c01f358d0341f73188ac0000000001000000"
signature = "304402204e4feb4dd7ea09c42a4c7eb7db84ded799050fb9baec53cd9e2da94cd80c06bc022048069e40cf73640cb89a21e42558cb2d6d6e120f8c9dff753ee9259ee06b5fbe01"
pubkey = "0204f090935e1903a7d87e759399280a988b0efeb47d09b159c59855e9a5e51f1a"

msghash=0x603bc91fdae35b1877e6e51fdfe7db78b66f9339cd2fec2d8b9d94bd07c13598

r = ""
rl = int(signature[6:8], 16)
for i in range(8, 8+rl*2):
    r += signature[i]
s = ""
sl = int(signature[8+rl*2+2 : 8+rl*2+4], 16)
for i in range(8+rl*2+4, 8+rl*2+4+sl*2):
    s += signature[i]

prefix = pubkey[0:2]
x = int(pubkey[2:], 16)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
y_sq = (pow(x, 3, p) + 7) % p
y = pow(y_sq, (p+1)//4, p)
if y % 2 != int(prefix) % 2:
    y = p - y


ri = int(r, 16)
si = int(s, 16)

st = (ri, si)
pkt = (x, y)

valid = chootverify(pkt, st, msghash)
print(valid)