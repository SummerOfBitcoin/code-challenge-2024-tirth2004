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

 
def inverse(a, m):
    m_orig = m
    if(a < 0):
      a = a%m
    prevy, y = 0, 1
    while(a > 1):
       q = m//a
       y, prevy = prevy-q*y, y
       a, m = m%a, a
    return y%m_orig

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
  binary = bin(k)[2:]

  # double and add algorithm for fast multiplication
  for char in binary[1:]:
    current = double(current)

    # 1 = double and add
    if (char == "1"):
       current = add(current, point) 

  # return the final point
  return current

def opchecksig(pkt, st, hash):
    point1 = multiply(inverse(st[1], n) * hash, G)
    point2 = multiply((inverse(st[1], n) * st[0]), pkt)
    point3 = add(point1, point2)

    return point3[0] == st[0]

# msg = "020000000125c9f7c56ab4b9c358cb159175de542b41c7d38bf862a045fa5da51979e37ffb010000001976a914286eb663201959fb12eff504329080e4c56ae28788acffffffff0254e80500000000001976a9141ef7874d338d24ecf6577e6eadeeee6cd579c67188acc8910000000000001976a9142e391b6c47778d35586b1f4154cbc6b06dc9840c88ac0000000001000000"
# signature = "30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01"
# pubkey = "02c371793f2e19d1652408efef67704a2e9953a43a9dd54360d56fc93277a5667d"
# message_bytes = bytes.fromhex(msg)
# hash_once = hashlib.sha256(hashlib.sha256(message_bytes).digest()).digest()
# hash_int_once = int.from_bytes(hash_once, byteorder="big")

# r = ""
# rl = int(signature[6:8], 16)
# for i in range(8, 8+rl*2):
#     r += signature[i]
# s = ""
# sl = int(signature[8+rl*2+2 : 8+rl*2+4], 16)
# for i in range(8+rl*2+4, 8+rl*2+4+sl*2):
#     s += signature[i]

# prefix = pubkey[0:2]
# x = int(pubkey[2:], 16)
# p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# y_sq = (pow(x, 3, p) + 7) % p
# y = pow(y_sq, (p+1)//4, p)
# if y % 2 != int(prefix) % 2:
#     y = p - y


# ri = int(r, 16)
# si = int(s, 16)

# print(len("4e9e3109b86c8d6649040dfab9b2a9c9a6cc80bbe867a33c14b75392576daa"))
# print(len("08c318d3c494e29bd0dcc49aa2b32c32f004115833eacc7d70f8591352ddea2a"))

# print(ri, si)

# st = (ri, si)
# pkt = (x, y)

# msghashe=103318048148376957923607078689899464500752411597387986125144636642406244063093
# ste = (108607064596551879580190606910245687803607295064141551927605737287325610911759, 73791001770378044883749956175832052998232581925633570497458784569540878807131)
# pkte = (33886286099813419182054595252042348742146950914608322024530631065951421850289, 9529752953487881233694078263953407116222499632359298014255097182349749987176)
# valid = opchecksig(pkt, st, hash_int_once)
# print(valid)
