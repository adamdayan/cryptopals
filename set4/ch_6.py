from Crypto.Hash import MD4 

from set4.ch_4 import preprocess, leftrotate, split_chunks
from set4.ch_5 import check_admin, generate_padding 
from set3.ch_3 import xor 

A = int.from_bytes(bytes([0x01, 0x23, 0x45, 0x67]), byteorder="little")
B = int.from_bytes(bytes([0x89, 0xab, 0xcd, 0xef]), byteorder="little")
C = int.from_bytes(bytes([0xfe, 0xdc, 0xba, 0x98]), byteorder="little")
D = int.from_bytes(bytes([0x76, 0x54, 0x32, 0x10]), byteorder="little")

def invert(num):
    ba = bytearray(num.to_bytes(byteorder="big", length=4))
    for i, b in enumerate(ba):
        ba[i] = 0xFF ^ b
    return int.from_bytes(ba, byteorder="big")

def f(x, y, z):
    return (x & y) | (~x & z)
 
def g(x, y, z):
    return (x & y) | (x & z) | (y & z)

def h(x, y, z):
    return x ^ y ^ z

def f_based(first, second, third, fourth, x, k, s):
    return leftrotate((first + f(second, third, fourth) + x[k]) % (2**32), s)

def g_based(first, second, third, fourth, x, k, s):
    return leftrotate((first + g(second, third, fourth) + x[k] + 0x5a827999) % (2**32), s)

def h_based(first, second, third, fourth, x, k, s):
    return leftrotate((first + h(second, third, fourth) + x[k] + 0x6ed9eba1) % (2**32), s)

def process_chunk(chunk, a, b, c, d):
    h = [a, b, c, d]
    s = [3, 7, 11, 19]
    X = [int.from_bytes(chunk[i*4:(i+1)*4], byteorder="little") for i in range(len(chunk) // 4)]
    for r in range(16):
        i = (16 - r) % 4
        k = r
        h[i] = f_based(h[i], h[(i+1)%4], h[(i+2)%4], h[(i+3)%4], X, k, s[r%4])
    s = [3, 5, 9, 13]
    for r in range(16):
        i = (16 - r) % 4
        k = 4*(r%4) + (r//4)
        h[i] = g_based(h[i], h[(i+1)%4], h[(i+2)%4], h[(i+3)%4], X, k, s[r%4])
    s = [3,9,11,15]
    k = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
    for r in range(16):
        i = (16 - r) % 4
        h[i] = h_based(h[i], h[(i+1)%4], h[(i+2)%4], h[(i+3)%4], X, k[r], s[r%4])
    h2 = [a, b, c, d] 
    for i in range(len(h)):
        h[i] = (h[i] + h2[i]) % (2**32)

    return h[0], h[1], h[2], h[3]

def hash_md4(message, start_registers = None, extension_len = 0):
    padded_message = preprocess(message, extension_len = extension_len, little_endian=True)
    chunks = split_chunks(padded_message)
    if start_registers:
        a, b, c, d = start_registers
    else:
        a, b, c, d = A, B, C, D
    for chunk in chunks:
        a, b, c, d = process_chunk(chunk, a, b, c, d)
    hashed_message = a.to_bytes(byteorder="little", length=4) + b.to_bytes(byteorder="little", length=4) + c.to_bytes(byteorder="little", length=4) + d.to_bytes(byteorder="little", length=4) 
    return hashed_message

def split_registers(hashed_message):
    registers = []
    for i in range(4):
        registers.append(int.from_bytes(hashed_message[i*4:(i+1)*4], byteorder="little"))
    return registers



if __name__=="__main__":
    message = "the quick brown fox jumps over the lazy dog".encode("utf-8")
    hashed_message = hash_md4(message)
    hash_verifier = MD4.new()
    hash_verifier.update(message)
    verified_hashed_message = hash_verifier.digest()
    assert hashed_message == verified_hashed_message, "hashes do no match! MD4 implementation incorrect. mine: {} verified: {}".format(hashed_message, verified_hashed_message)
    print("hashes match! MD4 implementation correct")
    
    key = "YELLOW SUBMARINE".encode("utf-8")
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".encode("utf-8")
    extension = ";admin=true".encode("utf-8") 
    hashed_message = hash_md4(key + message)
    start_registers = split_registers(hashed_message)
    
    for i in range(513):
        assumed_key = bytearray([64] * i)
        glue_padding = generate_padding(len(assumed_key + message), little_byteorder=True)
        forged_message = message + glue_padding + extension
        forged_mac = hash_md4(extension, start_registers, len(assumed_key + message + glue_padding))
        if hash_md4(key + forged_message) == forged_mac and check_admin(forged_message):
            print("Successfully forged MAC: {} {}".format(forged_message, forged_mac.hex()))
            break 
        elif i == 512:
            print("Failed to forge MAC")
           
