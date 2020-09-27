import base64
import hashlib
from set3.ch_3 import xor

H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0

def preprocess(message, extension_len=0):
    padded_message = message + bytearray([128])
    diff_512 = (len(padded_message) - len(padded_message) % -64) - len(padded_message)
    if diff_512 < 8:
        k = 64 - (8 - diff_512) 
    else:
        k = diff_512 - 8 
    padded_message = padded_message + bytearray([0] * k)
    orig_message_len = (len(message) + extension_len)  * 8
    orig_message_len_64bit = bytearray(reversed([(orig_message_len >> i) & 255 for i in range(0, 64, 8)]))
    return padded_message + orig_message_len_64bit

def split_chunks(padded_message):
    return [padded_message[i:i+64] for i in range(0, len(padded_message), 64)]

def split_words(chunk):
    return [chunk[i:i+4] for i in range(0, len(chunk), 4)] 

def leftrotate(num, rotation):
    return ((num << rotation) | (num >> (32 - rotation))) & (2**32 - 1)

def compress(chunk, h0, h1, h2, h3, h4):
    words = split_words(chunk)
    for i in range(16, 80):
        first = xor(words[i-3], words[i-8])
        second = xor(first, words[i-14])
        third = xor(second, words[i-16]) 
        words.append(
            bytearray(
                leftrotate(int.from_bytes(third, byteorder="big"), 1).to_bytes(byteorder="big", length=4)
            )
        )

    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if i in range(0, 20):
            #f = (b & c) | ((~b) and d)
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif i in range(20, 40):
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i in range(40, 60):
            f = (b & c) | (b & d) | (c & d)
            k= 0x8F1BBCDC
        elif i in range(60, 80):
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (leftrotate(a, 5) + f + e + k + int.from_bytes(words[i], byteorder="big")) & (2**32 - 1)
        e = d
        d = c
        c = leftrotate(b, 30)
        b = a
        a = temp
    
    return (h0 + a) & (2**32 - 1), (h1 + b) & (2**32 - 1), (h2 + c) & (2**32 - 1), (h3 + d) & (2**32 - 1), (h4 + e) & (2**32 - 1)

 
def hash_sha1(message, is_extending=False, start_registers=None, extension_len=0):
    padded_message = preprocess(message, extension_len)
    chunks = split_chunks(padded_message)
    if is_extending:
        h0, h1, h2, h3, h4 = start_registers
    else:
        h0, h1, h2, h3, h4 = H0, H1, H2, H3, H4
    for chunk in chunks:
        h0, h1, h2, h3, h4 = compress(chunk, h0, h1, h2, h3, h4)
    hash_int = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hash_int.to_bytes(byteorder="big", length=20)

if __name__=="__main__":
    message = "the quick brown fox jumps over the lazy dog".encode("ascii")
    hashed_message = hash_sha1(message)
    hash_verifier = hashlib.sha1()
    hash_verifier.update(message)
    verified_hashed_message = hash_verifier.digest()
    assert hashed_message == verified_hashed_message, "hashes do not match! SHA1 implementation incorrect. mine: {} verified: {}".format(hashed_message, verified_hashed_message)
    print("hashes match! SHA1 implementation correct")

    key = "YELLOW SUBMARINE".encode("ascii")
    hashed_authenticated_message = hash_sha1(key + message)
    
    tampered_message = "the Quick brown fox jumps over the lazy dog".encode("ascii")
    hashed_tampered_message = hash_sha1(key + tampered_message)
    
    assert hashed_tampered_message != hashed_authenticated_message, "tampering has occured undetected! MAC has failed"
    print(hashed_authenticated_message, hashed_tampered_message)



