import base64
import math
import random

from set2.ch_1 import padder, unpadder
from Crypto.Cipher import AES

def encrypt(prefix_bytearr, my_bytearr, append_bytearr, key):
    target_bytearr = prefix_bytearr + my_bytearr + append_bytearr
    padded_target_bytearr = padder(target_bytearr, len(key))
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    return cipher.encrypt(bytes(padded_target_bytearr))

def find_keysize(prefix_bytearr, append_bytearr, key):
    last_ciphertext_len = len(encrypt(prefix_bytearr, bytearray(), append_bytearr, key))

    for i in range(256):
        test_input_bytearr = bytearray([97]) * i 
        test_ciphertext = encrypt(prefix_bytearr, test_input_bytearr, append_bytearr, key)
        cur_ciphertext_len = len(test_ciphertext)
        if cur_ciphertext_len != last_ciphertext_len: 
            return cur_ciphertext_len - last_ciphertext_len
        else: 
            last_ciphertext_len = cur_ciphertext_len 

    raise Exception("Could not find keysize")

def find_last_unchanged_block(this_ciphertext, last_ciphertext, keysize):
    last_block_start = 0
    for i in range(len(last_ciphertext) // keysize):
        block_start = i * keysize
        block_end = block_start + keysize 
        
        if this_ciphertext[block_start:block_end] != last_ciphertext[block_start:block_end]:
            return last_block_start
        else:
            last_block_start = block_start

    return block_start

def find_prefix_len(prefix_bytearr, append_bytearr, key, keysize):
    keysize_attack_bytes_ciphertext = encrypt(prefix_bytearr, bytearray([97]) * keysize, append_bytearr, key)
    keysize_less_1_attack_bytes_ciphertext =  encrypt(prefix_bytearr, bytearray([97]) * (keysize - 1), append_bytearr, key)
    last_unchanged_block = find_last_unchanged_block(keysize_attack_bytes_ciphertext, keysize_less_1_attack_bytes_ciphertext, keysize)
    
    for i in reversed(range(keysize)):
        test_attack_bytes = bytearray([97]) * i
        this_ciphertext = encrypt(prefix_bytearr, test_attack_bytes, append_bytearr, key)
        if keysize_attack_bytes_ciphertext[last_unchanged_block:last_unchanged_block + keysize] != this_ciphertext[last_unchanged_block:last_unchanged_block + keysize]:
            prefix_len = last_unchanged_block + (keysize - (i + 1))
            return prefix_len

    return last_unchanged_block + keysize 

def detect_ecb(prefix_bytearr, prefix_len, prefix_supplement_bytes, append_bytearr, key, keysize):
    target_bytearr = bytearray([35]) * ((keysize * 2) + prefix_supplement_bytes)
    cipher_bytearr = encrypt(prefix_bytearr, target_bytearr, append_bytearr, key)
    if cipher_bytearr[prefix_len + prefix_supplement_bytes:prefix_len + prefix_supplement_bytes + keysize] == cipher_bytearr[prefix_len + prefix_supplement_bytes + keysize:prefix_len + prefix_supplement_bytes + (keysize * 2)]:
        return True
    return False

def generate_random_bytes():
    num_bytes = random.randint(5, 128)
    random_bytes = bytearray()

    for i in range(num_bytes):
        random_bytes += bytes([random.randint(0,128)])

    return random_bytes

def generate_missing_byte_dict(prefix_bytearr, prefix_bytes_supplement, prefix_len, known_bytes, append_bytes, key, keysize):
    missing_byte_dict = {}
    prefix_supplement_bytes = prefix_bytes_supplement * bytearray([97])
    for missing_byte in range(256):
        cipher_bytearr = encrypt(prefix_bytearr, prefix_supplement_bytes + known_bytes + bytearray([missing_byte]), append_bytes, key) 
        block_of_interest = cipher_bytearr[prefix_len + prefix_bytes_supplement : prefix_len + prefix_bytes_supplement + keysize]
        missing_byte_dict[bytes(block_of_interest)] = bytearray([missing_byte])

    return missing_byte_dict

def attack_ecb(prefix_bytearr, append_bytearr, key):
    keysize = find_keysize(prefix_bytearr, append_bytearr, key)
    prefix_len = find_prefix_len(prefix_bytearr, append_bytearr, key, keysize)
    prefix_nearest_block_supplement = keysize - (prefix_len % keysize)

    if not detect_ecb(prefix_bytearr, prefix_len , prefix_nearest_block_supplement,append_bytearr, key, keysize):
        raise Exception("Not ECB - cannot decrypt!")

    uncovered_bytes = bytearray()
    for cnt, byte in enumerate(append_bytearr):
        num_attack_bytes= keysize- (cnt % keysize) - 1 + prefix_nearest_block_supplement
        attack_bytes = bytearray([97]) * num_attack_bytes
        known_bytes = attack_bytes + uncovered_bytes
        missing_byte_dict = generate_missing_byte_dict(prefix_bytearr, 
                                                       prefix_nearest_block_supplement, 
                                                       prefix_len, 
                                                       known_bytes[-(keysize - 1):],
                                                       append_bytearr,
                                                       key, 
                                                       keysize)
        cipher_bytearr = encrypt(prefix_bytearr, attack_bytes, append_bytearr, key)
        lookup_bytes = cipher_bytearr[len(known_bytes) + prefix_len + 1 - keysize: len(known_bytes) + prefix_len + 1]
        missing_byte = missing_byte_dict[bytes(lookup_bytes)]
        uncovered_bytes += missing_byte

    return uncovered_bytes


if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("utf-8")
    
    prefix_bytearr = generate_random_bytes()
    append_string= "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    append_bytearr = base64.b64decode("".join(append_string.strip().split("\n")))

    keysize = find_keysize(prefix_bytearr, append_bytearr, key)
    assert keysize == len(key), "Incorrect keysize!"

    prefix_len = find_prefix_len(prefix_bytearr, append_bytearr, key, keysize)
    assert prefix_len == len(prefix_bytearr), "Incorrect prefix length. Computed: {} Actual: {}".format(prefix_len, len(prefix_bytearr))

    
    plaintext = attack_ecb(prefix_bytearr, append_bytearr, key)
    print("Decrypted plaintext: ", plaintext)
