import random

from set2.ch_2 import encrypt as encrypt_cbc
from set2.ch_1 import padder, unpadder
from Crypto.Cipher import AES

def gen_random_key(key_size):
    return bytearray([random.randint(0, 255) for k in range(key_size)])

def prepender_appender(target_bytearr):
    prepend_cnt = random.randint(5, 10)
    append_cnt = random.randint(5, 10)

    target_bytearr = bytearray([random.randint(0, 255) for k in range(prepend_cnt)]) + target_bytearr
    target_bytearr = target_bytearr + bytearray([random.randint(0, 255) for k in range(append_cnt)])

    return target_bytearr

def encrypt_ecb(target_bytearr, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(target_bytearr)

def encrypt_ecb_cbc(target_bytearr, is_ecb):
    key = gen_random_key(16)
    padded_target_bytearr = padder(target_bytearr, len(key))
    if is_ecb:
        ciphertext_bytearr = encrypt_ecb(bytes(padded_target_bytearr), bytes(key))
    else:
        iv = bytearray([random.randint(0, 255) for k in range(len(key))])
        ciphertext_bytearr = encrypt_cbc(bytes(padded_target_bytearr), iv, bytes(key))

    return ciphertext_bytearr


def identify_ecb(is_ecb):
    for key_size in range(1, 32):
        target_bytearr = bytearray([33]) * 100
        target_bytearr = prepender_appender(target_bytearr)
        ciphertext_bytearr = encrypt_ecb_cbc(target_bytearr, is_ecb)
        if ciphertext_bytearr[40:45] == ciphertext_bytearr[40 + key_size:45 + key_size]:
            return True

    return False


if __name__=="__main__":
    is_ecb = random.randint(0, 1)
    print("is_ecb: ", is_ecb) 
    
    guess_is_ecb = identify_ecb(is_ecb)

    assert guess_is_ecb == is_ecb, "INCORRECT CIPHER ID"
    
    if is_ecb: 
        print("CORRECT CIPHER ID: ECB")
    else: 
        print("CORRECT CIPHER ID: CBC")
        
    
    
