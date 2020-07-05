import random
import base64
import copy
import math

from Crypto.Cipher import AES
from set2.ch_1 import padder
from set2.ch_7 import unpadder, InvalidPaddingException

def select_plaintext(path):
    f = open(path, "r")
    all_plaintexts = []
    for line in f:
       all_plaintexts.append(line)
    f.close()
    return base64.b64decode(all_plaintexts[random.randint(0, len(all_plaintexts) - 1)])

def generate_random_bytes(num_bytes):
    rand_bytes = bytes([random.randint(0, 255) for _ in range(num_bytes)])
    return rand_bytes

def encrypt(plaintext_bytearr, key):
   iv = generate_random_bytes(len(key))
   padded_plaintext_bytearr = padder(plaintext_bytearr, len(key))
   cipher = AES.new(key, AES.MODE_CBC, iv)
   ciphertext_bytearr = cipher.encrypt(padded_plaintext_bytearr)
   return ciphertext_bytearr, iv

def check_padding(ciphertext_bytearr, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext_bytearr = cipher.decrypt(bytes(ciphertext_bytearr))
    try:
        unpadder(padded_plaintext_bytearr)
    except InvalidPaddingException as e:
        return False
    return True

def attack(ciphertext_bytearr, key, iv):
    uncovered_bytes= bytearray()
    plaintext_bytearr = bytearray()
    for i in reversed(range(len(key), len(ciphertext_bytearr))): 
    #for i in reversed(range(len(ciphertext_bytearr) - 1, len(ciphertext_bytearr))): 
        relevant_ciphertext_bytearr = ciphertext_bytearr[:((i//len(key)) * len(key)) + len(key)]
        padding_num = len(key) - (i % len(key)) 
        attack_bytes = bytearray()
        if padding_num > 1:
            for j in range(padding_num - 1):
                attack_bytes.append(uncovered_bytes[j] ^ padding_num)

        for potential_byte in range(256):
            if (potential_byte == ciphertext_bytearr[i - len(key)]) and (i == (len(ciphertext_bytearr) - 1)):
                continue
            potential_attack_bytes = bytearray([potential_byte]) + attack_bytes
            corrupted_ciphertext = bytearray(copy.deepcopy(relevant_ciphertext_bytearr))
            corrupted_ciphertext[i - len(key):i - len(key) + padding_num] = potential_attack_bytes
            if check_padding(corrupted_ciphertext, key, iv):
                uncovered_bytes = bytearray([potential_byte ^ padding_num]) + uncovered_bytes
                plaintext_bytearr = bytearray([potential_byte ^ padding_num ^ ciphertext_bytearr[i - len(key)]]) + plaintext_bytearr
                break
            if potential_byte == 255:
                raise Exception("Failed to decrypt {} byte".format(i))

    return plaintext_bytearr



if __name__=="__main__":
    plaintext_bytearr = select_plaintext("set3/data_ch_1.txt")
    key = generate_random_bytes(16)
    
    ciphertext_bytearr, iv = encrypt(plaintext_bytearr, key)
    assert check_padding(ciphertext_bytearr, key, iv), "Padding invalid"

    decrypted_message = attack(ciphertext_bytearr, key, iv)
    print("decrypted message: {}".format(decrypted_message))


