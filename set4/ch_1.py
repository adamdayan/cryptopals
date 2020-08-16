import base64
import random 
import math
import copy

from Crypto.Cipher import AES
from set3.ch_2 import xor


def ctr(target, key):
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    for i in range(math.ceil(len(target) / len(key))):
        ctr_block = i.to_bytes(16, "little")
        encrypted_ctr_block = cipher.encrypt(ctr_block)

        start = i * len(key)
        stop = min(start + len(key), len(target))
        result = result + xor(target[start:stop], encrypted_ctr_block)

    return result

def seek(ciphertext_bytearr, key, offset, new_text):
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(math.ceil(offset + len(new_text) / len(key))):
        ctr_block = i.to_bytes(16, "little")
        encrypted_ctr_block = cipher.encrypt(ctr_block)
        start = i * len(key)
        stop = min(start + len(key), offset + len(new_text))
        if start >= offset:
            ciphertext_bytearr[start:stop] = xor(new_text[start - offset:stop - offset], encrypted_ctr_block)

    return ciphertext_bytearr

def break_ctr(ciphertext_bytearr, key):
    attack_text = bytearray([97] * len(ciphertext_bytearr))
    original_ciphertext_bytearr = copy.copy(ciphertext_bytearr)
    attack_ciphertext = seek(ciphertext_bytearr, key, 0, attack_text)
    keystream = xor(attack_ciphertext, attack_text)
    plaintext_bytearr = xor(original_ciphertext_bytearr, keystream)
    return plaintext_bytearr
    
        

if __name__=="__main__":
    with open("set4/data_ch_1.txt", "r") as f:
        ecb_ciphertext_bytearr = base64.b64decode(f.read())
    
    ecb_key = "YELLOW SUBMARINE".encode("utf-8")
    ecb_cipher = AES.new(ecb_key, AES.MODE_ECB)
    plaintext_bytearr = ecb_cipher.decrypt(ecb_ciphertext_bytearr)
    key = bytes([random.randint(0, 255) for _ in range(16)])
    ciphertext_bytearr = ctr(plaintext_bytearr, key)

    decrypted_bytearr = break_ctr(ciphertext_bytearr, key)
    assert decrypted_bytearr == plaintext_bytearr, "Decrypted text and plaintext do not match!"
    print("decrypted text matched plaintext: {}".format(decrypted_bytearr.decode("utf-8")))

