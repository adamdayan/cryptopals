import math

from base64 import b64decode
from set1.ch_3 import xor_bytes
from set2.ch_1 import padder, unpadder
from Crypto.Cipher import AES


def split_into_blocks(target_bytearray, block_size):
    block_list = []
    for i in range(math.ceil(len(target_bytearray) / block_size)):
        block_list.append(target_bytearray[i * block_size : min((i+1) * block_size, len(target_bytearray))])

    return block_list

def encrypt_blocks(block_list, iv, key):
    pre_block = iv
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_block_list = []

    for block in block_list:
        xor_block = xor_bytes(block, pre_block)
        encrypted_block = cipher.encrypt(bytes(xor_block))
        pre_block = encrypted_block
        encrypted_block_list.append(encrypted_block)

    return encrypted_block_list


def decrypt_blocks(block_list, iv, key):
    pre_block = iv
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext_block_list = []

    for block in block_list:
        decrypted_block = cipher.decrypt(bytes(block))
        xor_block = xor_bytes(decrypted_block, pre_block)
        plaintext_block_list.append(xor_block)
        pre_block = block
    
    return plaintext_block_list

def encrypt(target_bytearray, iv, key):
    block_list = split_into_blocks(target_bytearray, len(key))
    encrypted_block_list = encrypt_blocks(block_list, iv, key) 
    return b"".join(encrypted_block_list)

def decrypt(target_bytearray, iv, key):
    block_list = split_into_blocks(target_bytearray, len(key))
    decrypted_block_list = decrypt_blocks(block_list, iv, key)
    return b"".join(decrypted_block_list)

if __name__=="__main__":
        
    plaintext = "The quick brown fox jumps over the lazy dog"
    plaintext_bytearray = plaintext.encode("utf-8")
    key = "YELLOW SUBMARINE"
    iv = bytearray(len(key))
    padded_plaintext_bytearray = padder(plaintext_bytearray, len(key))
    
    print("Plaintext: {}".format(plaintext))
    ciphertext = encrypt(padded_plaintext_bytearray, iv, key)
    print("Ciphertext: {}".format(ciphertext))

    recreated_plaintext = decrypt(ciphertext, iv, key)
    unpadded_recreated_plaintext = unpadder(recreated_plaintext)
    print("Recreated plaintext: {}".format(unpadded_recreated_plaintext))

    assert plaintext_bytearray == unpadded_recreated_plaintext, "plaintext and recreated_plaintext do not match!"
    
    """
    ## DECRYPT GIVEN TEXT FILE
    with open("set2/data_ch_2.txt", "r") as f:
        ciphertext_bytearr = b64decode("".join(f.read().strip().split("\n")))
    
    key = "YELLOW SUBMARINE"
    iv = bytearray(len(key))

    plaintext = decrypt(ciphertext_bytearr, iv, key)
    print(plaintext)
    """

   
