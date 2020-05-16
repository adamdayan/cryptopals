import base64

from set2.ch_3 import gen_random_key 
from set2.ch_1 import padder, unpadder
from Crypto.Cipher import AES 

def encrypt(target_bytearr, append_bytearr, key):
    target_bytearr = target_bytearr + append_bytearr
    padded_target_bytearr = padder(target_bytearr, len(key))
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    
    return cipher.encrypt(bytes(padded_target_bytearr))

def find_block_size(append_bytearr, key):
    is_block_size_known = False
    byte_cnt = 2
    prev_cipher_bytearr_size = len(encrypt(bytearray([35]) * byte_cnt, append_bytearr, key))
    hit_block_partition = False
    while not is_block_size_known and byte_cnt < 128: 
        test_bytearr = bytearray([35]) * byte_cnt
        cipher_bytearr = encrypt(test_bytearr, append_bytearr, key)
        this_cipher_bytearr_size = len(cipher_bytearr)
        if this_cipher_bytearr_size != prev_cipher_bytearr_size and not hit_block_partition:
            hit_block_partition = True
            block_partition_byte_cnt = byte_cnt
        elif this_cipher_bytearr_size != prev_cipher_bytearr_size and hit_block_partition:
            block_size = byte_cnt - block_partition_byte_cnt
            is_block_size_known = True
        prev_cipher_bytearr_size = this_cipher_bytearr_size
        byte_cnt += 1

    return block_size
        
def detect_ecb(append_bytearr, key, key_size):
    target_bytearr = bytearray([35]) * 256 
    cipher_bytearr = encrypt(target_bytearr, append_bytearr, key)
    if cipher_bytearr[:10] == cipher_bytearr[key_size: key_size + 10]:
        return True

    return False

def generate_missing_byte_dict(pre_bytearr, key):
    missing_byte_dict = {}
    for missing_byte in range(256):
        cipher_bytearr = encrypt(pre_bytearr, bytearray([missing_byte]), key)
        missing_byte_dict[bytes(cipher_bytearr)] = bytearray([missing_byte])

    return missing_byte_dict

def attack_ecb(append_bytearr, key):
    block_size = find_block_size(append_bytearr, key)
    print("block size: ", block_size)
    is_ecb = detect_ecb(append_bytearr, key, block_size)
    if not is_ecb:
        print("Not ECB- invalid attack!")
        return
    
    uncovered_bytes = bytearray()
    for cnt, byte in enumerate(append_bytearr):
        num_prepend_bytes = block_size - (cnt % block_size) - 1
        prepend_bytes = bytearray([97]) * num_prepend_bytes
        test_bytes = prepend_bytes + append_bytearr
        known_bytes = prepend_bytes + uncovered_bytes
        missing_byte_dict = generate_missing_byte_dict(known_bytes[-(block_size - 1):], key)
        cipher_bytearr = encrypt(prepend_bytes, append_bytearr, key)
        
        missing_byte = missing_byte_dict[bytes(cipher_bytearr[len(known_bytes) + 1 - block_size:len(known_bytes) + 1])]
        uncovered_bytes += missing_byte

    return uncovered_bytes


if __name__=="__main__":
    
    key = gen_random_key(16)
    append_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    append_bytearr = base64.b64decode("".join(append_string.strip().split("\n")))

    uncovered_message = attack_ecb(append_bytearr, key)
    print("Uncovered message: ", uncovered_message)
