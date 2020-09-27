import hashlib
import base64
from set4.ch_4 import hash_sha1, preprocess

def generate_padding(message_len):
    padding = bytearray([128])
    diff_512 = ( (message_len + 1)- (message_len + 1)%-64) - (message_len + 1)
    if diff_512 < 8:
        k = 64 - (8 - diff_512)
    else:
        k = diff_512 - 8
    padding += bytearray([0]*k)
    orig_message_len = message_len * 8
    orig_message_len_64bit = bytearray(reversed([(orig_message_len >> i) & 255 for i in range(0, 64, 8)]))
    return padding + orig_message_len_64bit

def split_registers(message_digest):
    hash_int = int.from_bytes(message_digest, byteorder="big")
    registers = []
    for i in range(5):
        registers.append(hash_int >> (i * 32) & (2**32 - 1))
    return list(reversed(registers))

def check_admin(message):
    return b";admin=true" in message

if __name__=="__main__":
    message = "the quick brown fox jumps over the lazy dog with alacrity and purpose".encode("ascii")
    padded_message = preprocess(message)
    padding = generate_padding(len(message))
    assert message + padding == padded_message, "incorrect padding: {} != {}".format(message + padding, padded_message)

    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".encode("ascii")
    key = "YELLOW SUBMARINE".encode("ascii")
    padded_message = preprocess(key + message)
    mac = hash_sha1(key + message)
    start_registers = split_registers(mac)

    for i in range(512):    
        assumed_key = bytearray([65] * i)
        glue_padding = generate_padding(len(assumed_key + message))
        extension = ";admin=true".encode("ascii")
        forged_message = message + glue_padding + extension
        forged_mac = hash_sha1(extension, True, start_registers, len(assumed_key + message + glue_padding))
        if hash_sha1(key + forged_message) == forged_mac and check_admin(forged_message):
            print("Successfully forged MAC: {} {}".format(forged_message, base64.b64encode(forged_mac)))
            break
        elif i == 16:
            print("Failed to forge MAC")







