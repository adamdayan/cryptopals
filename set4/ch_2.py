
from set4.ch_1 import ctr
from set2.ch_8 import construct_plaintext

def construct_and_encrypt(prepend_bytearr, user_input, append_bytearr, key):
    plaintext_bytearr = construct_plaintext(prepend_bytearr, user_input, append_bytearr)
    return ctr(plaintext_bytearr, key)

def detect_admin(ciphertext_bytearr, key):
    plaintext_bytearr = ctr(ciphertext_bytearr, key)
    plaintext = plaintext_bytearr.decode("utf-8")
    split_plaintext = plaintext.split(";")
    for chunk in split_plaintext:
        if chunk == "admin=true":
            return True
    return False

def attack_ctr(actual_user_input, desired_user_input, prepend_len, ciphertext_bytearr):
    relevant_keystream = bytearray()
    for i in range(len(actual_user_input)):
        relevant_keystream.append(ciphertext_bytearr[i + prepend_len] ^ actual_user_input[i])

    for i in range(len(desired_user_input)):
        ciphertext_bytearr[i + prepend_len] = desired_user_input[i] ^ relevant_keystream[i]

    return ciphertext_bytearr


if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("utf-8")

    prepend_string = "comment1=cooking%20MCs;userdata="
    append_string = ";comment2=%20like%20a%20pound%20of%20bacon"
    prepend_bytearr = prepend_string.encode("utf-8")
    append_bytearr  = append_string.encode("utf-8")

    user_input = "cadminetrue".encode("utf-8")
    desired_user_input = ";admin=true".encode("utf-8")

    ciphertext_bytearr = construct_and_encrypt(prepend_bytearr, user_input, append_bytearr, key)
    flipped_ciphertext_bytearr = attack_ctr(user_input, desired_user_input, len(prepend_bytearr), ciphertext_bytearr)
    
    assert detect_admin(ciphertext_bytearr, key), "Failed to find ';admin=true' in bitflipped plaintext: {}".format(ctr(ciphertext_bytearr, key))
    print("Decrypted bitflipped plaintext: {}".format(ctr(ciphertext_bytearr, key)))
    







