from Crypto.Cipher import AES
from set2.ch_1 import padder, unpadder


def construct_plaintext(prepend_bytearr, user_input, append_bytearr):
    user_input = user_input.replace(b"=", b"'='").replace(b";", b"';'")
    return prepend_bytearr + user_input + append_bytearr 

def construct_and_encrypt(prepend_bytearr, user_input, append_bytearr, key):
    plaintext_bytearr = construct_plaintext(prepend_bytearr, user_input, append_bytearr)
    padded_plaintext_bytearr = padder(plaintext_bytearr, len(key))
    iv = bytes([0] * len(key))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded_plaintext_bytearr)

def detect_admin(ciphertext_bytearr, key, prepend_len):
    iv = bytes([0] * len(key))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_bytearr = cipher.decrypt(bytes(ciphertext_bytearr))
    print("plaintext_bytearr: ", plaintext_bytearr)
    plaintext_bytearr = unpadder(plaintext_bytearr)
    plaintext_bytearr = plaintext_bytearr[:prepend_len] + plaintext_bytearr[prepend_len + 16:]
    print("plaintext_bytearr: ", plaintext_bytearr)
    plaintext = plaintext_bytearr.decode("utf-8")
    split_plaintext = plaintext.split(";")
    for chunk in split_plaintext:
        if chunk == "admin=true":
            return True

    return False

def attack_ciphertext(actual, desired, ciphertext_bytearr, prepend_len):
    ciphertext_bytearr = bytearray(ciphertext_bytearr)
    for i in range(len(actual)):    
        if actual[i] != desired[i]:
            ciphertext_bytearr[prepend_len + i] = ciphertext_bytearr[prepend_len + i] ^ (actual[i] ^ desired[i])


    return ciphertext_bytearr 
    


if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("utf-8")

    prepend_string = "comment1=cooking%20MCs;userdata="
    append_string = ";comment2=%20like%20a%20pound%20of%20bacon"
    prepend_bytearr = prepend_string.encode("utf-8")
    append_bytearr  = append_string.encode("utf-8")

    user_input = bytearray([97] * 15) + ";dmi=rue".encode("utf-8")
    print("prepend_len: ", len(prepend_bytearr), "user_input_len: ", len(user_input))

    ciphertext_bytearr = construct_and_encrypt(prepend_bytearr, user_input, append_bytearr, key)
    core_user_input = ";dmi=rue".encode("utf-8")
    actual_user_input = core_user_input.replace(b"=", b"'='").replace(b";", b"';'")[1:]
    desired_user_input = ";admin=true".encode("utf-8")
    #attacked_ciphertext_bytearr = attack_ciphertext(ciphertext_bytearr, len(prepend_bytearr))
    attacked_ciphertext_bytearr = attack_ciphertext(actual_user_input, desired_user_input, ciphertext_bytearr, len(prepend_bytearr))
    
    if detect_admin(attacked_ciphertext_bytearr, key, len(prepend_bytearr)):
        print("Successfully inserted 'admin=true' into encrypted message")
    else:
        print("Failed to insert 'admin=true' into encrypted message")
