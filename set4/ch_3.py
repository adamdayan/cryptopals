from Crypto.Cipher import AES
from set2.ch_1 import padder, unpadder
from set3.ch_2 import xor

def encrypt_cbc(plaintext_bytearr, key):
    padded_plaintext_bytearr = padder(plaintext_bytearr, len(key))
    iv = key
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(padded_plaintext_bytearr)

def decrypt(ciphertext_bytearr, key):
    iv = key
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext_bytearr = bytes(ciphertext_bytearr)
    padded_plaintext_bytearr = cipher.decrypt(ciphertext_bytearr)
    plaintext_bytearr = unpadder(padded_plaintext_bytearr)
    for b in plaintext_bytearr:
        if b > 127:
            return False, plaintext_bytearr
    return True, plaintext_bytearr

def modify_ciphertext(ciphertext_bytearr, blocksize):
    ciphertext_bytearr = bytearray(ciphertext_bytearr)
    ciphertext_bytearr[blocksize:2*blocksize] = bytearray([0] * blocksize)
    ciphertext_bytearr[2*blocksize:3*blocksize] = ciphertext_bytearr[:blocksize]
    return ciphertext_bytearr

def attack_ciphertext(ciphertext_bytearr, blocksize, key):
    ciphertext_bytearr = modify_ciphertext(ciphertext_bytearr, blocksize)
    is_successful_decrypt, plaintext_bytearr = decrypt(ciphertext_bytearr, key)
    if is_successful_decrypt:
        raise Exception("No ASCII error occurred - impossible to find key!")
    else:
        key = xor(plaintext_bytearr[:blocksize], plaintext_bytearr[2*blocksize:3*blocksize])
        return key


if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("ascii")
    plaintext_bytearr = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog".encode("ascii")

    ciphertext_bytearr = encrypt_cbc(plaintext_bytearr, key)
    recovered_key = attack_ciphertext(ciphertext_bytearr, len(key), key)
    assert recovered_key==key, "The recovered key does not match the key, attack failed!"
    print("attack successful. key: {} recovered_key: {}".format(key.decode("ascii"), recovered_key.decode("ascii")))
        
