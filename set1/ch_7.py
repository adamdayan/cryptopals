import base64
import math

from Crypto.Cipher import AES

if __name__=="__main__":
    
    with open("data_ch_7.txt") as f:
        ciphertext_bytearr = base64.b64decode(f.read())    

    key = "YELLOW SUBMARINE".encode("utf-8")
    block_size = int(128 / 8)

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext_bytearr)

    print("Plaintext: {}".format(plaintext))
