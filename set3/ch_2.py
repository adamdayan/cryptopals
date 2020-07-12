import base64 
import math 

from Crypto.Cipher import AES

def xor(target, ctr_block):
    output = bytearray(len(target))
    for i in range(len(target)):
        output[i] = target[i] ^ ctr_block[i]

    return output

    

def ctr(target, key, nonce):
    nonce = nonce.to_bytes(8, "little", signed=False)
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    for i in range(math.ceil(len(target) / len(key))):
        block_count = i.to_bytes(8, "little", signed=False) 
        ctr_block = nonce + block_count 
        encrypted_ctr_block = cipher.encrypt(ctr_block) 
        
        start = i * len(key)
        stop = min(start + len(key), len(target))
        result = result + (xor(target[start:stop], encrypted_ctr_block))

    return result


if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("utf-8")
    ciphertext_bytearr = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

    plaintext_bytearr = ctr(ciphertext_bytearr, key, 0)
    print("Decrypted string: {}".format(plaintext_bytearr.decode("utf-8")))
