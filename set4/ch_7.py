import time
import hashlib
import requests 

from statistics import median 

def break_byte(known_signature, idx, file_data, rounds):
    results = [[] for _ in range(256)]
    for r in range(rounds):
        for byte in range(256):
            guessed_signature = known_signature 
            guessed_signature[idx] = byte
            base = "http://localhost:8080"
            url = "/upload?file={}&signature={}".format(file_data, guessed_signature.hex())
            t_start = time.time()
            resp = requests.get(base + url, headers={"Connection" : "close"}).close()
            t_end = time.time()
            dur = t_end - t_start
            results[byte].append(dur)

    median_results = [median(res) for res in results]
    return median_results.index(max(median_results))

def attack_fileserver(file_data, rounds):
    guessed_file_signature = bytearray([0] * 16)
    for idx in range(16):
        guessed_file_signature[idx] = break_byte(guessed_file_signature, idx, file_data, rounds)
    return guessed_file_signature

if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("ascii")
    #FileAuthenticator.set_key(key)
    file_data = "asdfuaapsdfnwefrpasiudfhjnaasdfasdfkljasdflkjaoiucvpiouvpiuadfkjejkf"

    guessed_file_signature = attack_fileserver(file_data, 30)
    hash_verifier = hashlib.md5()
    hash_verifier.update(key + file_data.encode("ascii"))
    verification_signature = hash_verifier.digest()
    
    assert guessed_file_signature == verification_signature, "Failed to guess correct file signature. guessed: {} verified: {} byte_guessed: {} byte_verified: {}".format(guessed_file_signature.hex(), verification_signature.hex(), guessed_file_signature, verification_signature) 

    print("HMAC broken successfully! File signature: {}".format(guessed_file_signature.hex())) 
    print("veri:", verification_signature.hex()) 

