import hashlib 
import random 
import math

from set5.ch_1 import modexp
from set5.ch_7 import RSACipher, invmod

def transform_text_to_int(text):
    return int(text.encode("ascii").hex(), 16)

def transform_int_to_text(num):
    return bytearray.fromhex(hex(num)[2:]).decode("ascii")

class Server:
    def __init__(self):
        self.rsa = RSACipher()
        self.rsa.generate_key()
        self.hashes = {}

    def get_public_key(self):
        return self.rsa.get_public_key()

    def decrypt_msg(self, msg):
        msg_bytes = msg.to_bytes(int(math.log(msg, 256)) + 1, byteorder="big")
        hasher = hashlib.md5() 
        hasher.update(msg_bytes)
        msg_hash = hasher.digest()
        if msg_hash in self.hashes:
            raise Exception("REPLAYED MSG ATTACK DETECTED!")
        else:
            self.hashes[msg_hash] = 1
        return self.rsa.decrypt(msg)

class GoodClient:
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def send_msg(self, msg):
        return modexp(msg, self.e, self.n)

class BadClient:
    def __init__(self, e, n):
        self.e = e
        self.n = n

    def replay_msg(self, ciphertext, server):
        s = random.randint(2, self.n - 1)
        altered_ciphertext = (ciphertext * modexp(s, self.e, self.n)) % n
        altered_plaintext = server.decrypt_msg(altered_ciphertext)
        plaintext = (altered_plaintext * invmod(s, self.n)) % self.n
        return plaintext


if __name__=="__main__":
    server = Server()
    e, n = server.get_public_key()
    plaintext = "Hiya, this is my secret message!"
    plaintext_num_repr = transform_text_to_int(plaintext)
    
    gc = GoodClient(e, n)
    ciphertext = gc.send_msg(plaintext_num_repr)
    true_decrypted_plaintext = server.decrypt_msg(ciphertext)

    bc = BadClient(e, n)
    replay_decrypted_plaintext = bc.replay_msg(ciphertext, server)

    assert true_decrypted_plaintext == replay_decrypted_plaintext, "decrypted messages don't match! true: {} replay: {}".format(true_decrypted_plaintext, replay_decrypted_plaintext)
    print("decrypted message", transform_int_to_text(replay_decrypted_plaintext), plaintext)
