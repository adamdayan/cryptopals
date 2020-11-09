import hashlib
import math
import random 

from set5.ch_4 import get_num_byte_len

class Server:
    def __init__(self):
        self.private_key = random.randint(0, 2**100)
        self.salt = random.randint(0, 2**100)
        self.salt_bytes = self.salt.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.salt)
        )
        self.u = random.randint(0, 2**128)

    def agree_params(self, n, g, password):
        self.n = n
        self.g = g
        self.generate_password_params(password)

    def generate_password_params(self, password):
        hasher = hashlib.sha256()
        hasher.update(self.salt_bytes + password.encode("ascii"))
        x = int(hasher.digest().hex(), 16)
        self.v = pow(self.g, x, self.n)

    def send_salt_public_key_u(self, client):
        self.public_key = pow(self.g, self.private_key, self.n)
        client.accept_salt_public_key_u(self.salt, self.public_key, self.u)

    def accept_public_key(self, client_public_key):
        self.client_public_key = client_public_key

    def compute_hashes(self):
        self.s = pow(self.client_public_key * pow(self.v, self.u, self.n), self.private_key, self.n)
        s_bytes = self.s.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.s)
        )
        hasher = hashlib.sha256()
        hasher.update(s_bytes)
        self.k = hasher.digest()

    def authenticate(self, client_hmac):
        hasher = hashlib.sha256()
        hasher.update(self.k + self.salt_bytes)
        check_hmac = hasher.digest().hex()
        if check_hmac == client_hmac:
            return True
        else:
            print(check_hmac, client_hmac)
            return False

class Client:
    def __init__(self, n, g, password):
        self.n = n
        self.g = g
        self.password = password
        self.private_key = random.randint(0, 2**100)

    def agree_params(self, server):
        server.agree_params(self.n, self.g, self.password)

    def accept_salt_public_key_u(self, salt, server_public_key, u):
        self.salt = salt
        self.salt_bytes = self.salt.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.salt)
        )
        self.server_public_key = server_public_key
        self.u = u

    def send_public_key(self, server):
        self.public_key = pow(self.g, self.private_key, self.n)
        server.accept_public_key(self.public_key)

    def compute_hashes(self):
        hasher = hashlib.sha256()
        hasher.update(self.salt_bytes + self.password.encode("ascii"))
        x = int(hasher.digest().hex(), 16)
        self.s = pow(self.server_public_key, self.private_key + (self.u * x), self.n)
        s_bytes = self.s.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.s)
        )
        hasher = hashlib.sha256()
        hasher.update(s_bytes)
        self.k = hasher.digest()

    def authenticate(self, server):
        hasher = hashlib.sha256()
        hasher.update(self.k + self.salt_bytes)
        client_hmac = hasher.digest().hex()
        if server.authenticate(client_hmac):
            print("Successfully authenticated") 
        else:
            raise Exception("Failed to authenticate")


class BadServer(Server):
    def __init__(self, n, g):
        self.private_key = random.randint(0, 2**100)
        self.salt = random.randint(0, 2**100)
        self.salt_bytes = self.salt.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.salt)
        )
        self.u = random.randint(0, 2**128)
        self.n = n
        self.g = g

    
    def compute_hashes(self):
        pass

    def authenticate(self, client_hmac):
        self.client_hmac = client_hmac 
        return True

    def load_dict(self, path_to_dict):
        with open(path_to_dict) as dict_file:
            self.valid_words = set(dict_file.read().split())

    def crack_password(self, path_to_dict):
        self.load_dict(path_to_dict)
        for w in self.valid_words:
            hasher_x = hashlib.sha256()
            hasher_x.update(self.salt_bytes + w.encode("ascii"))
            x = int(hasher_x.digest().hex(), 16)
            v = pow(self.g, x, self.n)
            s = pow(self.client_public_key * pow(v, self.u, self.n), self.private_key, self.n)
            s_bytes = s.to_bytes(
                byteorder="big", 
                length=get_num_byte_len(s)
            )
            hasher_k = hashlib.sha256() 
            hasher_k.update(s_bytes)
            k = hasher_k.digest()
            hasher_hmac = hashlib.sha256()
            hasher_hmac.update(k + self.salt_bytes)
            check_hmac = hasher_hmac.digest().hex()
            if check_hmac == self.client_hmac:
                print("Successfully cracked password. Password = {}".format(w))
                return
        raise Exception("Failed to crack password")    

    

def attempt_simple_srp_authenticate(client, server):
    client.agree_params(server)
    client.send_public_key(server)
    server.send_salt_public_key_u(client)
    server.compute_hashes()
    client.compute_hashes()
    client.authenticate(server)

def crack_simple_srp(client, server):
    client.send_public_key(server)
    server.send_salt_public_key_u(client)
    server.compute_hashes()
    client.compute_hashes()
    client.authenticate(server)
    server.crack_password("/Users/Adam/Dev/cryptopals_resources/words.txt")

if __name__=="__main__":
    nist_p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    nist_p_bytearr = bytearray.fromhex(nist_p_hex)
    n = int.from_bytes(nist_p_bytearr, byteorder="big")
    g = 2
    
    password = "castle"

    client = Client(n, g, password)
    server = Server()
    attempt_simple_srp_authenticate(client, server)

    naive_client = Client(n, g, password)
    bad_server = BadServer(n, g)
    crack_simple_srp(naive_client, bad_server)
