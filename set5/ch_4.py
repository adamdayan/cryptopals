import hashlib
import math
import random

def get_num_byte_len(num):
    if num == 0:
        return 1
    else:
        return math.ceil(math.log2(num))


class Server:
    def __init__(self):
        self.private_key = random.randint(0, 2**100)

    def agree_params(self, n, g, k, email, password):
        self.n = n
        self.g = g
        self.k = k
        self.email = email
        self.generate_password_params(password)

    def generate_password_params(self, password):
        self.salt = random.randint(0, 2**100)
        hasher = hashlib.sha256()
        self.salt_bytes = self.salt.to_bytes(
            byteorder="big",
            length=get_num_byte_len(self.salt)
        )
        hasher.update(self.salt_bytes + password.encode("ascii"))
        xH = hasher.digest().hex()
        x = int(xH, 16)
        self.v = pow(self.g, x, self.n)

    def send_salt_and_public_key(self, client):
        self.public_key = (self.k * self.v) + pow(self.g, self.private_key, self.n) # NOTE: is ordering right? 
        client.accept_salt_and_public_key(self.salt, self.public_key)

    def accept_email_and_public_key(self, email, client_public_key):
        if email != self.email:
            raise Exception("Unknown email!")
        self.client_public_key = client_public_key

    def compute_hashes(self):
        hasher = hashlib.sha256()
        public_key_bytes = self.public_key.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.public_key)
        )
        client_public_key_bytes = self.client_public_key.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.client_public_key)
        )
        hasher.update(client_public_key_bytes + public_key_bytes)
        self.uH = hasher.digest().hex()
        self.u = int(self.uH, 16)
        
        self.s = pow(
            self.client_public_key  * pow(self.v, self.u, self.n),
            self.private_key,
            self.n
        )
        s_bytes = self.s.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.s)
        )
        hasher = hashlib.sha256()
        hasher.update(s_bytes)
        self.K = hasher.digest()

    def authenticate(self, srp_hash):
        hasher = hashlib.sha256()
        hasher.update(self.K + self.salt_bytes)
        check_hash = hasher.digest().hex()
        if check_hash == srp_hash:
            return True
        else:
            print(check_hash, srp_hash)
            return False

class Client:
    def __init__(self, n, g, k, email, password):
        self.n = n
        self.g = g
        self.k = k
        self.email = email
        self.password = password
        self.private_key = random.randint(0, 2**100)

    def agree_params(self, server):
        server.agree_params(self.n, self.g, self.k, self.email, self.password)

    def send_email_and_public_key(self, server):
        self.public_key = pow(self.g, self.private_key, self.n)
        server.accept_email_and_public_key(self.email, self.public_key)

    def accept_salt_and_public_key(self, salt, server_public_key):
        self.salt = salt
        self.server_public_key = server_public_key

    def compute_hashes(self):
        hasher = hashlib.sha256()
        public_key_bytes = self.public_key.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.public_key)
        )
        server_public_key_bytes = self.server_public_key.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.server_public_key)
        )
        hasher.update(public_key_bytes + server_public_key_bytes)
        uH = hasher.digest().hex()
        u = int(uH, 16)
        hasher = hashlib.sha256()
        self.salt_bytes = self.salt.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.salt)
        )
        hasher.update(self.salt_bytes + self.password.encode("ascii"))
        xH = hasher.digest().hex()
        x = int(xH, 16)
        self.s = pow(
            self.server_public_key  - self.k * pow(self.g, x, self.n), 
            self.private_key + u * x, 
            self.n
        )
        hasher = hashlib.sha256()
        s_bytes = self.s.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.s)
        )
        hasher.update(s_bytes)
        self.K = hasher.digest()

    def authenticate(self, server):
        hasher = hashlib.sha256()
        hasher.update(self.K + self.salt_bytes)
        if server.authenticate(hasher.digest().hex()):
            print("Successfully authenticated")
        else:
            raise Exception("Failed to authenticate")


def attempt_srp_authenticate(client, server):
    client.agree_params(server)
    client.send_email_and_public_key(server)
    print("client sent email and public key")
    server.send_salt_and_public_key(client)
    print("server sent salt and public key")
    server.compute_hashes()
    print("sever computed hashes")
    client.compute_hashes()
    print("client computed hashes")
    client.authenticate(server)


if __name__=="__main__":
    nist_p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    nist_p_bytearr = bytearray.fromhex(nist_p_hex)
    n = int.from_bytes(nist_p_bytearr, byteorder="big")
    g = 2
    k = 3
    email = "donald@whitehouse.gov"
    password = "mcdonalds"

    client = Client(n, g, k, email, password)
    server = Server()
    attempt_srp_authenticate(client, server)



