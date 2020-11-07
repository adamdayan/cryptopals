import hashlib

from set5.ch_4 import Server, Client, get_num_byte_len

class BadClientZeroKey(Client):
    def send_email_and_public_key(self, server):
        self.public_key = 0
        server.accept_email_and_public_key(self.email, self.public_key)
   
    def compute_hashes(self):
        self.salt_bytes = self.salt.to_bytes(
            byteorder="big", 
            length=get_num_byte_len(self.salt)
        )
        s_bytes= bytearray([0])
        hasher = hashlib.sha256()
        hasher.update(s_bytes)
        self.K = hasher.digest()


class BadClientNKey(BadClientZeroKey):
    def send_email_and_public_key(self, server):
        self.public_key = self.n
        server.accept_email_and_public_key(self.email, self.public_key)

def attempt_srp_authenticate_zero_key(client, server):
    client.agree_params(server)
    client.send_email_and_public_key(server)
    print("client sent email and zero key")
    server.send_salt_and_public_key(client)
    print("server sent salt and public key")
    server.compute_hashes()
    print("sever computed hashes")
    client.compute_hashes()
    print("client computed zero key hash")
    client.authenticate(server)
    print("client successfully authenticated using zeroed session key")

def attempt_srp_authenticate_n_key(client, server):
    client.agree_params(server)
    client.send_email_and_public_key(server)
    print("client sent email and zero key")
    server.send_salt_and_public_key(client)
    print("server sent salt and public key")
    server.compute_hashes()
    print("sever computed hashes")
    client.compute_hashes()
    print("client computed zero key hash")
    client.authenticate(server)
    print("client successfully authenticated using N public key and zeroed session key")



if __name__=="__main__":
    nist_p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    nist_p_bytearr = bytearray.fromhex(nist_p_hex)
    n = int.from_bytes(nist_p_bytearr, byteorder="big")
    g = 2
    k = 3
    email = "donald@whitehouse.gov"
    password = "mcdonalds"

    client = BadClientZeroKey(n, g, k, email, password)
    server = Server()
    attempt_srp_authenticate_zero_key(client, server)

    client = BadClientNKey(n, g, k, email, password)
    server = Server()
    attempt_srp_authenticate_n_key(client, server)
