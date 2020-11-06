import hashlib
import random
import math
from Crypto.Cipher import AES

from set5.ch_1 import generate_public_key, generate_session_key
from set2.ch_1 import padder, unpadder

def generate_aes_key(session_key):
    hasher = hashlib.sha1()
    if session_key <= 255:
        session_key_bytes = bytes([session_key])
    else:
        session_key_bytes = session_key.to_bytes(byteorder="big", length=math.ceil(math.log2(session_key)))
    hasher.update(session_key_bytes)
    return hasher.digest()[:16]

class GoodPerson:
    def __init__(self, name):
        self.name = name

    def set_params(self, p, g):
        self.p = p
        self.g = g
        self.private_key = random.randint(0, self.p) % self.p
        self.public_key = generate_public_key(p, g, self.private_key)

    def initiate_handshake(self, partner):
        partner.set_params(self.p, self.g)
        self.partner_public_key = partner.receive_handshake(self.public_key)
        self.session_key = generate_session_key(self.p, self.partner_public_key, self.private_key)
        self.aes_key = generate_aes_key(self.session_key)

    def receive_handshake(self, partner_public_key):
        self.partner_public_key = partner_public_key
        self.session_key = generate_session_key(self.p, self.partner_public_key, self.private_key)
        self.aes_key = generate_aes_key(self.session_key)
        return self.public_key

    def send_message(self, message, partner):
        print("{} sending message: {}".format(self.name, message))
        padded_message = padder(message, len(self.aes_key))
        iv = bytes([random.randint(0, 255) for _ in range(len(self.aes_key))])
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(padded_message)
        echoed_message, partner_iv = partner.echo_message(encrypted_message, iv)
        partner_cipher = AES.new(self.aes_key, AES.MODE_CBC, partner_iv)
        decrypted_echoed_message = unpadder(partner_cipher.decrypt(echoed_message))
        assert decrypted_echoed_message == message, "sent and echoed message differ do not match! sent: {} echoed: {}".format(message, decrypted_echoed_message)

    def echo_message(self, encrypted_message, iv):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(encrypted_message)
        message = unpadder(padded_message)
        print("{} received message: {}".format(self.name, message))
        return_iv = bytes([random.randint(0, 255) for _ in range(len(self.aes_key))])
        return_cipher = AES.new(self.aes_key, AES.MODE_CBC, return_iv)
        return return_cipher.encrypt(padder(message, len(self.aes_key))), return_iv


class BadPerson:
    def __init__(self, name, origin, recipient):
        self.name = name
        self.origin = origin
        self.recipient = recipient 
    
    def set_params(self, p, g):
        self.p = p 
        self.g = g

    def initiate_handshake(self, recipient):
        recipient.set_params(self.p, self.g)
        self.recipient_public_key = recipient.receive_handshake(self.p)

    def receive_handshake(self, origin_public_key):
        self.origin_public_key = origin_public_key
        self.initiate_handshake(self.recipient) 
        self.session_key = 0
        self.aes_key = generate_aes_key(self.session_key)
        return self.p

    def echo_message(self, encrypted_message, iv):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(encrypted_message)
        message = unpadder(padded_message)
        print("{} relayed message: {}".format(self.name, message))
        recipient_message, recipient_iv = self.recipient.echo_message(encrypted_message, iv)
        recipient_cipher = AES.new(self.aes_key, AES.MODE_CBC, recipient_iv)
        decrypted_recipient_message = unpadder(recipient_cipher.decrypt(recipient_message))
        print("{} relayed message: {}".format(self.name, decrypted_recipient_message))
        return recipient_message, recipient_iv

def safe_handshake(a, b, p, g, message):
    print("Conducting normal Diffie-Hellman key exchange")
    a.set_params(p, g)
    a.initiate_handshake(b)
    a.send_message(message, b)

def mitm_handshake(a, b, p, g, message):
    print("Man-in-the-middle altering public keys to p")
    a.set_params(p, g)
    m = BadPerson("Mary", a, b)
    a.initiate_handshake(m)
    a.send_message(message, m)




if __name__=="__main__":
    message = "Hi, I'm Alice!".encode("ascii")
    
    nist_p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    nist_p_bytearr = bytearray.fromhex(nist_p_hex)
    p = int.from_bytes(nist_p_bytearr, byteorder="big")
    g = 2
    
    alice = GoodPerson("Alice")
    bob = GoodPerson("Bob")

    safe_handshake(alice, bob, p, g, message)
    
    adam = GoodPerson("Adam")
    brian = GoodPerson("Brian")
    message = "Hi Brian, I'm Adam. The eagle has landed!".encode("ascii")

    mitm_handshake(adam, brian, p, g, message)


