from set5.ch_2 import GoodPerson, BadPerson, generate_aes_key

class BadPersonG1(BadPerson):
    def set_params(self, p, g):
        self.p = p
        self.g = 1
   
    def initiate_handshake(self, recipient):
        recipient.set_params(self.p, self.g)
        self.recipient_public_key = recipient.receive_handshake(1)

    def receive_handshake(self, origin_public_key):
        self.origin_public_key = origin_public_key
        self.initiate_handshake(self.recipient)
        self.session_key = 1 % self.p
        self.aes_key = generate_aes_key(self.session_key)
        return self.recipient_public_key

class BadPersonGP(BadPerson):
    def set_params(self, p, g):
        self.p = p
        self.g = p

    def initiate_handshake(self, recipient):
        recipient.set_params(self.p, self.g)
        self.recipient_public_key = recipient.receive_handshake(0)

class BadPersonGPminus1(BadPerson):
    def set_params(self, p, g):
        self.p = p
        self.g = p - 1
   
    def initiate_handshake(self, recipient):
        recipient.set_params(self.p, self.g)
        self.recipient_public_key = recipient.receive_handshake(1)

    def receive_handshake(self, origin_public_key):
        self.origin_public_key = origin_public_key
        self.initiate_handshake(self.recipient)
        self.session_key = 1 % self.p
        self.aes_key = generate_aes_key(self.session_key)
        return self.recipient_public_key

def mitm_G1_handshake(a, b, p, g, message):
    print("Man-in-the-middle setting g to 1")
    a.set_params(p, g)
    m = BadPersonG1("Mary", a, b)
    a.initiate_handshake(m)
    a.send_message(message, m)

def mitm_GP_handshake(a, b, p, g, message):
    print("Man-in-the-middle setting g to p")
    a.set_params(p, g)
    m = BadPersonGP("Mary", a, b)
    a.initiate_handshake(m)
    a.send_message(message, m)

def mitm_GPminus1_handshake(a, b, p, g, message):
    print("Man-in-the-middle setting g to p-1")
    a.set_params(p, g)
    m = BadPersonGPminus1("Mary", a, b)
    a.initiate_handshake(m)
    a.send_message(message, m)

if __name__=="__main__":
    nist_p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    nist_p_bytearr = bytearray.fromhex(nist_p_hex)
    p = int.from_bytes(nist_p_bytearr, byteorder="big")
    g = 2
    message = "Hi, I'm Alice!".encode("ascii")
 
    mitm_G1_handshake(GoodPerson("Alice"), GoodPerson("Bob"), p, g, message)
    mitm_GP_handshake(GoodPerson("Alice"), GoodPerson("Bob"), p, g, message)
    mitm_GPminus1_handshake(GoodPerson("Alice"), GoodPerson("Bob"), p, g, message)

