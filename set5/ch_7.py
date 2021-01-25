from Crypto.Util import number
from set5.ch_1 import modexp

def extended_euclidean(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - (quotient*r)
        old_s, s = s, old_s - (quotient*s)
        old_t, t = t, old_t - (quotient*t)

    return old_s, old_t

def gcd(a, b):
    if b > a:
        a, b = b, a

    r = a % b
    if r == 0:
        return b
    else:
        return gcd(b, r)

def invmod(x, m):
    _, t = extended_euclidean(m, x)
    return (t % m + m) % m

class RSACipher:
    def __init__(self):
        self.generate_key()

    def generate_key(self):
        congruent_1 = False
        while not congruent_1:
            self.p = number.getPrime(128)
            self.q = number.getPrime(128)
            self.n = self.p * self.q
            self.et = (self.p - 1) * (self.q - 1)
            self.e = 3 # TODO: check if I should make this the big standard 65636 (?)
            if gcd(self.et, self.e) == 1:
                congruent_1 = True
        self.d = invmod(self.e, self.et)
   
    def get_n(self):
        return self.n

    def get_public_key(self):
        return self.e, self.n

    def encrypt(self, target):
        return modexp(target, self.e, self.n)

    def decrypt(self, target):
        return modexp(target, self.d, self.n)

    def encrypt_text(self, plaintext):
        num_repr = int(plaintext.encode("ascii").hex(), 16)
        return hex(self.encrypt(num_repr))

    def decrypt_text(self, ciphertext):
        encrypted_num_repr = int(ciphertext, 16)
        decrypted_num_repr = self.decrypt(encrypted_num_repr)
        return bytearray.fromhex(hex(decrypted_num_repr)[2:]).decode("ascii")

if __name__=="__main__":
    rc = RSACipher()
    plain = 48697961 
    plain = 192808
    output = rc.encrypt(plain)
    decrypt = rc.decrypt(output)
    assert plain == decrypt, "plain: {} decrypt: {}".format(plain, decrypt)

    plaintext = "This is my secret message!"
    ciphertext = rc.encrypt_text(plaintext)
    decrypted_text = rc.decrypt_text(ciphertext)
    print("plaintext: ", plaintext, "decrypted_text: ", decrypted_text)
    assert plaintext == decrypted_text
