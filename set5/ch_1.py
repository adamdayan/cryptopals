import random 

def recursive_modexp(num, power, modulo):
    if power == 0:
        return 1
    elif power % 2 == 0:
        return (modexp(num, power//2, modulo)**2) % modulo
    else:
        return ((num % modulo) * modexp(num, power-1, modulo)) % modulo

def modexp(num, power, modulo):
    res = 1
    if power % 2 != 0:
        res = num
    while power:
        power = power >> 1
        num = (num * num) % modulo
        if power % 2 != 0:
            res = (res * num) % modulo
    return res

def generate_public_key(p, g, private_key):
    return modexp(g, private_key, p)

def generate_session_key(p, public_key, private_key):
    return modexp(public_key, private_key, p)

def diffie_hellman_key_exchange(p, g, a, b):
    A = generate_public_key(p, g, a)
    B = generate_public_key(p, g, b)

    sa = generate_session_key(p, B, a)
    sb = generate_session_key(p, A, b)
    return sa, sb


if __name__=="__main__":
    nist_p_hex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
    nist_p_bytearr = bytearray.fromhex(nist_p_hex)
    
    p = int.from_bytes(nist_p_bytearr, byteorder="big")
    g = 2
    a = random.randint(0, p) % p
    b = random.randint(0, p) % p
    print("a: {} b: {} p: {} g: {}".format(a, b, p, g))
    print("a_bits: {} b_bits: {} p_bits: {}".format(len(bin(a)[2:]), len(bin(b)[2:]), len(bin(p)[2:])))
    sa, sb = diffie_hellman_key_exchange(p, g, a, b)
    assert sa == sb, "DH failed, session keys do not match! sa: {}, sb: {}".format(sa, sb)
    print("session keys: ", sa, sb)

    
