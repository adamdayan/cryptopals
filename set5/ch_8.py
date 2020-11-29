import math
from set5.ch_7 import RSACipher, invmod, gcd

def find_cube_root(x):
    start_bit_len = x.bit_length() // 3
    low = 0
    high = math.sqrt(x)
    g_3 = 0
    while g_3 != x:
        #g = round((low + high) / 2)
        g = int((low + high) // 2)
        g_3 = g**3
        #print(g, g_3, low, high, high < low)
        if high < low:
            raise Exception("Failed to find cube root")
        elif g_3 > x:
            high = g
        elif g_3 < x:
            low = g + 1 
        else:
            return g

def chinese_remainder_solve(c0, c1, c2, n0, n1, n2):
    ms0 = n1 * n2
    ms1 = n0 * n2
    ms2 = n0 * n1
    result = ((c0 * ms0 * invmod(ms0, n0)) + (c1 * ms1 * invmod(ms1, n1)) + (c2 * ms2 * invmod(ms2, n2))) % (n0 * n1 * n2)
    #return result 
    return find_cube_root(result) 
   
def break_rsa_texts(ciphertexts, public_keys):
    cipher_nums = [int(c, 16) for c in ciphertexts]
    decrypted_num_repr = chinese_remainder_solve(*cipher_nums, *public_keys)
    return bytearray.fromhex(hex(decrypted_num_repr)[2:]).decode("ascii")
 
if __name__=="__main__":
    plain_num = 254 
    cipher_nums = []
    public_keys = []     
    for _ in range(3):
        rc = RSACipher()
        cipher_nums.append(rc.encrypt(plain_num))
        public_keys.append(rc.get_n())
   
    
    decrypted_num = chinese_remainder_solve(*cipher_nums, *public_keys)
    assert decrypted_num == plain_num, "Decrypted num and plain num do not match. Decrypted num: {}, plain num: {} delta: {}".format(decrypted_num, plain_num, abs(decrypted_num - plain_num))
    print("Successfully broke RSA! Decrypted num: {}".format(decrypted_num))
    
    plaintext = "This is my secret message!"
    ciphertexts = []
    public_keys = []
    for _ in range(3):
        rc = RSACipher()
        ciphertexts.append(rc.encrypt_text(plaintext))
        public_keys.append(rc.get_n())

    decrypted_text = break_rsa_texts(ciphertexts, public_keys)
    assert decrypted_text == plaintext, "plaintext and decrypted text do not match: {} {}".format(decrypted_text, plaintext)
    print("Succesfully broke RSA ciphertext: ", decrypted_text)
