import random

from ch_5 import MersenneTwister

def mersenne_stream_cipher(seed, input_bytearr):
    mt = MersenneTwister()
    mt.seed_mt(seed)
    output_bytearr = bytearray()
    idx = 0
    while idx < len(input_bytearr):
        cur_rn = mt.extract_number()
        for _ in range(4):
            output_bytearr.append(input_bytearr[idx] ^ (cur_rn & (2**8 - 1)))
            cur_rn = cur_rn >> 8
            idx += 1
            if idx >= len(input_bytearr):
                break

    return output_bytearr

def generate_random_bytearr():
    #num_bytes = random.randint(0, 100)
    num_bytes = 4 
    return bytearray([random.randint(0, 128) for _ in range(num_bytes)])

    
def crack_mt_cipher(ciphertext, known_plaintext):
    known_len = len(known_plaintext_bytearr)
    prefix_len = len(ciphertext) - known_len 
    known_ciphertext_start = prefix_len + (-prefix_len % 4)
    known_plaintext_start = 4 - (prefix_len % 4)
    keystream_byte = 0 
    for i in range(4):
        known_ciphertext_byte = ciphertext[known_ciphertext_start + i]
        known_plaintext_byte = known_plaintext[known_plaintext_start + i]
        keystream_byte += (known_ciphertext_byte ^ known_plaintext_byte) << (i * 8)

    mt_output_num = int(known_ciphertext_start / 4)
    for i in range(2**16):
        mt = MersenneTwister()
        mt.seed_mt(i)
        for _ in range(mt_output_num):
            mt.extract_number()

        if mt.extract_number() == keystream_byte:
            return i

    raise Exception("Failed to find seed with matching output")
    


if __name__=="__main__":
    """
    #### CHECK ENCRYPT/DECRYPT WORKS #### 
    plaintext_bytearr = "The quick brown fox jumps over the lazy dog".encode("utf-8")
    seed = 100 
    ciphertext_bytearr = mersenne_stream_cipher(seed, plaintext_bytearr)
    decrypted_bytearr = mersenne_stream_cipher(seed, ciphertext_bytearr)
    assert decrypted_bytearr == plaintext_bytearr, "decrypt and original do not match!"
    """
    known_plaintext_bytearr = ("A" * 14).encode("utf-8")
    plaintext_bytearr = generate_random_bytearr() + known_plaintext_bytearr
    seed = random.randint(0, 2**16)
    ciphertext_bytearr = mersenne_stream_cipher(seed, plaintext_bytearr)

    guessed_seed = crack_mt_cipher(ciphertext_bytearr, known_plaintext_bytearr)
    assert guessed_seed == seed, "{} != {}. Failed to guess seed correctly!".format(guessed_seed, seed)
    print("congratulations! guessed seed ({}) is equal to  seed ({})".format(guessed_seed, seed))

