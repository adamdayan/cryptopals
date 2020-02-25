import sys
import math
import base64
from operator import itemgetter
from ch_5 import repeating_xor, encrypt_with_repeating_xor
from ch_3 import compute_likely_key, compute_letter_freq
from itertools import combinations

import checker_6 as c

def compute_hamming_distance(t1, t2):
    hamming_distance = 0
    #iterate through each byte, convert it into a byte string and compare each bit in the byte string
    for t1_byte, t2_byte in zip(t1, t2):
        t1_bits = format(t1_byte, "08b")
        t2_bits = format(t2_byte, "08b")
        pre_hamming_distance = hamming_distance
        for t1_bit, t2_bit in zip(t1_bits, t2_bits):
            if t1_bit != t2_bit:
                hamming_distance += 1

    return hamming_distance

def find_most_likely_key_sizes(target):
    all_hamming_distances = []
    for key_size in range(2, 41):
        if key_size > len(target) / 2:
            break 
        
        all_chunks = split_into_key_size(target, key_size)
        paired_chunks = list(combinations(all_chunks, 2))
        hamming_distance = 0
        for p1, p2 in paired_chunks:
            hamming_distance += compute_hamming_distance(p1, p2)/key_size
        
        this_hamming_distance = {
            "key_size" : key_size, 
            "normalised_hamming_distance" : hamming_distance / len(paired_chunks)         
        }
        all_hamming_distances.append(this_hamming_distance)

    all_hamming_distances.sort(key=itemgetter("normalised_hamming_distance"))
    return [hamming_distance["key_size"] for hamming_distance in all_hamming_distances[:4]]

def split_into_key_size(target, key_size):
    all_chunks = []
    for i in range(0, len(target), key_size):
        chunk = target[i:min(len(target), i + key_size)]
        all_chunks.append(chunk)

    return all_chunks

def transpose_chunks(all_chunks, key_size):
    all_transposed_chunks = []

    for i in range(key_size):
        transposed_chunk = []
        for chunk in all_chunks:
            if i < len(chunk):
                transposed_chunk.append(chunk[i])
        all_transposed_chunks.append(transposed_chunk)

    return all_transposed_chunks

def recover_most_likely_key(target, key_size, reference_frequency):
    all_chunks = split_into_key_size(target, key_size)
    all_transposed_chunks = transpose_chunks(all_chunks, key_size)

    key = bytearray(key_size)
    for idx, transposed_chunk in enumerate(all_transposed_chunks):
        key[idx] = compute_likely_key(transposed_chunk, reference_frequency)[0]

    return key
            
if __name__=="__main__":
    """ 
    thd = compute_hamming_distance("this is a test".encode("ascii"), "wokka wokka!!!".encode("ascii"))
    print(thd) 

    with open("data_ch_6.txt", "r") as t:
        cipher_text = t.read()

    #print(cipher_text)
    cipher_text_bytes = base64.b64decode(cipher_text)

    most_likely_key_sizes = find_most_likely_key_sizes(cipher_text_bytes)
    #print(most_likely_key_sizes)
    
    with open("sample_text.txt", "r") as t:
        sample_text = t.read()

    reference_frequency = compute_letter_freq(sample_text)
    """

    #plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    plaintext = "When Babbage showed that Thwaites' cipher was essentially just another recreation of the Vigenere cipher, Thwaites presented a challenge to Babbage: given an original text (from Shakespeare's The Tempest : Act 1, Scene 2) and its enciphered version, he was to find the key words that Thwaites had used to encipher the original text. " 
    key = "Ice"
    test_ciphertext = repeating_xor(plaintext.encode("ascii"), key.encode("ascii"))
    check_ciphertext = c.repeating_key_xor(plaintext, key)
    print(test_ciphertext == check_ciphertext.encode("ascii")) 

    #key_sizes = find_most_likely_key_sizes(plaintext.encode("ascii"))
    #print(test_ciphertext)
    #print(key_sizes)
    #key = recover_most_likely_key(test_ciphertext, key_sizes[0], reference_frequency)

    #print(key_sizes, key)
