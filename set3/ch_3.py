import base64
import math
import string
import copy

from set1.ch_3 import compute_letter_freq, compute_loss
from set3.ch_2 import xor, ctr
from set3.ch_1 import generate_random_bytes

### ABANDONED TRIGRAM WORK DOESN'T IMPROVE SATISFACTORY ANSWER , GOT BORED ### 
"""
def compute_trigram_freq(target_string):
    alphabet = list(set(target_string))

    per_trigram_cnt = {}
    total = 0
    for l1 in alphabet:
        for l2 in alphabet:
            for l3 in alphabet:
                trigram = l1 + l2 + l3
                cnt = target_string.count(trigram)
                per_trigram_cnt[trigram] = cnt
                total += cnt

    per_trigram_freq = {
        trigram : float(cnt) / float(total) for trigram, cnt  in per_trigram_cnt.items()
    } 

    return per_trigram_freq
                
def prune_trigrams(reference_freq):
    pruned_freq = {}
    for cnt, trigram in enumerate(sorted(reference_freq.items(), key=lambda x: x[1], reverse=True)):
        if cnt > 300:
            break
        pruned_freq[trigram[0]] = trigram[1]

    return pruned_freq

def compute_trigram_loss(target_freq, reference_freq):
    loss = 0
    for key in reference_freq.keys():
        loss += abs(target_freq.get(key, 0) - reference_freq[key])

    return loss / len(reference_freq)

def improve_keystream_trigram(ciphertexts, guessed_keystream, reference_trigram_frequency):
    max_len = max([len(ciphertext) for ciphertext in ciphertexts])
    start_decrypt = ""
    for c in ciphertexts:
        start_decrypt = start_decrypt + " " + xor(c, guessed_keystream).decode("utf-8").lower()
    start_loss = compute_trigram_loss(compute_trigram_freq(start_decrypt), reference_trigram_frequency)
    for byte_pos in range(max_len):
        cur_best_ks_byte = guessed_keystream[byte_pos]
        cur_least_loss = start_loss
        this_guessed_keystream = copy.copy(guessed_keystream)
        for potential_ks_byte in range(256):
            this_guessed_keystream[byte_pos] = potential_ks_byte
            potential_plaintexts = ""
            try:
                for c in ciphertexts:
                    potential_plaintexts = potential_plaintexts + " " + xor(c, this_guessed_keystream).decode("utf-8").lower()
            except UnicodeDecodeError:
                continue
            potential_trigram_frequency = compute_trigram_freq(potential_plaintexts)
            potential_loss = compute_trigram_loss(potential_trigram_frequency, reference_trigram_frequency)
            if potential_loss < cur_least_loss:
                print(start_loss, potential_loss)
                cur_best_ks_byte = potential_ks_byte
                cur_least_loss = potential_loss 

        guessed_keystream[byte_pos] = cur_best_ks_byte
    return guessed_keystream
"""

def guess_keystream(ciphertexts, reference_letter_frequency):
    guessed_keystream = bytearray()
    max_len = max([len(ciphertext) for ciphertext in ciphertexts])
    for byte_pos in range(max_len):
        cur_best_ks_byte = 0
        cur_least_loss = math.inf
        for potential_ks_byte in range(256):
            potential_plaintext_bytes = bytearray()
            potential_plaintext_bytes = bytearray([ciphertext[byte_pos] ^ potential_ks_byte for ciphertext in ciphertexts if len(ciphertext) - 1 >= byte_pos])
            try:
                potential_letter_frequency = compute_letter_freq(potential_plaintext_bytes.decode("utf-8"))
            except UnicodeDecodeError:
                continue
            potential_loss = compute_loss(potential_letter_frequency, reference_letter_frequency)
 
            if potential_loss < cur_least_loss:
                cur_best_ks_byte = potential_ks_byte
                cur_least_loss = potential_loss 
        guessed_keystream.append(cur_best_ks_byte)
    return guessed_keystream

def attack(ciphertexts, reference_letter_frequency):
    guessed_keystream = guess_keystream(ciphertexts, reference_letter_frequency) 
    plaintexts = []
    for ciphertext in ciphertexts:
        plaintexts.append(xor(ciphertext, guessed_keystream))
    
    return plaintexts

if __name__=="__main__":
    plaintexts = []
    f = open("set3/data_ch_3.txt", "r")
    for line in f:
        plaintexts.append(base64.b64decode(line))
    f.close()

    key = generate_random_bytes(16)
    ciphertexts = [ctr(p, key, 123) for p in plaintexts]

    reference_path = "set1/sample_text.txt"
    with open(reference_path, "r") as f:
        reference_text = f.read()
    reference_letter_frequency =  compute_letter_freq(reference_text)

    decrypted_plaintexts = attack(ciphertexts, reference_letter_frequency)
    for p in decrypted_plaintexts:
        print(p.decode("utf-8"))

    
