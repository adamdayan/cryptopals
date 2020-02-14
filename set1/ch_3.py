import sys
import string
import math

def compute_letter_freq(target_string):
    alphabet = list(string.printable)
#    target_string = target_string.lower()

    per_letter_cnt = {}
    total = 0

    for letter in alphabet: 
        cnt = target_string.count(letter)
        per_letter_cnt[letter] = cnt
        total += cnt

    if total > 0: 
        per_letter_frequency = {
            letter : float(cnt) / float(total) for letter, cnt in per_letter_cnt.items()
        }
    else: 
        per_letter_frequency = {
            letter : 0 for letter, cnt  in per_letter_cnt.items()
        }

    return per_letter_frequency

def xor_single_byte(target_bytes, key):
    return bytearray([targ ^ key for targ in target_bytes])

def decrypt(target_bytes, key):
    decrypted_target_bytes = xor_single_byte(target_bytes, key)
    decrypted_string = decrypted_target_bytes.decode("utf-8")
        
    return decrypted_string

def compute_loss(target_frequency, reference_frequency):
    loss = 0
    for letter in list(string.printable): 
        loss += abs(target_frequency[letter] - reference_frequency[letter])

    return loss

def compute_likely_key(target, reference_frequency):
    cur_best_loss = math.inf
    cur_best_key = -1

    for key in range(256):
        try:
            decrypted_target = decrypt(target, key)
            
        except UnicodeDecodeError:
            continue
        target_frequency = compute_letter_freq(decrypted_target)
        loss = compute_loss(target_frequency, reference_frequency)

        if loss < cur_best_loss:
            cur_best_loss = loss 
            cur_best_key = key

    return cur_best_key, cur_best_loss

def crack_single_byte_cipher(target_hex, sample_text_path):
    with open(sample_text_path, "r") as t:
        sample_text = t.read()

    reference_frequency = compute_letter_freq(sample_text)

    most_likely_key, most_likely_loss = compute_likely_key(bytes.fromhex(target_hex), reference_frequency)

    print("Target hex: {}".format(target_hex))
    print("Most likely key: {}".format(most_likely_key))
    print("Resulting decrypt: {}".format(decrypt(bytes.fromhex(target_hex), most_likely_key)))


if __name__=="__main__":     
    intercept = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    crack_single_byte_cipher(intercept, "sample_text.txt")
