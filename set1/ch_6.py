import sys
import math
from operator import itemgetter 
from random import randint
from base64 import b64decode

from ch_5 import encrypt_with_repeating_xor
from ch_3 import decrypt, compute_likely_key, compute_letter_freq 


def compute_hamming_distance(byte_arr_1, byte_arr_2):
    total_hamming_distance = 0

    for byte_1, byte_2 in zip(byte_arr_1, byte_arr_2):
        xor_result = byte_1 ^ byte_2
        xor_result_bin_string = "{0:b}".format(xor_result)
        cur_hamming_distance = 0
        for bit in xor_result_bin_string:
            cur_hamming_distance += int(bit)

        total_hamming_distance += cur_hamming_distance
 
    return total_hamming_distance

def compute_key_size(target_bytearr):
    result_list = []
    for key_size in range(2, 41):
        if key_size * 2 > len(target_bytearr):
            break

        split_target = split_into_key_size(target_bytearr, key_size)
        cur_total_hamming_distance = 0
        cnt_samples = 10000 # sample randomly from split targets this many times
        for i in range(cnt_samples):
            cur_total_hamming_distance += compute_hamming_distance(
                split_target[randint(0, len(split_target) - 1)]
                , split_target[randint(0, len(split_target) - 1)]
            )


        average_hamming_distance = cur_total_hamming_distance / cnt_samples 
        normalised_average_hamming_distance = average_hamming_distance / key_size
    
        result_dict = {
            "key_size" : key_size,
            "total_hamming_distance" : cur_total_hamming_distance, 
            "average_hamming_distance" : average_hamming_distance, 
            "normalised_average_hamming_distance" : normalised_average_hamming_distance
        }
        result_list.append(result_dict)
    
    result_list.sort(key=itemgetter("normalised_average_hamming_distance"))
    return [result_dict["key_size"] for result_dict in result_list[:4]]

def split_into_key_size(target_bytearr, key_size):
    all_chunks = []
    for i in range(0, len(target_bytearr), key_size):
        if i + key_size > len(target_bytearr):
            break
        all_chunks.append(target_bytearr[i:i+key_size])

    return all_chunks

def transpose_chunks(all_chunks, transpose_num):
    all_transposed_chunks = []
    
    for cnt in range(transpose_num):
        transposed_chunk = []
        for chunk in all_chunks:
            transposed_chunk.append(chunk[cnt])

        all_transposed_chunks.append(transposed_chunk)
        
    return all_transposed_chunks

def find_key(target_bytearr, key_size, reference_frequency):
    split_target_chunks = split_into_key_size(target_bytearr, key_size)
    transposed_target_chunks= transpose_chunks(split_target_chunks, key_size)
    
    key = bytes()
    loss = 0 
    for chunk in transposed_target_chunks:
        most_likely_key, most_likely_loss = compute_likely_key(chunk, reference_frequency)
        key+=bytes([most_likely_key])
        loss+=most_likely_loss

    avg_loss = loss/len(key)
    return avg_loss, key

def compute_most_likely_key(target_bytearr, sample_text_path):
    with open(sample_text_path, "r") as t:
        sample_text = t.read()
    reference_frequency = compute_letter_freq(sample_text)

    most_likely_key_sizes = compute_key_size(target_bytearr)
    cur_lowest_loss = math.inf
    for key_size in most_likely_key_sizes:
        loss, key = find_key(target_bytearr, key_size, reference_frequency)
        if loss < cur_lowest_loss:
            cur_lowest_loss = loss
            cur_best_key = key


    return cur_best_key


if __name__=="__main__":

    with open('data_ch_6.txt') as f:
        ciphertext_bytearr = b64decode(''.join(f.read().strip().split('\n')))

    key = compute_most_likely_key(ciphertext_bytearr, "sample_text.txt")

    plaintext = decrypt(ciphertext_bytearr, key)

    print("Key: {}".format(key), "plaintext: {}".format(plaintext))

     
    

