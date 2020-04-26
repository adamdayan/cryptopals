import math

def split_into_blocks(target_bytearray, blocksize):
    block_list = []
    for i in range(0, len(target_bytearray), blocksize):
        block_list.append(target_bytearray[i:i+blocksize]) 
    
    return block_list

def find_pct_same(block_list):
    same_cnt = 0
    for block in block_list:
        for check_block in block_list:
            if block == check_block:
                same_cnt+=1

    return same_cnt / len(block_list)

def find_most_similar_ciphertext(ciphertext_bytearry_list, blocksize):
    highest_pct_same = 0
    most_similar_ciphertext = bytearray()
    most_similar_line_num = 0
    for idx, ciphertext in enumerate(ciphertext_bytearray_list):
        block_list = split_into_blocks(ciphertext, blocksize)
        pct_same = find_pct_same(block_list)
        if pct_same > highest_pct_same:
            highest_pct_same = pct_same
            most_similar_ciphertext = ciphertext
            most_similar_line_num = idx


    return highest_pct_same, most_similar_ciphertext, most_similar_line_num
    

if __name__=="__main__":

    with open("data_ch_8.txt", "r") as f:
        ciphertext_list = f.read().strip().split("\n")

    ciphertext_bytearray_list = [bytearray.fromhex(ciphertext) for ciphertext in ciphertext_list]
    highest_pct_same, most_similar_ciphertext, most_similar_line_num = find_most_similar_ciphertext(ciphertext_bytearray_list, 16)
    print("Most likely AES ECB encrypted ciphertext is {} with {}% equal blocks on line {}".format(most_similar_ciphertext, highest_pct_same, most_similar_line_num))

