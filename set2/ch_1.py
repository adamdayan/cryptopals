def padder(target_bytearray, block_size):
    if len(target_bytearray) == block_size:
        return target_bytearray
    num_missing_bytes = block_size - (len(target_bytearray) % block_size)
    missing_bytes = bytearray([num_missing_bytes]) * num_missing_bytes
    return target_bytearray + missing_bytes

def unpadder(padded_bytearray):
    potential_missing_byte_num = padded_bytearray[-1]
    if potential_missing_byte_num == 0:
        return padded_bytearray
    for i in range(len(padded_bytearray) - 1, len(padded_bytearray) - potential_missing_byte_num, -1):
        if padded_bytearray[i] != potential_missing_byte_num:
            return padded_bytearray

    return padded_bytearray[:-potential_missing_byte_num]
        
        

if __name__=="__main__":
#    target_plaintext = "YELLOW SUBMARINE"
    target_plaintext = "The quick brown fox jumps over the lazy dog" 
    target_bytearray = target_plaintext.encode("utf-8") 
    block_size = 20
    
    padded_target_bytearray = padder(target_bytearray, block_size)
    print("Target '{}' of length {} padded to a block size of {} results in '{}'".format(target_bytearray, len(target_bytearray), block_size, padded_target_bytearray))
    
    unpadded_target_bytearray = unpadder(padded_target_bytearray)
    print(unpadded_target_bytearray)
