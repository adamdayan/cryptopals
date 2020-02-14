import string
import math
import ch_3 as sbk

def find_minimum_loss_with_single_byte_key(target_list, reference_frequency):
    cur_best_loss = math.inf
    cur_best_idx = -1
    cur_best_decrypt = ""

    for idx, target in enumerate(target_list):
        key, loss = sbk.compute_likely_key(bytes.fromhex(target), reference_frequency)
        if loss < cur_best_loss:
            cur_best_loss = loss 
            cur_best_idx = idx
            cur_best_decrypt = sbk.decrypt(
                bytes.fromhex(target)
                , key
            )

    return target_list[cur_best_idx], cur_best_decrypt, cur_best_loss


def find_single_byte_cipher_string(target_path, sample_text_path):
    with open(target_path, "r") as targ:
        target_list = targ.read().splitlines()

    with open(sample_text_path, "r") as txt:
        sample_text = txt.read()

    reference_frequency = sbk.compute_letter_freq(sample_text)

    single_byte_target, single_byte_decrypt, single_byte_loss = find_minimum_loss_with_single_byte_key(
        #[t for t in target_list.__reversed__()],
        target_list,
        reference_frequency
    )

    print("Single byte key encrypted string: {}".format(single_byte_target))
    print("Single byte key decrypted string: {}".format(single_byte_decrypt))

if __name__=="__main__":
    find_single_byte_cipher_string("data_ch_4.txt", "sample_text.txt")
