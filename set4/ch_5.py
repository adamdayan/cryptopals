import time
import math
from set4.ch_4 import hash_sha1

def time_hash_sha1(message):
    start = time.time()
    hashed_message = hash_sha1(message)
    stop = time.time()
    return stop - start


def guess_key_length(key, message):
    actual_hash_time = time_hash_sha1(key+message)
    results = {}
    rounds = 30
    for i in range(rounds):
        for guessed_key_len in range(512):
            guessed_key = bytearray([65] * guessed_key_len)
            results[i] = results.get(i, 0) + time_hash_sha1(guessed_key+message)
    results = {guessed_key_len  : results[guessed_key_len] / rounds for guessed_key_len in results}

    return min(results, key=lambda guessed_key_len:abs(results[guessed_key_len] - actual_hash_time)) 


if __name__=="__main__":
    key = "YELLOW SUBMARINE".encode("ascii")
    message= "the quick brown fox jumps over the lazy dog".encode("ascii")
    actual_key_len = len(key)

    guessed_key_len = guess_key_length(key, message)
    assert guessed_key_len == actual_key_len, "failed to guess key length! {} != {}".format(guessed_key_len, actual_key_len)
