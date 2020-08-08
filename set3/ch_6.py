import time 
import random 
import math 

from ch_5 import MersenneTwister

def random_waiter():
    wait_time = random.randint(40, 1000)
    print("Sleeping for {} seconds".format(wait_time))
    time.sleep(wait_time)

def generate_random_mt_output():
    twister = MersenneTwister()
    random_waiter()
    seed = int(time.time())
    twister.seed_mt(seed)
    random_waiter()
    return twister.extract_number(), seed

def crack_mt_seed(output):
    output_received_time = math.floor(time.time())
    seed_time_lower_bound = output_received_time - 2000 - 1
    seed_time_upper_bound = output_received_time - 40 + 1
    print("Seed Time Upper Bound: {} Seed Time Lower Bound: {}".format(seed_time_upper_bound, seed_time_lower_bound))

    for i in range(seed_time_lower_bound, seed_time_upper_bound):
        mt = MersenneTwister()
        mt.seed_mt(i)
        if mt.extract_number() == output:
            return i

    raise Exception("Matching seed not found!")


if __name__=="__main__":
    output, seed = generate_random_mt_output()
    cracked_seed = crack_mt_seed(output)

    assert cracked_seed == seed, "Seeds do not match! Cracking failed."
    print("Cracked Seed: {} True Seed: {}".format(cracked_seed, seed))
