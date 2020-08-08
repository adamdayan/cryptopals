from ch_5 import MersenneTwister

def invert_right(a, shift):
    c = a >> shift
    b = a ^ c

    return b

def invert_left(a, shift, bitmask):
    for i in range(2**32):
        output = i ^ ((i << shift) & bitmask)
        if output == a:
            return i


def invert_left(a, shift, bitmask):
    b = a * (2**shift - 1)
    uncovered = shift
    while uncovered < 32:
        c = b << shift
        b = (a & (2 ** (uncovered + shift)- 1)) ^ (c & bitmask)
        uncovered += shift 

    return b & ((2 ** 32) - 1)
        
def invert_output(output):
    s = 7
    b = int("9D2C5680", 16)
    t = 15
    c = int("EFC60000", 16)
    l = 18
    u = 11
    
    y = invert_right(output, l)
    y = invert_left(y, t, c)
    y = invert_left(y, s, b)
    y = invert_right(y, u) 

    return y

def total_mt_tap(seed):
    mt = MersenneTwister()
    mt.seed_mt(12345)

    return [mt.extract_number() for _ in range(624)]

def invert_mt_outputs(outputs):
    inverted_outputs = [invert_output(o) for o in outputs]
    return MersenneTwister.from_state(inverted_outputs)

if __name__=="__main__":
    outputs = total_mt_tap(1234)
    copied_mt = invert_mt_outputs(outputs)
    for i in range(624):
        assert copied_mt.extract_number() != outputs[i], "copied MT does not match original MT!"

    print("Copied MT matched Original MT")
            
