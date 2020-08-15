class MersenneTwister:
    w = 32
    n = 624
    m = 397
    r = 31
    a = int("9908B0DF", 16)
    u = 11
    s = 7
    b = int("9D2C5680", 16)
    t = 15
    c = int("EFC60000", 16)
    l = 18
    f = 1812433253

    def __init__(self):
        self.mt = [i for i in range(self.n)] #TODO: not sure initial values are correct
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (~self.lower_mask) & ((2**self.w)-1) # TODO: check this gets lowest bits - correct endianess? bitwise?? 

    @classmethod
    def from_state(cls, state):
        _mt = cls() 
        _mt.mt = state
        _mt.index = 0
        return _mt 


    def seed_mt(self, seed):
        self.index = self.n
        self.mt[0] = seed
        for i in range(1, self.n):
            self.mt[i] = (self.f * (self.mt[i-1] ^ (self.mt[i-1] >> (self.w - 2))) + i) & ((2**self.w) - 1)

    def extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator has not been seeded")
            self.twist()
        y = self.mt[self.index]
        y = y ^ (y >> self.u)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index+= 1
        return y & ((2**self.w) - 1)

    def twist(self):
        for i in range(self.n):
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i+1) % self.n] & self.lower_mask) #TODO: should this be bitwise concatenation
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xA
        self.index = 0


if __name__=="__main__":
    twister = MersenneTwister()
    twister.seed_mt(100)
    
    for i in range(30):
        print("random number {}: {}".format(i, twister.extract_number()))

