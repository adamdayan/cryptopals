import sys
import math

def xor(a, b):
	return bytearray([a ^ b for a, b in zip(a, b)]) 

if __name__=="__main__":
    input_hex = "1c0111001f010100061a024b53535009181c"
    xor_hex = "686974207468652062756c6c277320657965"

    print("XORing {} with {}".format(input_hex, xor_hex))

    input_bytes = bytes.fromhex(input_hex)
    xor_bytes = bytes.fromhex(xor_hex)

    print("Input in bytes: {}".format(input_bytes))
    print("XOR in bytes: {}".format(xor_bytes))

    result = xor(input_bytes, xor_bytes) 

    print("Result: {}".format(result))
    print("English result: {}".format(result.decode("utf-8")))
    print("Hex result: {}".format(result.hex()))





