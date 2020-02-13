from ch_2 import xor


def repeating_xor(target, key):
    output = bytearray(len(target))
    for i in range(len(target)):
        output[i] = target[i] ^ key[i % len(key)]

    return output

def encrypt_with_repeating_xor(target, key):
    print("Encrypting plaintext {} with key {}".format(target, key)) 
    encrypted_text = repeating_xor(target.encode("utf-8"), key.encode("utf-8")).hex()
    print("Encrypted text: {}".format(encrypted_text))

if __name__=="__main__":
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"

    encrypt_with_repeating_xor(plaintext, key)
