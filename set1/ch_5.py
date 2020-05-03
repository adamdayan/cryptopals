from set1.ch_2 import xor


def repeating_xor(target, key):
    output = bytearray(len(target))
    for i in range(len(target)):
        output[i] = target[i] ^ key[i % len(key)]

    return output

def encrypt_with_repeating_xor(target, key):
    print("Encrypting plaintext {} with key {}".format(target, key)) 
    encrypted_text = repeating_xor(target.encode("utf-8"), key.encode("utf-8"))
    print("Encrypted bytes: {}".format(encrypted_text))

    return encrypted_text

if __name__=="__main__":
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"

    ciphertext = encrypt_with_repeating_xor(plaintext, key)
    print(ciphertext)
    print(ciphertext.decode("utf-8"))
    print(ciphertext.hex())
    ciphertext = ciphertext.hex()
    ans = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    if ans == ciphertext:
        print("Success!")
    else:
        print("Failure :(")
