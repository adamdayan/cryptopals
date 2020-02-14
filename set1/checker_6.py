from binascii import hexlify
from base64 import b64decode

def repeating_key_xor(intxt, key):
    outtxt = ""

    for i, c in enumerate(intxt):
        outtxt += chr(ord(c) ^ ord(key[i % len(key)]))

    return outtxt

def char_freq(chars):
    freq = 0
    most_freq_letters = 'etaoinhs'

    for c in chars:
        if c in most_freq_letters:
            freq += 1

    return freq

def repeating_key_xor(intxt, key):
    outtxt = ""

    for i, c in enumerate(intxt):
        outtxt += chr(ord(c) ^ ord(key[i % len(key)]))

    return outtxt


def hamming(s1, s2):
    dist = 0

    for c1, c2 in zip(s1, s2):
        diff = ord(c1) ^ ord(c2)
        dist += sum([1 for b in bin(diff) if b == '1'])

    return dist

def _best_key_lengths(data):
    avg_dist = []

    for ksize in range(2, 41):
        b1, b2, b3, b4 = data[:ksize], data[ksize:2 * ksize], \
        data[2 * ksize: 3 * ksize], data[3 * ksize:4 * ksize]
        dists, blocks = [], [b1, b2, b3, b4]

        for i in range(len(blocks) - 2):
            for j in range(i + 1, len(blocks) - 1):
                dists.append(hamming(blocks[i], blocks[j]) / float(ksize))

        avg_dist.append((sum(dists) / len(dists), ksize))

    return sorted(avg_dist)[:3]

def break_repeating_key(data):
    keylens = _best_key_lengths(data)
    best_freq, ptxt = 0, ''

    for _, keylen in keylens:
        key = ''
        blocks = [''] * keylen
        for i, c in enumerate(data):
            blocks[i % keylen] += c
        
        for block in blocks:
            key += chr(get_single_byte_key(block))

        txt = repeating_key_xor(data, key)
        cur_freq = char_freq(txt)

        if cur_freq > best_freq:
            best_freq = cur_freq
            ptxt = txt

        return ptxt




test_ciphertext = bytearray(b"\x1e\x0b\x00\'C\'(\x01\x07(\x04\x00i\x10\r&\x14\x00-C\x11!\x02\x11i7\r>\x02\x0c=\x06\x16nC\x06 \x13\r,\x11E>\x02\x16i\x06\x16:\x06\x0b=\n\x04%\x0f\x1ci\t\x10:\x17E(\r\n=\x0b\x00;C\x17,\x00\x17,\x02\x11 \x0c\x0bi\x0c\x03i\x17\r,C3 \x04\x00\'\x06\x17,C\x06 \x13\r,\x11Ii7\r>\x02\x0c=\x06\x16i\x13\x17,\x10\x00\'\x17\x00-C\x04i\x00\r(\x0f\t,\r\x02,C\x11&C\'(\x01\x07(\x04\x00sC\x02 \x15\x00\'C\x04\'C\n;\n\x02 \r\x04%C\x11,\x1b\x11iK\x03;\x0c\x08i0\r(\x08\x00:\x13\x00(\x11\x00n\x10E\x1d\x0b\x00i7\x00$\x13\x00:\x17EsC$*\x17ExOE\x1a\x00\x00\'\x06E{JE(\r\x01i\n\x11:C\x00\'\x00\x0c9\x0b\x00;\x06\x01i\x15\x00;\x10\x0c&\rIi\x0b\x00i\x14\x04:C\x11&C\x03 \r\x01i\x17\r,C\x0e,\x1aE>\x0c\x17-\x10E=\x0b\x04=C1!\x14\x04 \x17\x00:C\r(\x07E<\x10\x00-C\x11&C\x00\'\x00\x0c9\x0b\x00;C\x11!\x06E&\x11\x0c.\n\x0b(\x0fE=\x06\x1d=ME")

enc_text = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

print(_best_key_lengths(enc_text))
