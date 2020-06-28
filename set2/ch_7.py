def unpadder(padded_bytearr):
    potential_padding_len = padded_bytearr[-1]

    for i in reversed(range(len(padded_bytearr) - potential_padding_len, len(padded_bytearr), 1)):
        if padded_bytearr[i] != potential_padding_len:
            raise Exception("Invalid padding!")

    return padded_bytearr[:-potential_padding_len]


if __name__=="__main__":
    
    test_string = "ICE ICE BABY"
    test_correct_bytearr = test_string.encode("utf-8") + bytearray([4] * 4)
    test_incorrect_bytearr = test_string.encode("utf-8") + bytearray([5] * 4)
    test_incorrect_bytearr_2 = test_string.encode("utf-8") + bytearray([1, 2, 3, 4])

    unpadded_test_correct_bytearr = unpadder(test_correct_bytearr)
    assert unpadded_test_correct_bytearr == "ICE ICE BABY".encode("utf-8"), "Incorrectly unpadded!"

    try:
        unpadded_test_incorrect_bytearr = unpadder(test_incorrect_bytearr)
        print("Failed to detect invalid padding")
    except:
        print("Correctly detected invalid padding")
    
    try:
        unpadded_test_incorrect_bytearr = unpadder(test_incorrect_bytearr_2)
        print("Failed to detect invalid padding")
    except:
        print("Correctly detected invalid padding")
 
