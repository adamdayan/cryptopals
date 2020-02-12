import base64

hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

print("Input string: {}".format(hex_string))

hex_in_bytes = bytes.fromhex(hex_string)

print("In bytes: {}".format(hex_in_bytes))

hex_in_b64 = base64.b64encode(hex_in_bytes)

print("In b64: {}".format(hex_in_b64))


