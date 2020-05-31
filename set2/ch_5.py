import random
from set2.ch_1 import padder, unpadder
from set2.ch_3 import gen_random_key 

from Crypto.Cipher import AES

def parse_cookie(cookie_string):
    kv_list = cookie_string.split("&")
    cookie_dict = {}
    for kv in kv_list:
        key, value = tuple(kv.split("="))
        if value.isnumeric():
            value = int(value)

        cookie_dict[key] = value

    return cookie_dict

def encode(target_dict):
    encoded_dict = ""
    for key, value in target_dict.items():
        encoded_kv = str(key) + "=" + str(value) + "&"
        encoded_dict += encoded_kv

    return encoded_dict[:-1]

def profile_for(email):
    email = email.replace("&", "")
    email = email.replace("=", "")
    profile_dict = {
        "email" : email, 
        "uid" : 10,
        "role" : "user" 
    }

    encoded_profile = encode(profile_dict)

    return encoded_profile

def generate_encrypted_profile(email, key):
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    profile = profile_for(email)
    profile_bytearr = profile.encode("utf-8")
    padded_profile_bytearr = padder(profile_bytearr, len(key))
    ciphertext = cipher.encrypt(bytes(padded_profile_bytearr))
    return ciphertext

def decrypt_profile(ciphertext, key):
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    decrypted_cookie = unpadder(cipher.decrypt(ciphertext))
    decrypted_profile = parse_cookie(decrypted_cookie.decode("utf-8"))
    return decrypted_profile

def find_keysize(key):
    test_len = 1 
    last_encrypted_len = len(generate_encrypted_profile(test_len * "a", key)) 
    for i in range(512): 
        test_email = test_len * "a"
        test_encrypted_profile = generate_encrypted_profile(test_email, key)
        cur_encrypted_len = len(test_encrypted_profile)
        if cur_encrypted_len != last_encrypted_len:
            return cur_encrypted_len - last_encrypted_len 
        else:
            last_encrypted_len = cur_encrypted_len 
            test_len += 1

    raise Exception("Failed to find keysize")

def generate_valid_admin_ciphertext(key):
    email_prefix = "a" * (16 - len("email="))
    email_admin = "admin" + (chr(11) * 11)
    email_admin_ciphertext = generate_encrypted_profile(email_prefix + email_admin, key)
    return email_admin_ciphertext[16:32]

def compute_email_length(keysize):
    for email_len in range(keysize):
        pre_role = len("email=") + email_len + len("&uid=10&role=")
        if pre_role % keysize == 0:
            return email_len, pre_role

def attack_ecb_integrity(key):
    keysize = find_keysize(key)
    admin_ciphertext = generate_valid_admin_ciphertext(key) 
    
    email_len, pre_role = compute_email_length(keysize)
    unaltered_ciphertext = generate_encrypted_profile("a" * email_len, key) 
    altered_ciphertext = unaltered_ciphertext[:pre_role] + admin_ciphertext 
    
    return altered_ciphertext 

if __name__=="__main__":
    test_cookie = "foo=bar&baz=qux&zap=zazzle"
    parsed_test_cookie = parse_cookie(test_cookie)
    correct_parsed_test_cookie = {
        "foo" : "bar", 
        "baz" : "qux", 
        "zap" : "zazzle"
    }

    print("parsed_cookie: ", parsed_test_cookie)
    assert parsed_test_cookie == correct_parsed_test_cookie, "cookie has not been correctly parsed"
    
    test_encoded_profile = profile_for("foo@bar.com")
    print(test_encoded_profile)

    key = gen_random_key(16)
    test_encrypted_profile = generate_encrypted_profile("ed@wikileaks.com", key)
    print(test_encrypted_profile)
    test_decrypted_profile = decrypt_profile(test_encrypted_profile, key)
    print(test_decrypted_profile)

    test_keysize = find_keysize(key)
    print("keysize: ", test_keysize)
    assert test_keysize == len(key), "keysize has not been accurately found"
    

    print("Attack ECB integrity")
    altered_ciphertext = attack_ecb_integrity(key)
    decrypted_altered_ciphertext = decrypt_profile(altered_ciphertext, key)
    print(decrypted_altered_ciphertext)
