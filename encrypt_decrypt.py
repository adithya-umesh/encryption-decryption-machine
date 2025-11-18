# ROT13 -> SHIFT EVERY ALPHABET BY 13 ALPHABETS. Example: A becomes N, B becomes O


def encrypt(password):
    encrypted = ""
    for character in password:
        encrypted_char = chr(ord(character) + 13)
        encrypted += encrypted_char

    return encrypted

def decrypt(password):
    decrypted = ""
    for character in password:
        decrypted_char = chr(ord(character) - 13)
        decrypted += decrypted_char

    return decrypted

password = input("Enter a password: ")
print(f"Encrypted password: {encrypt(password)}")
encrypted_password = encrypt(password)
# print(f"Decrypted password: {decrypt(encrypted_password)}")