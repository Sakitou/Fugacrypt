#!/usr/bin/env python

import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import secrets
import base64
import string

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    salt = os.urandom(16)
    key = generate_key(password, salt)
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(salt + iv + ciphertext)

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = generate_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_file, 'wb') as decrypted_file:
        decrypted_file.write(plaintext)

def generate_random_password(length, use_uppercase=True, use_letters=True, use_numbers=True, use_symbols=True):
    characters = ''
    if use_letters:
        characters += string.ascii_letters
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += "@~!#$%^*()-_=+"

    if not characters:
        print("Error: No character type selected.")
        return None

    if not (use_uppercase or use_letters or use_numbers or use_symbols):
        print("Error: No character type selected.")
        return None

    return ''.join(secrets.choice(characters) for _ in range(length))

def generate_password_help():
    print("""
Usage manual for the pwrd (Password Generator) function.

The password generator creates secure passwords.
Simply use the command "-pwrd {number of characters}".

You can use additional options (which can be combined). Here they are:

-s: include special characters (@ ~! # $ % ^ * ( ) - _ = +)
-nomaj: generate a password without uppercase letters
-nol: generate a password without letters
-nonum: generate a password without numbers

For more information, you can check the Wiki on my GitHub page
https://github.com/Sakitou/Fugacrypt/wiki/Password-Generator
""")

def main():
    parser = argparse.ArgumentParser(description='Fugacrypt - File Encryption with AES256')
    parser.add_argument('-e', '--encrypt', nargs=3, metavar=('input_file', 'output_file', 'password'),
                        help='Encrypt the file with AES256')
    parser.add_argument('-d', '--decrypt', nargs=3, metavar=('input_file', 'output_file', 'password'),
                        help='Decrypt the file with AES256')
    parser.add_argument('-key', '--generate_key', action='store_true',
                        help='Generate an AES256 key')
    parser.add_argument('-pwrd', '--generate_password', nargs='+', metavar=('length'), type=int,
                        help='Generate a random password of the specified length')
    parser.add_argument('-s', '--symbols', action='store_true',
                        help='Include special characters in the password')
    parser.add_argument('-nomaj', '--no_uppercase', action='store_true',
                        help='Generate a password without uppercase letters')
    parser.add_argument('-nol', '--no_letters', action='store_true',
                        help='Generate a password without letters')
    parser.add_argument('-nonum', '--no_numbers', action='store_true',
                        help='Generate a password without numbers')
    parser.add_argument('-github', '--github_redirect', action='store_true',
                        help='Redirect to https://github.com/Sakitou/Fugacrypt')
    parser.add_argument('-install', '--install_redirect', action='store_true',
                        help='Redirect to https://github.com/Sakitou/Fugacrypt/wiki/Installation')

    args = parser.parse_args()

    if args.encrypt:
        print("Encrypting...")
        encrypt_file(args.encrypt[0], args.encrypt[1], args.encrypt[2])
        print(f"Encrypted with AES256 to {args.encrypt[1]}")

    elif args.decrypt:
        print("Decrypting...")
        decrypt_file(args.decrypt[0], args.decrypt[1], args.decrypt[2])
        print(f"Decrypted to {args.decrypt[1]}")

    elif args.generate_key:
        print(f"AES256 key generated: {generate_aes_key()}")

    elif args.generate_password:
        length = args.generate_password[0]
        use_uppercase = not args.no_uppercase
        use_letters = not args.no_letters
        use_numbers = not args.no_numbers
        use_symbols = args.symbols
        generated_password = generate_random_password(length, use_uppercase, use_letters, use_numbers, use_symbols)
        if generated_password:
            print(f"Generated password: {generated_password}")

    elif args.github_redirect:
        print("Redirecting to https://github.com/Sakitou/Fugacrypt")

    elif args.install_redirect:
        print("Redirecting to https://github.com/Sakitou/Fugacrypt/wiki/Installation")

    else:
        print("No option specified. Use -h to see available options.")

if __name__ == "__main__":
    main()
