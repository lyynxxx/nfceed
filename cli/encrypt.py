#!/usr/bin/env python3

import sys
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(plaintext: str, password: str) -> str:
    # Generate salt and nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    # Derive key
    key = derive_key(password, salt)
    
    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    
    # Combine salt + nonce + ciphertext
    combined = salt + nonce + ciphertext
    
    # Base64 encode
    return base64.b64encode(combined).decode('utf-8')

def main():
    # Check if input is from file or command line
    if len(sys.argv) < 2:
        print("Usage: ./encrypt.py <text_to_encrypt> <password>")
        print("       ./encrypt.py -f <filename> <password>")
        sys.exit(1)
    
    if sys.argv[1] == '-f':
        if len(sys.argv) != 4:
            print("Usage: ./encrypt.py -f <filename> <password>")
            sys.exit(1)
        
        filename = sys.argv[2]
        password = sys.argv[3]
        
        try:
            with open(filename, 'r') as f:
                plaintext = f.read()
        except Exception as e:
            print(f"Error reading file: {str(e)}", file=sys.stderr)
            sys.exit(1)
    else:
        plaintext = sys.argv[1]
        password = sys.argv[2]
    
    try:
        encrypted = encrypt_data(plaintext, password)
        print(encrypted)
    except Exception as e:
        print(f"Error encrypting data: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()

