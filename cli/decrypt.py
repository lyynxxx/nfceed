#!/usr/bin/env python3

import sys
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

def decrypt_data(encrypted_data: str, password: str) -> str:
    # Decode the base64 data
    combined = base64.b64decode(encrypted_data)
    
    # Extract the components
    salt = combined[:16]
    nonce = combined[16:28]
    ciphertext = combined[28:]
    
    # Derive the key
    key = derive_key(password, salt)
    
    # Decrypt
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode('utf-8')

def main():
    if len(sys.argv) != 3:
        print("Usage: ./decrypt.py <encrypted_data> <password>")
        sys.exit(1)
    
    encrypted_data = sys.argv[1]
    password = sys.argv[2]
    
    try:
        decrypted = decrypt_data(encrypted_data, password)
        print(decrypted)
    except Exception as e:
        print(f"Error decrypting data: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()

