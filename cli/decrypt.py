#!/bin/bash

# Usage function
usage() {
    echo "Usage: $0 <base64_encrypted_data> <password>"
    exit 1
}

# Check arguments
if [ "$#" -ne 2 ]; then
    usage
fi

encrypted_data="$1"
password="$2"

# Create a temporary directory with secure permissions
tempdir=$(mktemp -d)
chmod 700 "$tempdir"
cd "$tempdir"

# Decode base64 data
echo "$encrypted_data" | base64 -d > combined.bin

# Extract components (salt: 16 bytes, nonce: 12 bytes, rest is ciphertext)
dd if=combined.bin of=salt.bin bs=16 count=1 2>/dev/null
dd if=combined.bin of=nonce.bin bs=16 skip=1 count=1 2>/dev/null
dd if=combined.bin of=ciphertext.bin bs=28 skip=1 2>/dev/null

# Derive key using PBKDF2 (100000 iterations)
openssl pkeyutl -derive \
    -kdf pbkdf2 \
    -kdflen 32 \
    -pkeyopt digest:sha256 \
    -pkeyopt iterations:100000 \
    -pkeyopt pass:"$password" \
    -pkeyopt salt:"$(xxd -p -c 32 salt.bin)" \
    -out key.bin

# Decrypt using AES-256-GCM
openssl enc -aes-256-gcm \
    -d \
    -in ciphertext.bin \
    -K "$(xxd -p -c 64 key.bin)" \
    -iv "$(xxd -p -c 24 nonce.bin)" \
    -out decrypted.txt

# Output decrypted data
cat decrypted.txt

# Clean up
cd - >/dev/null
rm -rf "$tempdir"

