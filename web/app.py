from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)

# Define NFC tag capacities (in bytes)
NFC_TAGS = {
    'NTAG213': 144,
    'NTAG215': 504,
    'NTAG216': 888
}

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

@app.route('/')
def index():
    return render_template('index.html', tags=NFC_TAGS)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.json
        text = data['text']
        password = data['password']
        tag_type = data['tagType']
        
        if tag_type not in NFC_TAGS:
            return jsonify({'error': 'Invalid tag type'}), 400
        
        # Generate salt and nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # Derive key from password
        key = derive_key(password, salt)
        
        # Encrypt the data
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, text.encode(), None)
        
        # Combine salt, nonce, and ciphertext for storage
        combined = salt + nonce + ciphertext
        
        # Check if the encrypted data fits in the selected tag
        if len(combined) > NFC_TAGS[tag_type]:
            return jsonify({
                'error': f'Encrypted data size ({len(combined)} bytes) exceeds {tag_type} capacity ({NFC_TAGS[tag_type]} bytes)'
            }), 400
        
        # Convert to base64 for easy handling
        encoded = base64.b64encode(combined).decode('utf-8')
        
        return jsonify({
            'encrypted': encoded,
            'length': len(combined)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        encrypted_text = data['encryptedText']
        password = data['password']
        
        # Decode the base64 data
        try:
            combined = base64.b64decode(encrypted_text)
        except:
            return jsonify({'error': 'Invalid encrypted data format'}), 400
        
        # Extract salt, nonce, and ciphertext
        if len(combined) < 28:  # Minimum length: salt(16) + nonce(12)
            return jsonify({'error': 'Invalid encrypted data length'}), 400
            
        salt = combined[:16]
        nonce = combined[16:28]
        ciphertext = combined[28:]
        
        # Derive key from password
        try:
            key = derive_key(password, salt)
        except:
            return jsonify({'error': 'Error deriving key'}), 400
        
        # Decrypt the data
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return jsonify({
                'decrypted': plaintext.decode('utf-8')
            })
        except:
            return jsonify({'error': 'Decryption failed. Invalid password or corrupted data'}), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)

