import os
import struct
import base64
import io
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
CORS(app, origins=["https://steganography-tool-wars.onrender.com"])
def encrypt_message(message, password):
    
    salt = os.urandom(16)
    
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    
    
    token = f.encrypt(message.encode())
    
    
    return salt + token

def decrypt_message(encrypted_data, password):
    try:
       
        salt = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        
        return f.decrypt(ciphertext).decode()
    except Exception:
        return None


def data_to_bits(data_bytes):
    """Yields bits from bytes one by one"""
    for byte in data_bytes:
        for i in range(8):
            yield (byte >> (7 - i)) & 1

@app.route('/hide', methods=['POST'])
def hide_data():
    try:
       
        image_file = request.files['image']
        message = request.form.get('message', '')
        password = request.form.get('password', '')
        

        full_encrypted_bytes = encrypt_message(message, password)
        
       
        data_len = len(full_encrypted_bytes)
       
        len_prefix = struct.pack('>I', data_len) 
        
        final_data = len_prefix + full_encrypted_bytes
        
        img = Image.open(image_file).convert("RGB")
        width, height = img.size
        
        
        if len(final_data) * 8 > width * height:
             return jsonify({"error": "Image too small for this message"}), 400
             
        pixels = img.load()
        
        
        bit_generator = data_to_bits(final_data)
        
        try:
            for y in range(height):
                for x in range(width):
                    r, g, b = pixels[x, y]
                    
                    
                    
                    bit = next(bit_generator)
                    
                    
                    new_r = (r & ~1) | bit
                    pixels[x, y] = (new_r, g, b)
                    
        except StopIteration:
            pass 

        byte_io = io.BytesIO()
        img.save(byte_io, 'PNG')
        byte_io.seek(0)
        return send_file(byte_io, mimetype='image/png')

    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500

@app.route('/reveal', methods=['POST'])
def reveal_data():
    try:
        
        image_file = request.files['image']
        password = request.form.get('password', '')
        
        img = Image.open(image_file).convert("RGB")
        pixels = img.load()
        width, height = img.size
        
        extracted_bits = []
        bit_count = 0
        
        length_bits = []
        
        iterator = (pixels[x,y][0] & 1 for y in range(height) for x in range(width))
        
        
        for _ in range(32):
            length_bits.append(str(next(iterator)))
            
        data_length = int("".join(length_bits), 2)
        
        
        data_bits = []
        for _ in range(data_length * 8):
            data_bits.append(str(next(iterator)))
            
        
        data_str = "".join(data_bits)
        data_bytes = bytearray()
        for i in range(0, len(data_str), 8):
            byte = data_str[i:i+8]
            data_bytes.append(int(byte, 2))
            
        
        decrypted_msg = decrypt_message(bytes(data_bytes), password)
        
        if decrypted_msg is None:
             return jsonify({"error": "Wrong Password or Corrupted Data"}), 403
             
        return jsonify({"message": decrypted_msg})

    except StopIteration:
         return jsonify({"error": "No hidden data found (or header corrupted)"}), 400
    except Exception as e:
        print(e)
        return jsonify({"error": "Processing Error"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)