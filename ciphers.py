import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import numpy as np
import json
import math
from typing import Union, Dict, List, Any
import os
import base64

# 
# 
# Helper functions
def create_playfair_matrix(key):
    matrix = []
    key = ''.join(dict.fromkeys(key.upper().replace('J', 'I')))
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    matrix_chars = key + ''.join([c for c in alphabet if c not in key])
    return [list(matrix_chars[i:i+5]) for i in range(0, 25, 5)]

# Historical Ciphers
def caesar_encrypt(data, shift):
    return ''.join(chr((ord(char) - 65 + shift) % 26 + 65) if char.isalpha() else char for char in data)

def caesar_decrypt(data, shift):
    return ''.join(chr((ord(char) - 65 - shift) % 26 + 65) if char.isalpha() else char for char in data)

def monoalphabetic_encrypt(data, key_map):
    return ''.join(key_map.get(c.upper(), c) for c in data)

def monoalphabetic_decrypt(data, key_map):
    rev_map = {v: k for k, v in key_map.items()}
    return ''.join(rev_map.get(c.upper(), c) for c in data)

def homophonic_encrypt(data, key_map):
    return ''.join(random.choice(key_map[c.upper()]) if c.upper() in key_map else c for c in data)

def homophonic_decrypt(data, key_map):
    rev_map = {v: k for k, values in key_map.items() for v in values}
    return ''.join(rev_map.get(c, c) for c in data)

def playfair_encrypt(data, key):
    matrix = create_playfair_matrix(key)
    data = ''.join(c for c in data.upper().replace('J', 'I') if c.isalpha())
    if len(data) % 2:
        data += 'X'
    result = ''
    for i in range(0, len(data), 2):
        char1, char2 = data[i], data[i+1]
        row1, col1 = next((r, c) for r in range(5) for c in range(5) if matrix[r][c] == char1)
        row2, col2 = next((r, c) for r in range(5) for c in range(5) if matrix[r][c] == char2)
        if row1 == row2:
            result += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
        elif col1 == col2:
            result += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
        else:
            result += matrix[row1][col2] + matrix[row2][col1]
    return result

def playfair_decrypt(data, key):
    matrix = create_playfair_matrix(key)
    result = ''
    for i in range(0, len(data), 2):
        char1, char2 = data[i], data[i+1]
        row1, col1 = next((r, c) for r in range(5) for c in range(5) if matrix[r][c] == char1)
        row2, col2 = next((r, c) for r in range(5) for c in range(5) if matrix[r][c] == char2)
        if row1 == row2:
            result += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
        elif col1 == col2:
            result += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
        else:
            result += matrix[row1][col2] + matrix[row2][col1]
    return result

def vigenere_encrypt(data, key):
    key = key.upper()
    return ''.join(chr((ord(c) + ord(key[i % len(key)]) - 2*65) % 26 + 65) 
                  for i, c in enumerate(data.upper()) if c.isalpha())

def vigenere_decrypt(data, key):
    key = key.upper()
    return ''.join(chr((ord(c) - ord(key[i % len(key)]) + 26) % 26 + 65) 
                  for i, c in enumerate(data.upper()) if c.isalpha())

def autokey_encrypt(data, key):
    key = key.upper()
    keystream = key + ''.join(c for c in data.upper() if c.isalpha())
    return ''.join(chr((ord(c) + ord(keystream[i]) - 2*65) % 26 + 65) 
                  for i, c in enumerate(data.upper()) if c.isalpha())

def autokey_decrypt(data, key):
    key = key.upper()
    plaintext = ''
    keystream = key
    for i, c in enumerate(data.upper()):
        if c.isalpha():
            dec = chr((ord(c) - ord(keystream[i]) + 26) % 26 + 65)
            plaintext += dec
            keystream += dec
    return plaintext

def rail_fence_encrypt(data, rails):
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    
    for char in data:
        fence[rail].append(char)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
            
    return ''.join([''.join(rail) for rail in fence])

def rail_fence_decrypt(data, rails):
    fence = [[''] * len(data) for _ in range(rails)]
    rail = 0
    direction = 1
    
    # Mark the positions in the fence pattern
    for i in range(len(data)):
        fence[rail][i] = '*'
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
    
    # Fill the marked positions with the encrypted text
    index = 0
    for i in range(rails):
        for j in range(len(data)):
            if fence[i][j] == '*':
                fence[i][j] = data[index]
                index += 1
    
    # Read off the decrypted text
    result = ''
    rail = 0
    direction = 1
    for i in range(len(data)):
        result += fence[rail][i]
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
    
    return result

def columnar_encrypt(data, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    cols = [''] * len(key)
    col = 0
    
    for char in data:
        cols[col] += char
        col = (col + 1) % len(key)
        
    return ''.join(cols[i] for i in key_order)

def columnar_decrypt(data, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    col_length = math.ceil(len(data) / len(key))
    cols = [''] * len(key)
    
    # Split data into columns
    position = 0
    for i in key_order:
        remaining = len(data) - position
        col_len = min(col_length, remaining)
        cols[i] = data[position:position + col_len]
        position += col_len
    
    # Read off row by row
    result = ''
    for i in range(col_length):
        for col in cols:
            if i < len(col):
                result += col[i]
                
    return result

def affine_encrypt(data: str, a: int, b: int) -> str:
    if math.gcd(a, 26) != 1:
        raise ValueError("Parameter 'a' must be coprime with 26")
    return ''.join(chr((a * (ord(c) - 65) + b) % 26 + 65) if c.isalpha() 
                  else c for c in data.upper())

def hill_encrypt(data, key_matrix):
    # Convert text to numbers (A=0, B=1, etc.)
    nums = [ord(c) - 65 for c in data.upper() if c.isalpha()]
    # Pad if necessary
    while len(nums) % len(key_matrix) != 0:
        nums.append(0)
    
    result = ''
    # Process in blocks
    for i in range(0, len(nums), len(key_matrix)):
        block = nums[i:i + len(key_matrix)]
        encrypted = np.dot(key_matrix, block) % 26
        result += ''.join(chr(n + 65) for n in encrypted)
    
    return result

def hill_decrypt(data, key_matrix):
    # Find modular multiplicative inverse of determinant
    det = int(round(np.linalg.det(key_matrix)))
    det_inv = pow(det % 26, -1, 26)
    
    # Calculate adjugate matrix
    adj = np.round(det * np.linalg.inv(key_matrix)).astype(int)
    
    # Calculate inverse key matrix
    inv_key = (det_inv * adj % 26)
    
    # Convert text to numbers
    nums = [ord(c) - 65 for c in data.upper() if c.isalpha()]
    
    result = ''
    # Process in blocks
    for i in range(0, len(nums), len(inv_key)):
        block = nums[i:i + len(inv_key)]
        decrypted = np.dot(inv_key, block) % 26
        result += ''.join(chr(n + 65) for n in decrypted)
    
    return result

def affine_decrypt(data: str, a: int, b: int) -> str:
    if math.gcd(a, 26) != 1:
        raise ValueError("Parameter 'a' must be coprime with 26")
    a_inv = pow(a, -1, 26)
    return ''.join(chr((a_inv * (ord(c) - 65 - b)) % 26 + 65) if c.isalpha() 
                  else c for c in data.upper())

# Modern Symmetric Ciphers
def aes_encrypt(data, key):
    # Add PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(data, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def des_encrypt(data, key, mode=modes.CBC):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.DES(key), mode(iv))
    encryptor = cipher.encryptor()
    return {'iv': iv, 'data': encryptor.update(data) + encryptor.finalize()}

def des_decrypt(data, key, mode=modes.CBC):
    cipher = Cipher(algorithms.DES(key), mode(data['iv']))
    decryptor = cipher.decryptor()
    return decryptor.update(data['data']) + decryptor.finalize()

def triple_des_encrypt(data, key, mode=modes.CBC):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), mode(iv))
    encryptor = cipher.encryptor()
    return {'iv': iv, 'data': encryptor.update(data) + encryptor.finalize()}

def triple_des_decrypt(data, key, mode=modes.CBC):
    cipher = Cipher(algorithms.TripleDES(key), mode(data['iv']))
    decryptor = cipher.decryptor()
    return decryptor.update(data['data']) + decryptor.finalize()

def blowfish_encrypt(data, key, mode=modes.CBC):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(key), mode(iv))
    encryptor = cipher.encryptor()
    return {'iv': iv, 'data': encryptor.update(data) + encryptor.finalize()}

def blowfish_decrypt(data, key, mode=modes.CBC):
    cipher = Cipher(algorithms.Blowfish(key), mode(data['iv']))
    decryptor = cipher.decryptor()
    return decryptor.update(data['data']) + decryptor.finalize()

def rc4_encrypt(data, key):
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    cipher = Cipher(algorithms.ARC4(key), None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def rc4_decrypt(data, key):
    result = rc4_encrypt(data, key)  # RC4 is symmetric
    return result if isinstance(data, bytes) else result.decode()

def unpad_data(padded_data: bytes) -> bytes:
    """Remove PKCS7 padding from data"""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

"""
Encryption Implementation Module

Features:
Historical Ciphers:
- Caesar, Playfair, Vigenère
- Monoalphabetic substitution
- Homophonic substitution
- Rail fence and columnar transposition

Modern Ciphers:
- AES (256-bit keys)
- DES and Triple DES
- Blowfish
- RC4 stream cipher

Security Features:
- HMAC authentication
- PKCS7 padding
- IV management
- Key derivation
"""

class SecureMessage:
    """
    Unified encryption interface for all supported ciphers.
    
    Features:
    - Cipher selection and initialization
    - Message encryption/decryption
    - Authentication (HMAC)
    - Error handling
    """
    SUPPORTED_CIPHERS = {
        'CAESAR': (caesar_encrypt, caesar_decrypt),
        'MONOALPHABETIC': (monoalphabetic_encrypt, monoalphabetic_decrypt),
        'PLAYFAIR': (playfair_encrypt, playfair_decrypt),
        'VIGENERE': (vigenere_encrypt, vigenere_decrypt),
        'DES': (des_encrypt, des_decrypt),
        'AES': (aes_encrypt, aes_decrypt),
        'BLOWFISH': (blowfish_encrypt, blowfish_decrypt),
        'RC4': (rc4_encrypt, rc4_decrypt)
    }

    def __init__(self, cipher_type: str, key: Union[str, bytes]):
        if cipher_type not in self.SUPPORTED_CIPHERS:
            raise ValueError(f"Unsupported cipher type: {cipher_type}")
        self.cipher_type = cipher_type
        self.key = key

    def encrypt(self, message: Union[str, bytes]) -> dict:
        try:
            encryption_methods = {
                'CAESAR': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m, int.from_bytes(self.key[:1], 'big')),
                'MONOALPHABETIC': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m, self.key),
                'PLAYFAIR': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m, self.key),
                'VIGENERE': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m, self.key),
                'DES': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m if isinstance(m, bytes) else m.encode(), self.key),
                'AES': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m if isinstance(m, bytes) else m.encode(), self.key),
                'BLOWFISH': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m if isinstance(m, bytes) else m.encode(), self.key),
                'RC4': lambda m: self.SUPPORTED_CIPHERS[self.cipher_type][0](m if isinstance(m, bytes) else m.encode(), self.key)
            }
            
            encrypted = encryption_methods[self.cipher_type](message)
            
            key_bytes = self.key if isinstance(self.key, bytes) else self.key.encode()
            h = hmac.HMAC(key_bytes, hashes.SHA256())
            h.update(encrypted if isinstance(encrypted, bytes) else encrypted.encode())
            mac = h.finalize()
            
            return {
                'cipher': self.cipher_type,
                'data': encrypted,
                'mac': mac
            }
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {str(e)}")

    def decrypt(self, secure_message: dict) -> str:
        try:
            if not all(k in secure_message for k in ['cipher', 'data', 'mac']):
                raise ValueError("Invalid secure message format")
            
            # Convert base64 encoded data back to bytes
            if isinstance(secure_message['data'], str):
                secure_message['data'] = base64.b64decode(secure_message['data'])
            if isinstance(secure_message['mac'], str):
                secure_message['mac'] = base64.b64decode(secure_message['mac'])
                
            # Verify HMAC
            key_bytes = self.key if isinstance(self.key, bytes) else self.key.encode()
            h = hmac.HMAC(key_bytes, hashes.SHA256())
            h.update(secure_message['data'])
            try:
                h.verify(secure_message['mac'])
            except Exception:
                raise ValueError("Message authentication failed")
                
            # Decrypt the data
            decryption_methods = {
                'CAESAR': lambda d: caesar_decrypt(d, int.from_bytes(self.key[:1], 'big')),
                'MONOALPHABETIC': lambda d: monoalphabetic_decrypt(d, self.key),
                'PLAYFAIR': lambda d: playfair_decrypt(d, self.key),
                'VIGENERE': lambda d: vigenere_decrypt(d, self.key),
                'DES': lambda d: des_decrypt(d, self.key),
                'AES': lambda d: aes_decrypt(d, self.key),
                'BLOWFISH': lambda d: blowfish_decrypt(d, self.key),
                'RC4': lambda d: rc4_decrypt(d, self.key)
            }
            
            decrypted = decryption_methods[secure_message['cipher']](secure_message['data'])
            
            # Handle bytes vs string output
            if isinstance(decrypted, bytes):
                return unpad_data(decrypted).decode()
            return decrypted
            
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {str(e)}")
