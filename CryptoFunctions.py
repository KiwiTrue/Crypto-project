# CryptoFunctions.py

from Crypto.Cipher import PKCS1_OAEP, AES, DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import string
import numpy as np

# Existing ciphers (Caesar and Vigenère)

def caesar_encrypt(message, shift):
    encrypted = ''
    for char in message:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(encrypted_message, shift):
    return caesar_encrypt(encrypted_message, -shift)

def vigenere_encrypt(message, key):
    encrypted = ''
    key_length = len(key)
    key_int = [ord(i.upper()) - 65 for i in key]
    for i, char in enumerate(message):
        if char.isalpha():
            shift = key_int[i % key_length]
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def vigenere_decrypt(encrypted_message, key):
    decrypted = ''
    key_length = len(key)
    key_int = [ord(i.upper()) - 65 for i in key]
    for i, char in enumerate(encrypted_message):
        if char.isalpha():
            shift = key_int[i % key_length]
            shift_base = 65 if char.isupper() else 97
            decrypted += chr((ord(char) - shift_base - shift + 26) % 26 + shift_base)
        else:
            decrypted += char
    return decrypted

# New cipher functions

def monoalphabetic_encrypt(message, key):
    alphabet = string.ascii_lowercase
    key_map = dict(zip(alphabet, key.lower()))
    encrypted = ''
    for char in message:
        if char.islower():
            encrypted += key_map.get(char, char)
        elif char.isupper():
            encrypted += key_map.get(char.lower(), char.lower()).upper()
        else:
            encrypted += char
    return encrypted

def monoalphabetic_decrypt(encrypted_message, key):
    alphabet = string.ascii_lowercase
    key_map = dict(zip(key.lower(), alphabet))
    decrypted = ''
    for char in encrypted_message:
        if char.islower():
            decrypted += key_map.get(char, char)
        elif char.isupper():
            decrypted += key_map.get(char.lower(), char.lower()).upper()
        else:
            decrypted += char
    return decrypted

def autokey_encrypt(message, key):
    encrypted = ''
    key = key + message
    key = key[:len(message)]
    for i in range(len(message)):
        if message[i].isalpha():
            m = ord(message[i].upper()) - 65
            k = ord(key[i].upper()) - 65
            encrypted_char = chr(((m + k) % 26) + 65)
            encrypted += encrypted_char if message[i].isupper() else encrypted_char.lower()
        else:
            encrypted += message[i]
    return encrypted

def autokey_decrypt(encrypted_message, key):
    decrypted = ''
    key = key.upper()
    for i in range(len(encrypted_message)):
        if encrypted_message[i].isalpha():
            e = ord(encrypted_message[i].upper()) - 65
            k = ord(key[i].upper()) - 65 if i < len(key) else ord(decrypted[i - len(key)].upper()) - 65
            decrypted_char = chr(((e - k + 26) % 26) + 65)
            decrypted += decrypted_char if encrypted_message[i].isupper() else decrypted_char.lower()
            key += decrypted_char
        else:
            decrypted += encrypted_message[i]
    return decrypted

def rail_fence_encrypt(message, num_rails):
    fence = [''] * num_rails
    rail = 0
    var = 1
    for char in message:
        fence[rail] += char
        rail += var
        if rail == 0 or rail == num_rails - 1:
            var = -var
    encrypted = ''.join(fence)
    return encrypted

def rail_fence_decrypt(encrypted_message, num_rails):
    pattern = get_rail_pattern(len(encrypted_message), num_rails)
    rails = [''] * num_rails
    index = 0
    for i in range(num_rails):
        for j in range(len(pattern)):
            if pattern[j] == i:
                rails[i] += encrypted_message[index]
                index += 1
    result = ''
    indices = [0] * num_rails
    for rail in pattern:
        result += rails[rail][indices[rail]]
        indices[rail] += 1
    return result

def get_rail_pattern(length, num_rails):
    pattern = []
    rail = 0
    var = 1
    for _ in range(length):
        pattern.append(rail)
        rail += var
        if rail == 0 or rail == num_rails - 1:
            var = -var
    return pattern

def columnar_transposition_encrypt(message, key):
    num_columns = len(key)
    num_rows = len(message) // num_columns + (len(message) % num_columns > 0)
    fill_char = '_'
    padding = fill_char * ((num_columns * num_rows) - len(message))
    message += padding
    matrix = [list(message[i:i+num_columns]) for i in range(0, len(message), num_columns)]
    key_order = sorted([(char, i) for i, char in enumerate(key)])
    encrypted = ''
    for _, index in key_order:
        for row in matrix:
            encrypted += row[index]
    return encrypted

def columnar_transposition_decrypt(encrypted_message, key):
    num_columns = len(key)
    num_rows = len(encrypted_message) // num_columns
    key_order = sorted([(char, i) for i, char in enumerate(key)])
    columns = {}
    start = 0
    for char, index in key_order:
        columns[index] = encrypted_message[start:start+num_rows]
        start += num_rows
    decrypted = ''
    for i in range(num_rows):
        for j in range(num_columns):
            decrypted += columns[j][i]
    decrypted = decrypted.rstrip('_')
    return decrypted

def affine_encrypt(message, a, b):
    encrypted = ''
    for char in message:
        if char.isalpha():
            x = ord(char.lower()) - 97
            y = (a * x + b) % 26
            encrypted_char = chr(y + 97)
            encrypted += encrypted_char.upper() if char.isupper() else encrypted_char
        else:
            encrypted += char
    return encrypted

def affine_decrypt(encrypted_message, a, b):
    decrypted = ''
    a_inv = modinv(a, 26)
    for char in encrypted_message:
        if char.isalpha():
            y = ord(char.lower()) - 97
            x = a_inv * (y - b) % 26
            decrypted_char = chr(x + 97)
            decrypted += decrypted_char.upper() if char.isupper() else decrypted_char
        else:
            decrypted += char
    return decrypted

def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def hill_encrypt(message, key_matrix):
    message = ''.join(filter(str.isalpha, message.lower()))
    while len(message) % key_matrix.shape[0] != 0:
        message += 'x'
    encrypted = ''
    for i in range(0, len(message), key_matrix.shape[0]):
        block = [ord(char) - 97 for char in message[i:i+key_matrix.shape[0]]]
        result = np.dot(key_matrix, block) % 26
        encrypted += ''.join(chr(num + 97) for num in result)
    return encrypted

def hill_decrypt(encrypted_message, key_matrix):
    det = int(round(np.linalg.det(key_matrix))) % 26
    det_inv = modinv(det, 26)
    adjugate = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
    inverse_matrix = (det_inv * adjugate) % 26
    decrypted = ''
    for i in range(0, len(encrypted_message), inverse_matrix.shape[0]):
        block = [ord(char) - 97 for char in encrypted_message[i:i+inverse_matrix.shape[0]]]
        result = np.dot(inverse_matrix, block) % 26
        decrypted += ''.join(chr(int(num) + 97) for num in result)
    return decrypted

# Update the encrypt and decrypt functions

def encrypt(message, key, cipher='rsa', **kwargs):
    if cipher == 'rsa':
        encryptor = PKCS1_OAEP.new(key)
        encrypted = encryptor.encrypt(message.encode())
        return encrypted
    elif cipher == 'aes':
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        return session_key + cipher_aes.nonce + tag + ciphertext
    elif cipher == 'des':
        des = DES.new(key[:8], DES.MODE_EAX)
        nonce = des.nonce
        ciphertext, tag = des.encrypt_and_digest(message.encode())
        return nonce + tag + ciphertext
    elif cipher == 'caesar':
        shift = key  # Key is an integer shift value
        return caesar_encrypt(message, shift)
    elif cipher == 'vigenere':
        return vigenere_encrypt(message, key)
    elif cipher == 'monoalphabetic':
        return monoalphabetic_encrypt(message, key)
    elif cipher == 'autokey':
        return autokey_encrypt(message, key)
    elif cipher == 'rail_fence':
        num_rails = key  # Key is the number of rails
        return rail_fence_encrypt(message, num_rails)
    elif cipher == 'columnar_transposition':
        return columnar_transposition_encrypt(message, key)
    elif cipher == 'affine':
        a = kwargs.get('a')
        b = kwargs.get('b')
        return affine_encrypt(message, a, b)
    elif cipher == 'hill':
        key_matrix = key
        return hill_encrypt(message, key_matrix)
    else:
        raise ValueError("Unsupported cipher")

def decrypt(encrypted_message, key, cipher='rsa', **kwargs):
    if cipher == 'rsa':
        decryptor = PKCS1_OAEP.new(key)
        decrypted = decryptor.decrypt(encrypted_message)
        return decrypted.decode()
    elif cipher == 'aes':
        session_key = encrypted_message[:16]
        nonce = encrypted_message[16:32]
        tag = encrypted_message[32:48]
        ciphertext = encrypted_message[48:]
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode()
    elif cipher == 'des':
        nonce = encrypted_message[:8]
        tag = encrypted_message[8:24]
        ciphertext = encrypted_message[24:]
        des = DES.new(key[:8], DES.MODE_EAX, nonce=nonce)
        data = des.decrypt_and_verify(ciphertext, tag)
        return data.decode()
    elif cipher == 'caesar':
        shift = key
        return caesar_decrypt(encrypted_message, shift)
    elif cipher == 'vigenere':
        return vigenere_decrypt(encrypted_message, key)
    elif cipher == 'monoalphabetic':
        return monoalphabetic_decrypt(encrypted_message, key)
    elif cipher == 'autokey':
        return autokey_decrypt(encrypted_message, key)
    elif cipher == 'rail_fence':
        num_rails = key
        return rail_fence_decrypt(encrypted_message, num_rails)
    elif cipher == 'columnar_transposition':
        return columnar_transposition_decrypt(encrypted_message, key)
    elif cipher == 'affine':
        a = kwargs.get('a')
        b = kwargs.get('b')
        return affine_decrypt(encrypted_message, a, b)
    elif cipher == 'hill':
        key_matrix = key
        return hill_decrypt(encrypted_message, key_matrix)
    else:
        raise ValueError("Unsupported cipher")