"""
Secure Protocol Handler - Implements secure key distribution and cipher negotiation
"""
import os
from typing import Dict, Tuple, List, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import json
import base64

class SecureProtocol:
    CIPHER_TYPE = 'AES'  # Simplify to use single cipher type
    KEY_SIZE = 32  # 256-bit AES key
    
    @staticmethod
    def generate_keypair(name: str) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return private_key, private_key.public_key()
    
    @staticmethod
    def export_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """Export public key in shareable format"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def cipher_preference_order() -> List[str]:
        """Returns ciphers in order of security preference"""
        return ['AES', 'BLOWFISH', 'DES']
    
    @staticmethod
    def negotiate_cipher(local_ciphers: List[str], remote_ciphers: List[str]) -> str:
        """Select strongest common cipher using preference order"""
        for cipher in SecureProtocol.cipher_preference_order():
            if cipher in local_ciphers and cipher in remote_ciphers:
                return cipher
        raise ValueError("No common cipher found")

    @staticmethod
    def generate_session_id() -> str:
        """Generate a unique session identifier"""
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    @staticmethod
    def create_secure_session(cipher_type: str) -> Tuple[str, bytes]:
        """Create a new secure session with initial key"""
        session_id = SecureProtocol.generate_session_id()
        key = SecureProtocol.generate_session_key(cipher_type)
        return session_id, key

    @staticmethod
    def generate_session_key() -> bytes:
        return os.urandom(32)  # 256-bit key for AES

    @staticmethod
    def create_secure_message(data: Union[str, bytes], cipher_type: str) -> Dict:
        """Create a properly formatted secure message"""
        return {
            'cipher': cipher_type,
            'data': data,
            'mac': None  # Will be added during encryption
        }