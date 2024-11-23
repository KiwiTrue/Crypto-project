"""
Secure Protocol Handler - Implements secure key distribution and cipher negotiation

Key Features:
- RSA keypair generation and management
- Public key exchange mechanism
- Cipher negotiation between parties 
- Session key generation
"""
import os
from typing import Dict, Tuple, List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import json

class SecureProtocol:
    """
    Manages cryptographic protocols and key exchange.
    
    Security Features:
    - 2048-bit RSA keys for asymmetric encryption
    - Support for multiple symmetric ciphers
    - Secure key storage and distribution
    - Protocol negotiation
    """
    SUPPORTED_CIPHERS = ['AES', 'BLOWFISH', 'DES']
    
    @staticmethod
    def generate_keypair(save_path: str) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate and save keypair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Save private key
        with open(f"{save_path}.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        return private_key, private_key.public_key()
    
    @staticmethod
    def export_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """Export public key in shareable format"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def negotiate_cipher(local_ciphers: List[str], remote_ciphers: List[str]) -> str:
        """Select strongest common cipher"""
        for cipher in SecureProtocol.SUPPORTED_CIPHERS:
            if cipher in local_ciphers and cipher in remote_ciphers:
                return cipher
        raise ValueError("No common cipher found")
    
    @staticmethod
    def generate_session_key(cipher_type: str) -> bytes:
        """Generate appropriate key for chosen cipher"""
        key_sizes = {'AES': 32, 'BLOWFISH': 32, 'DES': 8}
        return os.urandom(key_sizes[cipher_type])