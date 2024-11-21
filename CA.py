"""
Certification Authority module - Handles certificates and key distribution
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging

class CertificationAuthority:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.certificates: Dict[str, x509.Certificate] = {}
        self.users: Dict[str, Dict[str, Any]] = {}
        self.cert_serial = 0
        self.revoked_certs = set()
        self.logger = logging.getLogger('CA')

    def certify(self, public_key):
        cert = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.certificates[public_key] = cert
        return cert

    def get_certificates(self):
        return self.certificates

    def register_user(self, user_id: str, public_key: rsa.RSAPublicKey) -> x509.Certificate:
        try:
            if user_id in self.users:
                self.revoke_certificate(user_id)
            cert = self.create_certificate(public_key, user_id)
            self.users[user_id] = {
                'public_key': public_key,
                'certificate': cert,
                'created_at': datetime.utcnow()
            }
            self.logger.info(f"User {user_id} registered successfully")
            return cert
        except Exception as e:
            self.logger.log_error(f"Failed to register user {user_id}: {str(e)}")
            raise

    def create_certificate(self, public_key, user_id):
        self.cert_serial += 1
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_id),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Mastermind Game CA'),
        ]))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=1))
        builder = builder.serial_number(self.cert_serial)
        builder = builder.public_key(public_key)
        
        certificate = builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256()
        )
        return certificate

    def revoke_certificate(self, user_id: str) -> None:
        if user_id in self.users:
            self.revoked_certs.add(self.users[user_id]['certificate'].serial_number)
            self.logger.info(f"Certificate revoked for user {user_id}")

    def verify_certificate(self, certificate: x509.Certificate) -> bool:
        try:
            if isinstance(certificate, bytes):
                certificate = x509.load_pem_x509_certificate(certificate)
                
            if certificate.serial_number in self.revoked_certs:
                return False
            if datetime.utcnow() > certificate.not_valid_after:
                return False
                
            # Verify the certificate was signed by this CA
            ca_cert = self.get_ca_certificate()
            certificate.verify_directly_issued_by(ca_cert)
            return True
        except Exception as e:
            self.logger.log_error(f"Certificate verification failed: {str(e)}")
            return False

    def get_ca_certificate(self):
        # Create a self-signed certificate for the CA
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Mastermind Game CA'),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'Mastermind Game CA'),
        ]))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
        builder = builder.serial_number(1)
        builder = builder.public_key(self.private_key.public_key())
        
        certificate = builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256()
        )
        return certificate

    def distribute_keys(self, user_id: str, cipher_choice: str, symmetric_key: bytes) -> Dict[str, Dict[str, Any]]:
        if not self.verify_user(user_id):
            raise ValueError("Invalid initiator credentials")

        encrypted_keys = {}
        for uid, user in self.users.items():
            if uid != user_id and self.verify_user(uid):
                try:
                    encrypted_key = self.encrypt_key(user['public_key'], symmetric_key)
                    encrypted_keys[uid] = {
                        'cipher': cipher_choice,
                        'key': encrypted_key
                    }
                except Exception as e:
                    self.logger.log_error(f"Failed to encrypt key for user {uid}: {str(e)}")

        return encrypted_keys

    def verify_user(self, user_id: str) -> bool:
        return (user_id in self.users and 
                self.verify_certificate(self.users[user_id]['certificate']))

    def encrypt_key(self, public_key: rsa.RSAPublicKey, key: bytes) -> bytes:
        return public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
