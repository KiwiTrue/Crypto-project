# CertificationAuthority.py

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import struct  # Add this import at the top
import os

CA_PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), 'ca_private_key.pem')
CA_PUBLIC_KEY_FILE = os.path.join(os.path.dirname(__file__), 'ca_public_key.pem')

class CertificationAuthority:
    ca_private_key = None
    ca_public_key = None

    @classmethod
    def generate_ca_keys(cls):
        if cls.ca_private_key is None:
            if os.path.exists(CA_PRIVATE_KEY_FILE) and os.path.exists(CA_PUBLIC_KEY_FILE):
                # Load existing CA keys
                with open(CA_PRIVATE_KEY_FILE, 'rb') as f:
                    cls.ca_private_key = RSA.import_key(f.read())
                with open(CA_PUBLIC_KEY_FILE, 'rb') as f:
                    cls.ca_public_key = RSA.import_key(f.read())
                print('CA keys loaded from files.')
            else:
                # Generate new CA keys
                cls.ca_private_key = RSA.generate(2048)
                cls.ca_public_key = cls.ca_private_key.publickey()
                # Save keys to files
                with open(CA_PRIVATE_KEY_FILE, 'wb') as f:
                    f.write(cls.ca_private_key.export_key('PEM'))
                with open(CA_PUBLIC_KEY_FILE, 'wb') as f:
                    f.write(cls.ca_public_key.export_key('PEM'))
                print('New CA keys generated and saved to files.')

    @staticmethod
    def generate_keys():
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        return private_key, public_key

    @classmethod
    def certify_user(cls, public_key):
        cls.generate_ca_keys()
        public_key_der = public_key.export_key(format='DER')
        hash_obj = SHA256.new(public_key_der)
        signature = pkcs1_15.new(cls.ca_private_key).sign(hash_obj)
        signature_length = len(signature)
        certificate = struct.pack('>I', signature_length) + signature + public_key_der
        return certificate

    @classmethod
    def validate_certificate(cls, certificate):
        cls.generate_ca_keys()
        if len(certificate) < 4:
            print("Invalid certificate format.")
            return None
        sig_len = struct.unpack('>I', certificate[:4])[0]
        if len(certificate) < 4 + sig_len:
            print("Incomplete certificate.")
            return None
        signature = certificate[4:4 + sig_len]
        public_key_der = certificate[4 + sig_len:]
        public_key = RSA.import_key(public_key_der)
        hash_obj = SHA256.new(public_key_der)
        try:
            pkcs1_15.new(cls.ca_public_key).verify(hash_obj, signature)
            return public_key
        except (ValueError, TypeError):
            print('Certificate validation failed.')
            return None
