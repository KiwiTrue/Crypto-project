# CertificationAuthority.py

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class CertificationAuthority:
    def __init__(self):
        self.ca_private_key = RSA.generate(2048)
        self.ca_public_key = self.ca_private_key.publickey()

    def generate_keys(self):
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        return private_key, public_key

    def certify_user(self, public_key):
        public_key_der = public_key.export_key(format='DER')
        hash_obj = SHA256.new(public_key_der)
        signature = pkcs1_15.new(self.ca_private_key).sign(hash_obj)
        certificate = signature + public_key_der
        return certificate

    def validate_certificate(self, certificate):
        signature = certificate[:256]
        public_key_der = certificate[256:]
        public_key = RSA.import_key(public_key_der)
        hash_obj = SHA256.new(public_key_der)
        try:
            pkcs1_15.new(self.ca_public_key).verify(hash_obj, signature)
            return public_key
        except (ValueError, TypeError):
            print('Certificate validation failed.')
            return None