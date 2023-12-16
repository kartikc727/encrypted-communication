import base64
import json
import cryptography
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.fernet import Fernet

class CryptoManager:
    @staticmethod
    def gen_key_pair():
        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048)

        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())

        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH)

        return private_key, public_key
    
    @staticmethod
    def serialize(message:'JSONType')->bytes:
        serialized = json.dumps(message)
        return base64.b64encode(serialized.encode('utf-8'))
    
    @staticmethod
    def deserialize(serialized:bytes)->'JSONType':
        serialized_str = base64.b64decode(serialized).decode('utf-8')
        return json.loads(serialized_str)
    
    @staticmethod
    def encrypt_message(message:'JSONType', recipient_username:str, public_key:bytes)->tuple:
        # Create the AES key to encrypt our message
        aes_key = Fernet.generate_key()
        cipher_suite = Fernet(aes_key)
        
        # Encrypt our message using the key
        encrypted_message = cipher_suite.encrypt(CryptoManager.serialize(message)).decode('utf-8')
        
        # Encrypt the AES key using the recipient's public key
        public_key_obj = crypto_serialization.load_ssh_public_key(
            public_key,
            backend=crypto_default_backend())

        ciphertext = public_key_obj.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))

        return encrypted_message, base64.b64encode(ciphertext).decode('utf-8')
    
    @staticmethod
    def decrypt_message(encrypted_message:str, encrypted_key:str, private_key:bytes):
        # Recover the AES key to decrypt the message
        private_key_obj = crypto_serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=crypto_default_backend())

        aes_key = private_key_obj.decrypt(
            base64.b64decode(encrypted_key.encode('utf-8')),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        
        # Decrypt the message using the AES key
        cipher_suite = Fernet(aes_key)
        decrypted_message = cipher_suite.decrypt(encrypted_message.encode('utf-8'))
        
        return CryptoManager.deserialize(decrypted_message)
    
    @staticmethod
    def sign_message(message:'JSONType', private_key:bytes):
        private_key_obj = crypto_serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=crypto_default_backend()
        )

        signature = private_key_obj.sign(
            CryptoManager.serialize(message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(message:'JSONType', signature:str, author_username:str, public_key:bytes)->bool:
        public_key_obj = crypto_serialization.load_ssh_public_key(
            public_key,
            backend=crypto_default_backend())

        try:
            public_key_obj.verify(
                base64.b64decode(signature.encode('utf-8')),
                CryptoManager.serialize(message),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False
