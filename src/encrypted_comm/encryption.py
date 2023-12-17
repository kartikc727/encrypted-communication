""" This module handles the cryptographic requirements of the application, such
    as encryption, decryption, signing, and verification of messages. 
"""

import base64
import json
import cryptography
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.fernet import Fernet

class CryptoManager:
    """ This class contains the functions for encryption and verification of
        messages. It also contains the functions for generating key pairs.
    """
    @staticmethod
    def gen_key_pair()->tuple[bytes, bytes]:
        """Generates a public/private key pair for use in encryption and
        decryption of messages.

        Returns:
            tuple[bytes, bytes]:
                The first element is the private key, and the
                second element is the public key.
        """
    
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
        """Serializes a JSON object into a base64-encoded bytes object. The
        serialized object can be encrypted and sent over the network.

        Args:
            message (JSONType):
                A JSON-serializable object.

        Returns:
            bytes:
                The serialized message.
        """
        serialized = json.dumps(message)
        return base64.b64encode(serialized.encode('utf-8'))
    
    @staticmethod
    def deserialize(serialized:bytes)->'JSONType':
        """Deserializes a base64-encoded bytes object into a JSON object. The
        deserialized object is usually recovered after decryption and can be
        used by the application.

        Args:
            serialized (bytes): The serialized message.

        Returns:
            JSONType: The deserialized message.
        """
        serialized_str = base64.b64decode(serialized).decode('utf-8')
        return json.loads(serialized_str)
    
    @staticmethod
    def encrypt_message(message:'JSONType', public_key:bytes)->tuple[str, str]:
        """Encrypts a message using the recipient's public key. The message is
        encrypted using AES encryption, and the AES key is encrypted using the
        recipient's public key.

        Args:
            message (JSONType):
                The message to be encrypted.
            public_key (bytes):
                The recipient's public key.

        Returns:
            tuple[str, str]:
                The encrypted message and the encrypted AES key.
        """
        # Create the AES key to encrypt our message
        aes_key = Fernet.generate_key()
        cipher_suite = Fernet(aes_key)
        
        # Encrypt our message using the key
        encrypted_message = cipher_suite.encrypt(
            CryptoManager.serialize(message)).decode('utf-8')
        
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
    def decrypt_message(encrypted_message:str, encrypted_key:str,
            private_key:bytes)->'JSONType':
        """Decrypts a message using the recipient's private key. The message is
        decrypted using AES decryption, and the AES key is decrypted using the
        recipient's private key.
        
        Args:
            encrypted_message (str):
                The encrypted message.
            encrypted_key (str):
                The encrypted AES key.
            private_key (bytes):
                The recipient's private key.

        Returns:
            JSONType:
                The decrypted message.
        """
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
    def sign_message(message:'JSONType', private_key:bytes)->str:
        """Signs a message using the sender's private key. The SHA256 hash of
        the message is signed using the sender's private key.

        Args:
            message (JSONType):
                The message to be signed.
            private_key (bytes):
                The sender's private key.

        Returns:
            str:
                The signature of the message.
        """
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
    def verify_signature(message:'JSONType', signature:str,
            public_key:bytes)->bool:
        """Verifies the signature of a message using the sender's public key.
        The SHA256 hash of the message is verified against the signature using
        the sender's public key.

        Args:
            message (JSONType):
                The message to be verified.
            signature (str):
                The signature of the message.
            public_key (bytes):
                The sender's public key.

        Returns:
            bool:
                True if the signature is valid, False otherwise.
        """
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
