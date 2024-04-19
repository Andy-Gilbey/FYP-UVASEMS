import base64
import bcrypt
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import b64decode, b64encode

# These functions are pretty much utility and do not require a specific instance of any class 
# so they are just slapped as static. 
# NB- After attempting to just import the EncryptionHandler - it caused an exception, so ensure to import the actual function name also

@staticmethod
def hash_salt_pw(password):
        """
        Hashes and salts a password using bcrypt.
        The result will be then suitable for secure storage.
        
        Args:
            password (str): The password which is going to be hashed and salted.

        Returns:
            bytes: The resulting hashed and salted password.
        """
    
        # Generate a nice salt
        salt = bcrypt.gensalt()
        # Hash the password with the salt..
        hashed_Pw = bcrypt.hashpw(password.encode(), salt)
        return hashed_Pw

@staticmethod
def generate_keynonce():
    key = os.urandom(32)  # 32 bytes = 256 bits
    nonce = os.urandom(12)
    return (key, nonce)

@staticmethod
def encrypt_data(data, key, nonce):
    aesgcm = AESGCM(key)
    encrypted_data = aesgcm.encrypt(nonce, data.encode(), None)
    return b64encode(encrypted_data).decode("utf-8")

@staticmethod
def decrypt_data(encryptedData, key, nonce):
    # Added the below to the method that pulls the encryption key+nonce
    # so it will return the key and nonce decoded already
    # key = base64.b64decode(key)
    # nonce = base64.b64decode(nonce)

    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, base64.b64decode(encryptedData), None)
    decrypted_string = decrypted_data.decode("utf-8")

    return decrypted_string