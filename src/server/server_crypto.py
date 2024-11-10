import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class ServerCrypto:
    def __init__(self):
        self.salt_length = 16
        self.key_length = 32
        self.block_size = 128  # AES block size in bits

    def create_salt(self):
        return secrets.token_bytes(self.salt_length)

    def create_symmetric_key(self):
        return secrets.token_bytes(self.key_length)

    def hash_data(self, data, salt=b""):
        h = hashlib.new('sha256')
        h.update(data.encode() + salt)
        return h.digest()

    def encrypt_data(self, data, key):
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ct

    def decrypt_data(self, data, key):
        iv = data[:16]
        ct = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(self.block_size).unpadder()
        pt = unpadder.update(padded_data) + unpadder.finalize()
        return pt.decode()
