import hashlib
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SALT_LENGTH = 16
KEY_LENGTH = 32
BLOCK_SIZE = 128


class ServerCrypto:
    def __init__(self):
        self._salt = secrets.token_bytes(SALT_LENGTH)
        self._key = secrets.token_bytes(KEY_LENGTH)

    def hash_data(self, data):
        h = hashlib.new('sha256')
        h.update(data.encode() + self._salt)
        return h.digest()

    def encrypt_data(self, data):
        iv = secrets.token_bytes(16)
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(BLOCK_SIZE).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ct

    def decrypt_data(self, data):
        iv = data[:16]
        ct = data[16:]
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        pt = unpadder.update(padded_data) + unpadder.finalize()
        return pt.decode()
