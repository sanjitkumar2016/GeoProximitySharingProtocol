import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SALT_LENGTH = 16
KEY_LENGTH = 32
BLOCK_SIZE = 128


class ServerCrypto:
    """
    A class used to perform cryptographic operations such as hashing, encryption, and decryption.

    Attributes
    _salt : bytes
        A random salt value used for hashing.
    _key : bytes
        A random key used for encryption and decryption.

    Methods
    hash_data(data)
        Hashes the input data using SHA-256 along with a salt.
    encrypt_data(data)
        Encrypts the input data using AES encryption in CBC mode with PKCS7 padding.
    decrypt_data(data)
        Decrypts the input data using AES decryption in CBC mode with PKCS7 padding removal.
    """

    def __init__(self):
        self._salt = secrets.token_bytes(SALT_LENGTH)
        self._key = secrets.token_bytes(KEY_LENGTH)

    def hash_data(self, data: str) -> bytes:
        """
        Hashes the given data using SHA-256 algorithm and a salt.

        Args:
            data (str): The data to be hashed.

        Returns:
            bytes: The resulting hash as a byte sequence.
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode() + self._salt)
        return digest.finalize()

    def encrypt_data(self, data: str) -> bytes:
        """
        Encrypts the given data using AES encryption in CBC mode with PKCS7 padding.

        Args:
            data (str): The plaintext data to be encrypted.

        Returns:
            bytes: The initialization vector (IV) concatenated with the ciphertext.
        """
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(BLOCK_SIZE).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ct

    def decrypt_data(self, data: bytes) -> str:
        """
        Decrypts the given encrypted data using AES encryption in CBC mode.

        Args:
            data (bytes): The encrypted data to be decrypted. The first 16 bytes should be the IV,
                          and the rest should be the ciphertext.

        Returns:
            str: The decrypted plaintext as a string.

        Raises:
            ValueError: If the decryption process fails.
        """
        iv = data[:16]
        ct = data[16:]
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
        pt = unpadder.update(padded_data) + unpadder.finalize()
        return pt.decode()
