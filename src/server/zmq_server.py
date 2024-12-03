import secrets

import zmq
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hmac import HMAC


class ZMQServer:
    """
    A server class that uses ZeroMQ for sending encrypted messages and provides utility methods for key management and hashing.

    Attributes:
        context (zmq.Context): The ZeroMQ context for creating sockets.

    Methods:
        send_message(host: str, port: int, message: str, recipient_public_key: rsa.RSAPublicKey):
            Sends an encrypted message to a specified host and port using ZeroMQ.
        public_key_from_pem(pem: bytes) -> rsa.RSAPublicKey:
            Load a public key from a PEM-encoded byte string.
        public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
            Converts an RSA public key to PEM format.
        generate_key() -> bytes:
            Generates a cryptographic key.
        hash_state(state: tuple, key: bytes) -> tuple:
            Hashes each element of the given state tuple using HMAC with the provided key and SHA256 algorithm
    """

    def __init__(self):
        self.context = zmq.Context()

    def send_message(self, host: str, port: int, message: str, recipient_public_key: rsa.RSAPublicKey):
        """
        Sends an encrypted message to a specified host and port using ZeroMQ.

        Args:
            host (str): The hostname or IP address of the recipient.
            port (int): The port number on which the recipient is listening.
            message (str): The plaintext message to be sent.
            recipient_public_key (rsa.RSAPublicKey): The recipient's RSA public key used for encrypting the message.

        Raises:
            ValueError: If the encryption process fails.
        """
        socket = self.context.socket(zmq.PUSH)
        socket.connect(f"tcp://{host}:{port}")

        # Encrypt the message with the recipient's public key
        encrypted_message = recipient_public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        socket.send(encrypted_message)

    def public_key_from_pem(self, pem: bytes) -> rsa.RSAPublicKey:
        """
        Load a public key from a PEM-encoded byte string.

        Args:
            pem (bytes): The PEM-encoded public key.

        Returns:
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: The loaded public key.

        Raises:
            ValueError: If the PEM data could not be deserialized.
            TypeError: If the PEM data does not contain a valid public key.
        """
        return serialization.load_pem_public_key(pem, backend=default_backend())

    def public_key_to_pem(self, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Converts an RSA public key to PEM format.

        Args:
            public_key (rsa.RSAPublicKey): The RSA public key to convert.

        Returns:
            bytes: The PEM-encoded public key.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def generate_key(self) -> bytes:
        """
        Generates a cryptographic key.

        Returns:
            bytes: A 64-byte cryptographic key.
        """
        return secrets.token_bytes(64)

    def hash_state(self, state: tuple, key: bytes) -> tuple:
        """
        Hashes each element of the given state tuple using HMAC with the provided key and SHA256 algorithm.

        Args:
            state (tuple): A tuple containing the elements to be hashed.
            key (bytes): A byte string used as the key for the HMAC hashing.

        Returns:
            tuple: A tuple containing the hashed values of the input state elements, represented as hexadecimal strings.
        """
        hashed_state = []
        for val in state:
            h = HMAC(key, hashes.SHA256())
            h.update(str(val).encode())
            hashed_state.append(h.finalize().hex())
        return tuple(hashed_state)
