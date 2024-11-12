import secrets

import zmq
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hmac import HMAC


class ZMQServer:
    def __init__(self):
        self.context = zmq.Context()

    def send_message(self, host: str, port: int, message: str,
                     recipient_public_key: rsa.RSAPublicKey):
        socket = self.context.socket(zmq.PUSH)
        socket.connect(f"tcp://{host}:{port}")

        # Encrypt the message with the recipient's public key
        encrypted_message = recipient_public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        socket.send(encrypted_message)

    def public_key_from_pem(self, pem: bytes):
        return serialization.load_pem_public_key(
            pem,
            backend=default_backend()
        )

    def public_key_to_pem(self, public_key: rsa.RSAPublicKey):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def generate_key(self) -> bytes:
        return secrets.token_bytes(64)

    def hash_state(self, state: tuple, key: bytes) -> tuple:
        hashed_state = []
        for val in state:
            h = HMAC(key, hashes.SHA256())
            h.update(str(val).encode())
            hashed_state.append(h.finalize().hex())
        return tuple(hashed_state)
