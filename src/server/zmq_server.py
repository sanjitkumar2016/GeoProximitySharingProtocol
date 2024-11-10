import zmq
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class ZMQServer:
    def __init__(self):
        self.context = zmq.Context()

    def send_message(self, host: str, port: int, message: str,
                     recipient_public_key: rsa.RSAPublicKey):
        socket = self.context.socket(zmq.REQ)
        socket.connect(f"tcp://{host}:{port}")

        # Encrypt the message with the recipient's public key
        encrypted_message = recipient_public_key.encrypt(
            message.encode('utf-8'),
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
