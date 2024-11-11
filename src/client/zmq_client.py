import json
import threading

import zmq
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class ZMQClient:
    def __init__(self, client_user, host, port):
        self.client_user = client_user
        self.context = zmq.Context()
        self.running = True
        self.listen_socket = self.context.socket(zmq.PULL)
        self.listen_socket.bind(f"tcp://{host}:{port}")
        self.thread = threading.Thread(target=self._receive_messages)
        self.thread.start()

        # Generate public/private key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def get_public_key(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def send_message(self, host, port, message, recipient_public_key):
        socket = self.context.socket(zmq.PUSH)
        socket.connect(f"tcp://{host}:{port}")

        # Load recipient's public key
        public_key = serialization.load_pem_public_key(
            recipient_public_key,
            backend=default_backend()
        )

        # Encrypt the message with the recipient's public key
        encrypted_message = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        socket.send(encrypted_message)

    def _receive_messages(self):
        while self.running:
            try:
                message = self.listen_socket.recv()
                self._parse_message(message)
            except zmq.Again:
                continue

    def _parse_message(self, message):
        decrypted_message = self._decrypt_message(message)
        message = json.loads(decrypted_message)

        if "friend_request" in message:
            requester = message["friend_request"]
            self.client_user.handle_friend_request(requester)

        elif "friend_request_accepted" in message:
            friend_username = message["friend_request_accepted"]
            self.client_user.friend_request_accepted(friend_username)

    def _decrypt_message(self, message):
        decrypted_message = self.private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode('utf-8')

    def stop(self):
        self.running = False
        self.thread.join()
        self.context.term()
