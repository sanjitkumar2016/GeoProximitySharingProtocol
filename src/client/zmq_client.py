import json
import threading

import zmq
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class ZMQClient:
    """
    A client class for handling ZeroMQ communication with encryption.

    Attributes:
        client_user: An instance representing the user of the client.
        context: The ZeroMQ context.
        running: A boolean indicating if the client is running.
        listen_socket: The ZeroMQ socket for listening to incoming messages.
        thread: The thread for receiving messages.
        private_key: The RSA private key for decrypting messages.
        public_key: The RSA public key for encrypting messages.

    Methods:
        __init__(client_user, host, port):
            Initializes the ZMQClient with the given user, host, and port.
        get_public_key() -> bytes:
            Returns the public key in PEM format.
        send_message(host, port, message, recipient_public_key):
            Sends an encrypted message to the specified host and port using the recipient's public key.
        _receive_messages():
            Listens for incoming messages and processes them.
        _parse_message(message):
            Parses and handles the received message.
        _decrypt_message(message) -> str:
            Decrypts the received message using the private key.
        stop():
            Stops the client and terminates the ZeroMQ context.
    """

    def __init__(self, client_user, host, port):
        self.client_user = client_user
        self.context = zmq.Context()
        self.running = True
        self.listen_socket = self.context.socket(zmq.PULL)
        self.listen_socket.bind(f"tcp://{host}:{port}")
        self.thread = threading.Thread(target=self._receive_messages)
        self.thread.start()

        # Generate public/private key pair
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=8192, backend=default_backend())
        self.public_key = self.private_key.public_key()

    def get_public_key(self) -> bytes:
        """
        Retrieves the public key in PEM format.

        Returns:
            bytes: The public key encoded in PEM format.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def send_message(self, host, port, message, recipient_public_key):
        """
        Sends an encrypted message to a specified host and port using ZeroMQ.

        Args:
            host (str): The hostname or IP address of the recipient.
            port (int): The port number to connect to on the recipient's host.
            message (str): The plaintext message to be sent.
            recipient_public_key (bytes): The recipient's public key in PEM format for encrypting the message.

        Raises:
            ValueError: If the recipient's public key is invalid or the encryption fails.
        """
        socket = self.context.socket(zmq.PUSH)
        socket.connect(f"tcp://{host}:{port}")

        # Load recipient's public key
        public_key = serialization.load_pem_public_key(recipient_public_key, backend=default_backend())

        # Encrypt the message with the recipient's public key
        encrypted_message = public_key.encrypt(
            message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
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

        elif "location_request" in message:
            friend_username = message["location_request"]
            radius = message["radius"]
            key = bytes.fromhex(message["key"])
            self.client_user.handle_location_request(friend_username, radius, key)  # noqa: E501

        elif "location_request_accepted" in message:
            friend_username = message["location_request_accepted"]
            key = message["key"]
            self.client_user.location_request_accepted(friend_username, key)

        elif "location_rehashes" in message:
            friend_username = message["location_rehashes"]
            latitude_rehashes = tuple(message["latitude_rehashes"])
            longitude_rehashes = tuple(message["longitude_rehashes"])
            self.client_user.handle_location_rehashes(friend_username, latitude_rehashes, longitude_rehashes)

        elif "location_rehashes_verified" in message:
            friend_username = message["location_rehashes_verified"]
            location_matches = message["location_matches"]
            self.client_user.handle_location_rehashes_verified(friend_username, location_matches)  # noqa: E501

    def _decrypt_message(self, message):
        decrypted_message = self.private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_message.decode("utf-8")

    def stop(self):
        """
        Stops the ZeroMQ client by setting the running flag to False,
        joining the client thread, and terminating the ZeroMQ context.
        """
        self.running = False
        self.thread.join()
        self.context.term()
