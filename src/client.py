import json
import logging
import threading

import zmq
from Crypto.PublicKey import RSA

# Configure the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Client:
    """
    A client class for handling communication with a keystore and sending/receiving messages.

    Attributes:
        username (str): The username of the client.
        keystore_address (str): The address of the keystore server.
        context (zmq.Context): The ZeroMQ context.
        socket (zmq.Socket): The ZeroMQ socket for sending requests to the keystore.
        private_key (bytes): The client's private RSA key.
        public_key (bytes): The client's public RSA key.
        recv_socket (zmq.Socket): The ZeroMQ socket for receiving messages.
        recv_port (str): The port on which the client receives messages.
        send_socket (zmq.Socket): The ZeroMQ socket for sending messages.
        recv_thread (threading.Thread): The thread for receiving messages.

    Methods:
        __init__(username, keystore_address="tcp://localhost:5555"):
            Initializes the client with a username and optional keystore address.

        generate_keys():
            Generates a new pair of RSA keys for the client.

        send_public_key():
            Sends the client's public key to the keystore.

        regenerate_keys():
            Regenerates the client's RSA keys and sends the new public key to the keystore.

        send_message(address, message):
            Sends a message to the specified address.

        receive_messages():
            Continuously listens for incoming messages and prints them.
    """

    def __init__(self, username, recv_port, keystore_address="tcp://localhost:5555"):
        self.username = username
        self.keystore_address = keystore_address
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REQ)
        self.socket.connect(self.keystore_address)

        self.recv_socket = self.context.socket(zmq.PULL)
        self.recv_socket.bind(f"tcp://*:{recv_port}")
        self.recv_port = recv_port

        self.send_socket = self.context.socket(zmq.PUSH)
        
        self.generate_keys()
        self.send_data()

        self.recv_thread = threading.Thread(target=self.receive_messages)
        self.recv_thread.start()

    def generate_keys(self):
        """
        Generates a pair of RSA keys (private and public) for the client.

        This method creates a 2048-bit RSA key pair. The private key is stored in
        `self.private_key` and the public key is stored in `self.public_key`.

        Returns:
            None
        """
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()

    def get_data(self, user):
        """
        Sends a request to the keystore to get the public key of a user.

        This method sends a JSON formatted request to the keystore server to
        retrieve the public key of a specified user. The request has the following
        structure:
        {
            "command": "get",
            "user": <username>,
        }

        Returns:
            dict: The public key and port of the specified user if found.
        """
        message = json.dumps({"command": "get", "user": user})
        self.socket.send_string(message)
        response = self.socket.recv_string()
        if response.startswith("404"):
            logger.error("User not found")
            return {}
        return json.loads(response)

    def send_data(self):
        """
        Sends the user's public key and port to the server.

        This method serializes the user's public key, username, and port into
        a JSON formatted string and sends it to the server via a socket
        connection. It then waits for an acknowledgment from the server.

        The JSON message has the following structure:
        {
            "command": "set",
            "user": <username>,
            "key": <public_key>,
            "port": <recv_port>,
        }

        Raises:
            Any exceptions raised by the socket's send_string or recv_string methods.
        """
        message = json.dumps(
            {
                "command": "set",
                "user": self.username,
                "key": self.public_key.decode("utf-8"),
                "port": self.recv_port,
            }
        )
        self.socket.send_string(message)
        response = self.socket.recv_string()  # Wait for keystore acknowledgment
        if response.startswith("200"):
            logger.info("Key added successfully")
        else:
            logger.error("Key not added successfully")

    def regenerate_keys(self):
        """
        Regenerates the cryptographic keys for the client.

        This method first generates a new set of keys by calling `generate_keys()`
        and then sends the newly generated public key to the appropriate recipient
        by calling `send_public_key()`.
        """
        self.generate_keys()
        logger.info("Regenerated keys")
        self.send_data()

    def send_message(self, user, message):
        """
        Sends a message to the specified port on localhost.

        Args:
            port (int): The port number of the recipient.
            message (str): The message to be sent.

        Raises:
            Exception: If there is an error in connecting, sending, or disconnecting the socket.
        """
        user_data = self.get_data(user)
        if not user_data:
            logger.error("User data not found")
            return

        address = f"tcp://localhost:{user_data['port']}"
        self.send_socket.connect(address)
        logger.debug("Connected to address: %s", address)
        logger.info("Sending message: %s", message)

        self.send_socket.send_string(message)
        logger.debug("Message sent to address: %s", address)

        self.send_socket.disconnect(address)
        logger.debug("Disconnected from address: %s", address)

    def receive_messages(self):
        """
        Continuously receives messages from the server and prints them.

        This method runs an infinite loop that waits for messages from the server
        using the `recv_socket.recv_string()` method. Upon receiving a message,
        it prints the message to the console.

        Note:
            This method blocks indefinitely and should be run in a separate thread
            or process to avoid blocking the main program flow.
        """
        while True:
            message = self.recv_socket.recv_string()
            print(f"{self.username} received a message: {message}")
