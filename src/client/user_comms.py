import logging
import threading
import json

import zmq

# Configure the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UserComms:
    def __init__(self, context: zmq.Context, recv_port: int, username: str):
        self.context = context
        self.username = username
        self.friend_requests = {}
        self.locations = {}

        # Create a PULL socket to receive messages
        self.recv_socket = self.context.socket(zmq.PULL)
        self.recv_socket.bind(f"tcp://*:{recv_port}")
        self.recv_port = recv_port
        self.send_socket = self.context.socket(zmq.PUSH)

        # Start a thread to receive messages
        self.recv_thread = threading.Thread(target=self.receive_messages)
        self.recv_thread.start()

    def handle_friend_request(self, data):
        """
        Handles a friend request message.

        Args:
            data (dict): The message data containing the user and shared secret.
        """
        self.friend_requests[data["user"]] = data["shared_secret_half"]
        logger.info(
            "%s: %s: Friend request stored from %s",
            self.username,
            self.username,
            data["user"],
        )

    def send_message(self, port, message):
        """
        Sends a message to the specified port on localhost.

        Args:
            port (int): The port number of the recipient.
            message (str): The message to be sent.

        Raises:
            Exception: If there is an error in connecting, sending, or disconnecting the socket.
        """

        address = f"tcp://localhost:{port}"
        self.send_socket.connect(address)
        logger.debug("%s: Connected to address: %s", self.username, address)
        logger.info("%s: Sending message: %s", self.username, message)

        self.send_socket.send_string(message)
        logger.debug("%s: Message sent to address: %s", self.username, address)

        self.send_socket.disconnect(address)
        logger.debug("%s: Disconnected from address: %s", self.username, address)

    def receive_messages(self):
        """
        Continuously receives messages and prints them.

        This method runs an infinite loop that waits for messages from the server
        using the `recv_socket.recv_string()` method. Upon receiving a message,
        it prints the message to the console.

        Note:
            This method blocks indefinitely and should be run in a separate thread
            or process to avoid blocking the main program flow.
        """
        while True:
            message = self.recv_socket.recv_string()
            data = json.loads(message)
            if "shared_secret_half" in data:
                logger.info(
                    "%s: Received friend request from %s", self.username, data["user"]
                )
                self.handle_friend_request(data)
            elif "location" in data:
                logger.info(
                    "%s: Received location from %s at %s",
                    self.username,
                    data["user"],
                    data["location"],
                )
                # self.handle_location(data)
            else:
                logger.info("%s: Received message: %s", self.username, data["message"])
