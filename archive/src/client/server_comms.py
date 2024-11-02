import json
import logging

import zmq

# Configure the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServerComms:
    """
    ServerComms class handles interactions with a keystore server using ZeroMQ.

    Attributes:
        server_address (str): The address of the keystore server.
        context (zmq.Context): The ZeroMQ context for creating sockets.
        socket (zmq.Socket): The ZeroMQ socket used for communication with the server.

    Methods:
        __init__(context: zmq.Context, server_address: str):
            Initializes the ServerComms instance with the given context and server address.

        get_data(other_user: str) -> dict:
            Sends a request to the keystore to get the public key of a user.

        send_data(username: str, public_pem: str, recv_port: int):
            Sends the user's public key and port to the server.
    """

    def __init__(self, context: zmq.Context, server_address: str):
        self.server_address = server_address
        self.context = context
        self.socket = self.context.socket(zmq.REQ)
        self.socket.connect(self.server_address)

    def get_data(self, other_user) -> dict:
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
        message = json.dumps({"command": "get", "user": other_user})
        self.socket.send_string(message)
        response = self.socket.recv_string()
        if response.startswith("404"):
            logger.error("User not found")
            return {}
        return json.loads(response)

    def send_data(self, username: str, public_pem: str, recv_port: int):
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
                "user": username,
                "key": public_pem.decode(),
                "port": recv_port,
            }
        )
        self.socket.send_string(message)
        response = self.socket.recv_string()  # Wait for keystore acknowledgment
        if response.startswith("200"):
            logger.info("%s: Key added successfully", username)
        else:
            logger.error("%s: Key not added successfully", username)
