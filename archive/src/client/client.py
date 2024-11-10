import json
import logging

import zmq

from archive.src.client.server_comms import ServerComms
from archive.src.client.user_comms import UserComms
from archive.src.client.security_manager import SecurityManager

# Configure the logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Client:
    def __init__(
        self, username: str, recv_port: int, server_address="tcp://127.0.0.1:5555"
    ):
        # Initialize client attributes
        self.username = username
        self.friends = {}  # {id: shared_secret}
        self.context = zmq.Context()
        self.recv_port = recv_port

        # Initialize communication objects
        self.server_comms = ServerComms(self.context, server_address)
        self.user_comms = UserComms(self.context, self.recv_port, username)
        self.security_manager = SecurityManager()

        # Generate RSA keys
        self.regenerate_keys()

    def regenerate_keys(self):
        public_pem = self.security_manager.generate_public_key()
        logger.info("%s: Regenerated keys", self.username)
        self.server_comms.send_data(self.username, public_pem, self.recv_port)

    def get_port_for_user(self, user) -> int | None:
        """
        Retrieves the port number for the specified user.

        Args:
            user (str): The username of the user to retrieve the port for.

        Returns:
            int: The port number of the specified user.
        """
        user_data = self.server_comms.get_data(user)
        if not user_data:
            logger.error("%s: User data not found", self.username)
            return
        if "port" not in user_data:
            logger.error("%s: Port not found", self.username)
            return
        return user_data["port"]

    def send_friend_request(self, user):
        """
        Sends a friend request to the specified user.

        Args:
            user (str): The username of the user to send the friend request to.
        """
        shared_secret = self.security_manager.generate_shared_secret()
        data = {"user": self.username, "shared_secret_half": shared_secret}
        message = json.dumps(data)

        port = self.get_port_for_user(user)
        if port:
            self.user_comms.send_message(port, message)

    def accept_friend_request(self, user):
        """
        Accepts a friend request from the specified user.

        Args:
            user (str): The username of the user to accept the friend request from.
        """
        shared_secret = self.user_comms.friend_requests.pop(user, None)
        if shared_secret:
            self.friends[user] = shared_secret
            logger.info("%s: Friend request accepted from %s", self.username, user)
        else:
            logger.error("%s: No friend request found from %s", self.username, user)

    def send_location(self):
        """
        Sends the user's location to all friends.

        Args:
            location (str): The user's location.
        """
        for friend in self.friends:
            message = json.dumps({"user": self.username, "location": "home"})
            port = self.get_port_for_user(friend)
            if port:
                self.user_comms.send_message(port, message)
