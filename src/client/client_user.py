import base64
import ipaddress
import logging

import requests

from src.client.zmq_client import ZMQClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ClientUser:
    def __init__(
        self,
        username: str,
        host: str,
        port: int,
        server_host: str = "127.0.0.1",
        server_port: int = 8080,
    ):
        if not username or not isinstance(username, str) or not username.isalpha():  # noqa: E501
            raise ValueError("Invalid username")
        if not host or not isinstance(host, str) or not ipaddress.ip_address(host):  # noqa: E501
            raise ValueError("Invalid host")
        if not port or not isinstance(port, int) or port < 0 or port > 65535:
            raise ValueError("Invalid port")

        self.username = username
        self.host = host
        self.port = port
        self.server_host = server_host
        self.server_port = server_port
        self.zmq_client = ZMQClient(host, port)
        self._post_create_user()

        self.friends: set[str] = set()
        self.friend_requests: set[str] = set()

    def _post_create_user(self):
        url = f"https://{self.server_host}:{self.server_port}/create_user"
        params = {
            "username": self.username,
            "host": self.host,
            "port": self.port,
        }
        encoded_public_key = base64.b64encode(self.zmq_client.get_public_key()).decode("utf-8")  # noqa: E501
        headers = {
            "Authorization": f"PublicKey {encoded_public_key}",
        }
        response = None
        try:
            response = requests.post(
                url, params=params, headers=headers, verify=False, timeout=5
            )
            response.raise_for_status()
            self.auth_token = response.json().get("auth_token")
            logger.info("Success! %s", response.json().get("message"))
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to create user: %s - %s", e, response.text)
            raise e

    def add_friend(self, friend_username):
        # Method to send a friend request to another user
        pass

    def accept_friend_request(self, friend_username):
        # Method to accept a friend request from another user
        pass

    def send_message(self, friend_username, message):
        # Method to send a message to a friend
        pass
