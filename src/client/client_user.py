import ipaddress
import logging

from src.client.web_client import WebClient
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
        self._web_client = WebClient(self, server_host, server_port)
        self._zmq_client = ZMQClient(self, host, port)
        self._web_client.post_create_user(self._zmq_client.get_public_key())

        self._friends: set[str] = set()
        self._outgoing_friend_requests: set[str] = set()
        self._incoming_friend_requests: set[str] = set()

    @property
    def friends(self):
        return self._friends

    def handle_friend_request(self, requester):
        self._incoming_friend_requests.add(requester)
        logger.info("Received friend request from '%s'", requester)

    def add_friend(self, friend_username: str):
        if friend_username in self._friends:
            logger.info("Already friends with '%s'", friend_username)
            return

        if friend_username in self._outgoing_friend_requests:
            logger.info("Friend request already sent to '%s'", friend_username)
            return

        if friend_username in self._incoming_friend_requests:
            logger.info("Accepting friend request from '%s'", friend_username)
            self.accept_friend_request(friend_username)
            return

        self._web_client.post_add_friend(friend_username)
        self._outgoing_friend_requests.add(friend_username)

    def accept_friend_request(self, friend_username):
        if friend_username in self._friends:
            logger.info("Already friends with '%s'", friend_username)
            return

        if friend_username not in self._incoming_friend_requests:
            logger.info("No friend request from '%s'", friend_username)
            return

        self._web_client.post_accept_friend_request(friend_username)
        self._incoming_friend_requests.remove(friend_username)
        self._friends.add(friend_username)

    def friend_request_accepted(self, friend_username):
        self._outgoing_friend_requests.remove(friend_username)
        self._friends.add(friend_username)
        logger.info("Friend request accepted by '%s'", friend_username)

    def request_location(self, friend_username):
        if friend_username not in self._friends:
            logger.info("Not friends with '%s'", friend_username)
            return
