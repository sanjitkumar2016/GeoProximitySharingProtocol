import ipaddress
import json
import logging

from src.client.client_location import ClientLocation
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
        self._client_location = ClientLocation()
        self._web_client = WebClient(self, server_host, server_port)
        self._zmq_client = ZMQClient(self, host, port)
        self._web_client.post_create_user(self._zmq_client.get_public_key())

        self._friends: set[str] = set()
        self._outgoing_friend_requests: set[str] = set()
        self._incoming_friend_requests: set[str] = set()

        self._outgoing_location_requests: dict[str: tuple] = {}
        self._incoming_location_requests: dict[str: tuple] = {}

        self._rehash_verification: dict[str: dict] = {}

        self._location_statuses: dict[str: bool] = {}

    @property
    def friends(self):
        return self._friends

    def handle_friend_request(self, requester):
        self._incoming_friend_requests.add(requester)
        logger.info("Received friend request from '%s'", requester)

    def handle_location_request(
        self, friend_username: str, radius: int, key: bytes
    ):
        if friend_username not in self._friends:
            return

        logger.info(
            "Received location request from '%s' for %s mile(s)",
            friend_username,
            radius
        )
        self._incoming_location_requests[friend_username] = (radius, key)

    def handle_location_rehashes(
        self,
        friend_username: str,
        friend_latitude_rehashes: tuple,
        friend_longitude_rehashes: tuple
    ):
        if friend_username not in self._incoming_location_requests:
            logger.info("No location request sent to '%s'", friend_username)
            return

        friend_address = self._web_client.get_address_request(friend_username)
        if not friend_address:
            logger.info("Failed to get address for '%s'", friend_username)
            return
        if friend_address["username"] != friend_username:
            logger.info("Invalid address for '%s'", friend_username)
            return

        logger.info("Received location rehashes from '%s'", friend_username)

        my_latitude_rehashes = self._rehash_verification[friend_username]["latitude_rehashes"]  # noqa: E501
        my_longitude_rehashes = self._rehash_verification[friend_username]["longitude_rehashes"]  # noqa: E501

        latitudes_match = self._client_location.compare_hashes(
            friend_latitude_rehashes, my_latitude_rehashes)
        longitudes_match = self._client_location.compare_hashes(
            friend_longitude_rehashes, my_longitude_rehashes)
        location_matches = latitudes_match and longitudes_match

        self._rehash_verification.pop(friend_username)
        self._incoming_location_requests.pop(friend_username)

        self._location_statuses[friend_username] = location_matches

        message = {
            "location_rehashes_verified": self.username,
            "location_matches": location_matches,
        }
        self._zmq_client.send_message(
            friend_address["host"],
            friend_address["port"],
            json.dumps(message),
            friend_address["public_key"],
        )

    def handle_location_rehashes_verified(self, friend_username, location_matches):  # noqa: E501
        if friend_username not in self._outgoing_location_requests:
            logger.info("No location request sent to '%s'", friend_username)
            return
        self._outgoing_location_requests.pop(friend_username)
        self._location_statuses[friend_username] = location_matches
        logger.info("Location rehashes verified by '%s'. Within radius: %s",
                    friend_username, location_matches)

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

    def request_location(self, friend_username: str, radius: float = 1.0):
        if friend_username not in self._friends:
            logger.info("Not friends with '%s'", friend_username)
            return
        if not radius or not isinstance(radius, (int, float)) or radius <= 0:
            logger.info("Invalid radius '%s'", radius)
            return

        friend_address = self._web_client.get_address_request(friend_username)
        if not friend_address:
            logger.info("Failed to get address for '%s'", friend_username)
            return
        if friend_address["username"] != friend_username:
            logger.info("Invalid address for '%s'", friend_username)
            return

        key = self._client_location.generate_key()
        self._outgoing_location_requests[friend_username] = (radius, key)
        message = {
            "location_request": self.username,
            "radius": radius,
            "key": key.hex(),
        }
        self._zmq_client.send_message(
            friend_address["host"],
            friend_address["port"],
            json.dumps(message),
            friend_address["public_key"],
        )
        logger.info("Location request sent to '%s'", friend_username)

    def accept_location_request(self, friend_username):
        if friend_username not in self._incoming_location_requests:
            logger.info("No location request from '%s'", friend_username)
            return

        radius, key = self._incoming_location_requests[friend_username]
        latitude_hashes = self._client_location.latitude_hashes(radius, key)
        longitude_hashes = self._client_location.longitude_hashes(radius, key)
        rehashes = self._web_client.post_accept_location_request(
            friend_username,
            json.dumps(latitude_hashes).encode("utf-8"),
            json.dumps(longitude_hashes).encode("utf-8"),
        )
        rehashes["latitude_rehashes"] = tuple(json.loads(rehashes["latitude_rehashes"]))  # noqa: E501
        rehashes["longitude_rehashes"] = tuple(json.loads(rehashes["longitude_rehashes"]))  # noqa: E501
        self._rehash_verification[friend_username] = rehashes
        logger.info("Location response sent to '%s'", friend_username)

    def location_request_accepted(self, friend_username, key_2):
        if friend_username not in self._outgoing_location_requests:
            logger.info("No location request sent to '%s'", friend_username)
            return

        radius, key_1 = self._outgoing_location_requests[friend_username]
        latitude_hashes = self._client_location.latitude_hashes(radius, key_1)  # noqa: E501
        longitude_hashes = self._client_location.longitude_hashes(radius, key_1)  # noqa: E501

        key_2 = bytes.fromhex(key_2)
        latitude_rehashes = self._client_location.hash_state(latitude_hashes, key_2)  # noqa: E501
        longitude_rehashes = self._client_location.hash_state(longitude_hashes, key_2)  # noqa: E501

        friend_address = self._web_client.get_address_request(friend_username)
        if not friend_address:
            logger.info("Failed to get address for '%s'", friend_username)
            return
        if friend_address["username"] != friend_username:
            logger.info("Invalid address for '%s'", friend_username)
            return

        message = {
            "location_rehashes": self.username,
            "latitude_rehashes": latitude_rehashes,
            "longitude_rehashes": longitude_rehashes,
        }
        self._zmq_client.send_message(
            friend_address["host"],
            friend_address["port"],
            json.dumps(message),
            friend_address["public_key"],
        )

    def get_location_statuses(self):
        for friend in self._location_statuses:
            logger.info("Location status for '%s': %s",
                        friend, self._location_statuses[friend])
