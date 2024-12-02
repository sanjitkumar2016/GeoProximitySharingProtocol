import ipaddress
import json
import logging

from src.client.client_location import ClientLocation
from src.client.web_client import WebClient
from src.client.zmq_client import ZMQClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ClientUser:
    """
    ClientUser class represents a user in the GeoProximitySharingProtocol system.

    Attributes:
        username (str): The username of the client user.
        host (str): The host address of the client user.
        port (int): The port number of the client user.
        _client_location (ClientLocation): An instance of ClientLocation for managing location data.
        _web_client (WebClient): An instance of WebClient for handling web requests.
        _zmq_client (ZMQClient): An instance of ZMQClient for handling ZeroMQ communication.
        _friends (set[str]): A set of usernames representing the user's friends.
        _outgoing_friend_requests (set[str]): A set of usernames representing outgoing friend requests.
        _incoming_friend_requests (set[str]): A set of usernames representing incoming friend requests.
        _outgoing_location_requests (dict[str, tuple]): A dictionary mapping friend usernames to outgoing location request details.
        _incoming_location_requests (dict[str, tuple]): A dictionary mapping friend usernames to incoming location request details.
        _rehash_verification (dict[str, dict]): A dictionary for storing rehash verification data.
        _location_statuses (dict[str, bool]): A dictionary mapping friend usernames to their location statuses.

    Methods:
        friends: Returns the list of friends associated with the user.
        handle_friend_request(requester: str): Handles an incoming friend request.
        handle_location_request(friend_username: str, radius: int, key: bytes): Handles an incoming location request from a friend.
        handle_location_rehashes(friend_username: str, friend_latitude_rehashes: tuple, friend_longitude_rehashes: tuple): Handles location rehashes received from a friend.
        handle_location_rehashes_verified(friend_username: str, location_matches: bool): Handles the verification of location rehashes for a given friend.
        add_friend(friend_username: str): Adds a friend by their username.
        accept_friend_request(friend_username: str): Accepts a friend request from the specified user.
        friend_request_accepted(friend_username: str): Handles the acceptance of a friend request.
        request_location(friend_username: str, radius: float = 1.0): Sends a location request to a specified friend within a given radius.
        accept_location_request(friend_username: str): Accepts a location request from a friend and sends the location response.
        location_request_accepted(friend_username: str, key_2: str): Handles the acceptance of a location request from a friend.
        get_location_statuses: Retrieves and logs the location statuses of friends.
    """

    def __init__(
        self,
        username: str,
        host: str,
        port: int,
        server_host: str = "127.0.0.1",
        server_port: int = 8080,
    ):
        if not username or not isinstance(username, str) or not username.isalpha():
            raise ValueError("Invalid username")
        if not host or not isinstance(host, str) or not ipaddress.ip_address(host):
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

        self._outgoing_location_requests: dict[str:tuple] = {}
        self._incoming_location_requests: dict[str:tuple] = {}

        self._rehash_verification: dict[str:dict] = {}

        self._location_statuses: dict[str:bool] = {}

    @property
    def friends(self) -> list:
        """
        Returns the list of friends associated with the user.

        Returns:
            list: A list of friends.
        """
        return self._friends

    def handle_friend_request(self, requester: str):
        """
        Handles an incoming friend request by adding the requester to the set of incoming friend requests
        and logging the event.

        Args:
            requester (str): The username of the user sending the friend request.
        """
        self._incoming_friend_requests.add(requester)
        logger.info("Received friend request from '%s'", requester)

    def handle_location_request(self, friend_username: str, radius: int, key: bytes):
        """
        Handles an incoming location request from a friend.

        This method checks if the requesting friend is in the user's friend list.
        If the friend is not in the list, the request is ignored. Otherwise, it logs
        the request and stores the request details.

        Args:
            friend_username (str): The username of the friend making the request.
            radius (int): The radius (in miles) within which the friend is requesting the location.
            key (bytes): A key associated with the location request.

        Returns:
            None
        """
        if friend_username not in self._friends:
            return

        logger.info(
            "Received location request from '%s' for %s mile(s)",
            friend_username,
            radius,
        )
        self._incoming_location_requests[friend_username] = (radius, key)

    def handle_location_rehashes(
        self,
        friend_username: str,
        friend_latitude_rehashes: tuple,
        friend_longitude_rehashes: tuple,
    ):
        """
        Handles the location rehashes received from a friend and verifies if they match the user's location rehashes.

        Args:
            friend_username (str): The username of the friend sending the location rehashes.
            friend_latitude_rehashes (tuple): The latitude rehashes received from the friend.
            friend_longitude_rehashes (tuple): The longitude rehashes received from the friend.

        Returns:
            None

        Logs:
            - Logs an info message if no location request was sent to the friend.
            - Logs an info message if failed to get the address for the friend.
            - Logs an info message if the address for the friend is invalid.
            - Logs an info message indicating whether the received location rehashes match the user's location rehashes.

        Side Effects:
            - Updates the internal state by removing the friend's username from the incoming location requests and rehash verification.
            - Updates the location status for the friend.
            - Sends a message to the friend indicating whether the location rehashes were verified and if the locations match.
        """
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

        my_latitude_rehashes = self._rehash_verification[friend_username]["latitude_rehashes"]
        my_longitude_rehashes = self._rehash_verification[friend_username]["longitude_rehashes"]

        latitudes_match = self._client_location.compare_hashes(friend_latitude_rehashes, my_latitude_rehashes)
        longitudes_match = self._client_location.compare_hashes(friend_longitude_rehashes, my_longitude_rehashes)
        location_matches = latitudes_match and longitudes_match

        logger.info(
            "Received location rehashes from '%s' Within radius: %s",
            friend_username,
            location_matches,
        )

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

    def handle_location_rehashes_verified(self, friend_username: str, location_matches: bool):
        """
        Handles the verification of location rehashes for a given friend.

        This method is called when location rehashes have been verified for a friend.
        It updates the internal state to reflect the verification status and logs the result.

        Args:
            friend_username (str): The username of the friend whose location rehashes have been verified.
            location_matches (bool): A boolean indicating whether the friend's location is within the specified radius.

        Returns:
            None
        """
        if friend_username not in self._outgoing_location_requests:
            logger.info("No location request sent to '%s'", friend_username)
            return
        self._outgoing_location_requests.pop(friend_username)
        self._location_statuses[friend_username] = location_matches
        logger.info(
            "Location rehashes verified by '%s'. Within radius: %s",
            friend_username,
            location_matches,
        )

    def add_friend(self, friend_username: str):
        """
        Adds a friend by their username.

        This method handles the process of adding a friend by checking if the user is already a friend,
        if a friend request has already been sent, or if there is an incoming friend request from the user.
        If none of these conditions are met, it sends a friend request to the specified user.

        Args:
            friend_username (str): The username of the friend to be added.

        Returns:
            None
        """
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

    def accept_friend_request(self, friend_username: str):
        """
        Accepts a friend request from the specified user.

        Args:
            friend_username (str): The username of the friend whose request is to be accepted.

        Returns:
            None

        Logs:
            - Info: If already friends with the specified user.
            - Info: If there is no friend request from the specified user.
        """
        if friend_username in self._friends:
            logger.info("Already friends with '%s'", friend_username)
            return

        if friend_username not in self._incoming_friend_requests:
            logger.info("No friend request from '%s'", friend_username)
            return

        self._web_client.post_accept_friend_request(friend_username)
        self._incoming_friend_requests.remove(friend_username)
        self._friends.add(friend_username)

    def friend_request_accepted(self, friend_username: str):
        """
        Handles the acceptance of a friend request.

        This method removes the specified friend username from the list of outgoing
        friend requests and adds it to the list of friends. It also logs the acceptance
        of the friend request.

        Args:
            friend_username (str): The username of the friend who accepted the request.
        """
        self._outgoing_friend_requests.remove(friend_username)
        self._friends.add(friend_username)
        logger.info("Friend request accepted by '%s'", friend_username)

    def request_location(self, friend_username: str, radius: float = 1.0):
        """
        Sends a location request to a specified friend within a given radius.

        Args:
            friend_username (str): The username of the friend to request location from.
            radius (float, optional): The radius within which to request the location. Defaults to 1.0.

        Returns:
            None

        Logs:
            - Info if the specified friend is not in the user's friend list.
            - Info if the radius is invalid (not a positive number).
            - Info if the address request for the friend fails.
            - Info if the address received does not match the friend's username.
            - Info when the location request is successfully sent.
        """
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

    def accept_location_request(self, friend_username: str):
        """
        Accepts a location request from a friend and sends the location response.

        Args:
            friend_username (str): The username of the friend who sent the location request.

        Returns:
            None

        Logs:
            Logs an info message if there is no location request from the specified friend.
            Logs an info message when the location response is sent to the specified friend.
        """
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
        rehashes["latitude_rehashes"] = tuple(json.loads(rehashes["latitude_rehashes"]))
        rehashes["longitude_rehashes"] = tuple(json.loads(rehashes["longitude_rehashes"]))
        self._rehash_verification[friend_username] = rehashes
        logger.info("Location response sent to '%s'", friend_username)

    def location_request_accepted(self, friend_username: str, key_2: str):
        """
        Handles the acceptance of a location request from a friend.

        This method is called when a friend accepts a location request. It verifies
        the request, rehashes the location data with the provided key, and sends the
        rehashed location data to the friend.

        Args:
            friend_username (str): The username of the friend who accepted the location request.
            key_2 (str): The second key used for rehashing the location data.

        Returns:
            None
        """
        if friend_username not in self._outgoing_location_requests:
            logger.info("No location request sent to '%s'", friend_username)
            return

        radius, key_1 = self._outgoing_location_requests[friend_username]
        latitude_hashes = self._client_location.latitude_hashes(radius, key_1)
        longitude_hashes = self._client_location.longitude_hashes(radius, key_1)

        key_2 = bytes.fromhex(key_2)
        latitude_rehashes = self._client_location.hash_state(latitude_hashes, key_2)
        longitude_rehashes = self._client_location.hash_state(longitude_hashes, key_2)

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
        """
        Retrieves and logs the location statuses of friends.

        Iterates through the `_location_statuses` dictionary, logging the location
        status for each friend.

        Returns:
            None
        """
        for friend, status in self._location_statuses.items():
            logger.info("Location status for '%s': %s", friend, status)
