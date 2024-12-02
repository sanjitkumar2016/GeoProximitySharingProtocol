import json
import logging
import threading

from src.server.server_crypto import ServerCrypto
from src.server.web_server import WebServer
from src.server.zmq_server import ZMQServer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServerStore:
    """
    ServerStore is a class that manages user data, friend requests, and location sharing for a server.

    Attributes:
        _server_crypto (ServerCrypto): An instance of the ServerCrypto class for cryptographic operations.
        _zmq_server (ZMQServer): An instance of the ZMQServer class for ZeroMQ messaging.
        _users (set): A set of hashed usernames representing registered users.
        _users_address (dict): A dictionary mapping hashed usernames to their address and public key information.
        _friends_map (dict): A dictionary mapping hashed usernames to their friends' hashed usernames.
        _active_friends_requests (dict): A dictionary mapping hashed usernames to their active friend requests.
        web_server (WebServer): An instance of the WebServer class for handling web requests.
        server_thread (threading.Thread): A thread for running the web server.

    Methods:
        __init__(host: str = "127.0.0.1", port: int = 8080):
            Initializes the ServerStore instance with the given host and port, and starts the web server.
        _init_user_vars():
            Initializes user-related variables.
        _start_web_server(host="127.0.0.1", port=8080):
            Starts the web server on the specified host and port.
        post_create_user(username: str, host: str, port: int, public_key: bytes) -> bytes:
            Creates a new user in the server store and returns an authentication token.
        post_add_friend(auth_token: bytes, target: str) -> bool:
        post_accept_friend_request(auth_token: bytes, username: str) -> bool:
        get_address_request(auth_token: bytes, target: str) -> tuple:
        post_accept_location_request(auth_token: bytes, target: str, latitude_hashes: bytes, longitude_hashes: bytes) -> dict:
            Handles the acceptance of a location request by verifying the requester and target, rehashing the provided latitude and longitude hashes, and sending a message to the target.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self._server_crypto = ServerCrypto()
        self._zmq_server = ZMQServer()
        self._init_user_vars()
        self._start_web_server(host=host, port=port)

    def _init_user_vars(self):
        self._users = set()
        self._users_address = {}
        self._friends_map = {}
        self._active_friends_requests = {}

    def _start_web_server(self, host: str = "127.0.0.1", port: int = 8080):
        self.web_server = WebServer(self, host=host, port=port)
        self.server_thread = threading.Thread(target=self.web_server.start)
        self.server_thread.start()
        logger.info("Web server started")

    def post_create_user(self, username: str, host: str, port: int, public_key: bytes) -> bytes:
        """
        Creates a new user in the server store.

        This method registers a new user by their username, host, port, and public key.
        It ensures that the username is unique by hashing it and checking against existing users.
        If the username already exists, it returns None. Otherwise, it adds the user to the store,
        initializes their friends map and active friend requests, and logs the creation event.

        Args:
            username (str): The username of the new user.
            host (str): The host address of the new user.
            port (int): The port number of the new user.
            public_key (bytes): The public key of the new user in PEM format.

        Returns:
            bytes: An authentication token for the new user, or None if the username already exists.
        """
        username = username.lower()
        username_hash = self._server_crypto.hash_data(username)
        if username_hash in self._users:
            return None

        self._users.add(username_hash)
        self._users_address[username_hash] = {
            "host": host,
            "port": port,
            "public_key": self._zmq_server.public_key_from_pem(public_key),
        }
        self._friends_map[username_hash] = set()
        self._active_friends_requests[username_hash] = set()
        logger.info("User '%s' created at address %s:%s", username, host, port)

        auth_token = self._server_crypto.encrypt_data(username)
        return auth_token

    def post_add_friend(self, auth_token: bytes, target: str) -> bool:
        """
        Handles the process of adding a friend by sending a friend request.

        Args:
            auth_token (str): The authentication token of the requester.
            target (str): The identifier of the target user to be added as a friend.

        Returns:
            bool: True if the friend request was successfully sent, False otherwise.

        Raises:
            DecryptionError: If the auth_token cannot be decrypted.
            KeyError: If the requester or target user is not found in the user database.
        """
        requester = self._server_crypto.decrypt_data(auth_token)
        requester_hash = self._server_crypto.hash_data(requester)
        target_hash = self._server_crypto.hash_data(target)

        if requester_hash not in self._users or target_hash not in self._users:
            return False
        if target_hash in self._friends_map[requester_hash]:
            return False

        self._active_friends_requests[requester_hash].add(target_hash)
        logger.info("Friend request from '%s' to '%s'", requester, target)
        self._zmq_server.send_message(
            self._users_address[target_hash]["host"],
            self._users_address[target_hash]["port"],
            json.dumps({"friend_request": requester}),
            self._users_address[target_hash]["public_key"],
        )
        return True

    def post_accept_friend_request(self, auth_token, username) -> bool:
        """
        Accepts a friend request for the given user.

        Args:
            auth_token (str): The authentication token of the target user.
            username (str): The username of the requester.

        Returns:
            bool: True if the friend request was successfully accepted, False otherwise.

        Raises:
            None

        This method performs the following steps:
        1. Decrypts the authentication token to get the target user's identifier.
        2. Hashes the target user's identifier and the requester's username.
        3. Checks if both users exist in the system.
        4. Checks if there is an active friend request from the requester to the target.
        5. Adds each user to the other's friend list.
        6. Removes the friend request from the active requests list.
        7. Sends a message to the requester indicating that the friend request was accepted.
        8. Logs the acceptance of the friend request.

        Note:
            This method assumes that the server's cryptographic and messaging systems are properly initialized and configured.
        """
        target = self._server_crypto.decrypt_data(auth_token)
        target_hash = self._server_crypto.hash_data(target)
        requester_hash = self._server_crypto.hash_data(username)

        if requester_hash not in self._users or target_hash not in self._users:
            return False
        if target_hash not in self._active_friends_requests[requester_hash]:
            return False

        self._friends_map[requester_hash].add(target_hash)
        self._friends_map[target_hash].add(requester_hash)
        self._active_friends_requests[requester_hash].remove(target_hash)
        self._zmq_server.send_message(
            self._users_address[requester_hash]["host"],
            self._users_address[requester_hash]["port"],
            json.dumps({"friend_request_accepted": target}),
            self._users_address[requester_hash]["public_key"],
        )
        logger.info("Friend request accepted from '%s' to '%s'", username, target)  # noqa: E501
        return True

    def get_address_request(self, auth_token, target) -> tuple:
        """
        Retrieves the address information for a target user if the requester is authorized.

        Args:
            auth_token (str): The authentication token of the requester.
            target (str): The identifier of the target user.

        Returns:
            tuple: A tuple containing the host, port, and public key of the target user if the requester is authorized.
                   Returns None if the requester or target is not found, or if the requester is not a friend of the target.
        """
        requester = self._server_crypto.decrypt_data(auth_token)
        requester_hash = self._server_crypto.hash_data(requester)
        target_hash = self._server_crypto.hash_data(target)

        if requester_hash not in self._users or target_hash not in self._users:
            return None
        if requester_hash not in self._friends_map[target_hash]:
            return None

        host = self._users_address[target_hash]["host"]
        port = self._users_address[target_hash]["port"]
        public_key = self._users_address[target_hash]["public_key"]

        return host, port, self._zmq_server.public_key_to_pem(public_key)

    def post_accept_location_request(
        self, auth_token: bytes, target: str, latitude_hashes: bytes, longitude_hashes: bytes
    ) -> dict:
        """
        Handles the acceptance of a location request by verifying the requester and target,
        rehashing the provided latitude and longitude hashes, and sending a message to the target.

        Args:
            auth_token (bytes): The authentication token of the requester.
            target (str): The target user for the location request.
            latitude_hashes (bytes): The latitude hashes to be rehashed.
            longitude_hashes (bytes): The longitude hashes to be rehashed.

        Returns:
            dict: A dictionary containing the rehashed latitude and longitude hashes if the request is valid.
                  Returns False if the requester or target is not valid or if the target is not a friend of the requester.
        """
        requester = self._server_crypto.decrypt_data(auth_token)
        requester_hash = self._server_crypto.hash_data(requester)
        target_hash = self._server_crypto.hash_data(target)

        if requester_hash not in self._users or target_hash not in self._users:
            return False
        if target_hash not in self._friends_map[requester_hash]:
            return False

        latitude_hashes = json.loads(latitude_hashes)
        longitude_hashes = json.loads(longitude_hashes)
        key = self._zmq_server.generate_key()

        rehashes = {}
        rehashes["latitude_rehashes"] = json.dumps(self._zmq_server.hash_state(latitude_hashes, key)).encode("utf-8")
        rehashes["longitude_rehashes"] = json.dumps(self._zmq_server.hash_state(longitude_hashes, key)).encode("utf-8")

        self._zmq_server.send_message(
            self._users_address[target_hash]["host"],
            self._users_address[target_hash]["port"],
            json.dumps({"location_request_accepted": requester, "key": key.hex()}),
            self._users_address[target_hash]["public_key"],
        )
        logger.info("Location request from '%s' to '%s'", requester, target)
        return rehashes
