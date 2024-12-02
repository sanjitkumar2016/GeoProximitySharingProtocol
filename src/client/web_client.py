import logging
from base64 import b64decode, b64encode

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebClient:
    """
    A client for interacting with a web server for geo-proximity sharing protocol.

    Attributes:
        client_user: The user object representing the client.
        server_host (str): The hostname of the server.
        server_port (int): The port number of the server.
        base_url (str): The base URL constructed from the server host and port.
        _auth_token (str): The authentication token received after user creation.

    Methods:
        post_create_user(public_key):
            Creates a new user on the server with the provided public key.
        post_add_friend(target):
            Sends a request to add a friend with the specified username.
        post_accept_friend_request(target):
            Accepts a friend request from the specified username.
        get_address_request(target):
            Retrieves the address and public key of the specified username.
        post_accept_location_request(target, latitude_hashes, longitude_hashes):
            Accepts a location request and exchanges rehashed location data with the specified username.
    """

    def __init__(self, client_user, server_host: str, server_port: int):
        self.client_user = client_user
        self.server_host = server_host
        self.server_port = server_port
        self.base_url = f"https://{server_host}:{server_port}"
        self._auth_token = None

    def post_create_user(self, public_key: bytes):
        """
        Sends a POST request to create a new user on the server.

        Args:
            public_key (bytes): The public key of the user to be created, in bytes.

        Raises:
            requests.exceptions.RequestException: If the request fails for any reason.

        Side Effects:
            Sets the `_auth_token` attribute of the client if the request is successful.
            Logs the success or failure message.

        Returns:
            None
        """
        url = self.base_url + "/create_user"
        params = {
            "username": self.client_user.username,
            "host": self.client_user.host,
            "port": self.client_user.port,
        }
        encoded_public_key = b64encode(public_key).decode("utf-8")
        headers = {
            "Authorization": f"PublicKey {encoded_public_key}",
        }
        response = None
        try:
            response = requests.post(url, params=params, headers=headers, verify=False, timeout=5)
            response.raise_for_status()
            self._auth_token = response.json().get("auth_token")
            logger.info("Success! %s", response.json().get("message"))
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to create user: %s - %s", e, response.text)
            raise e

    def post_add_friend(self, target: str):
        """
        Sends a POST request to add a friend to the user's friend list.

        Args:
            target (str): The username of the friend to be added.

        Raises:
            requests.exceptions.RequestException: If the request fails for any reason.

        Logs:
            Info: When a friend is successfully added.
            Info: When the request to add a friend fails, including the error and response text.
        """
        url = self.base_url + "/add_friend"
        params = {"username": target}
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
        }
        response = None
        try:
            response = requests.post(url, params=params, headers=headers, verify=False, timeout=5)
            response.raise_for_status()
            logger.info("Added %s as a friend", target)
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to add friend: %s - %s", e, response.text)
            raise e

    def post_accept_friend_request(self, target: str):
        """
        Sends a POST request to accept a friend request from the specified user.

        Args:
            target (str): The username of the user whose friend request is to be accepted.

        Raises:
            requests.exceptions.RequestException: If there is an issue with the request.

        Logs:
            Info: When the friend request is successfully accepted.
            Info: When the friend request acceptance fails, including the error and response text.
        """
        url = self.base_url + "/accept_friend_request"
        params = {"username": target}
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
        }
        response = None
        try:
            response = requests.post(url, params=params, headers=headers, verify=False, timeout=5)
            response.raise_for_status()
            logger.info("Accepted friend request from %s", target)
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to accept friend request: %s - %s", e, response.text)
            raise e

    def get_address_request(self, target: str) -> dict:
        """
        Sends a GET request to retrieve the address of the specified target user.

        Args:
            target (str): The username of the target user whose address is being requested.

        Returns:
            dict: A dictionary containing the address information of the target user, including the public key.

        Raises:
            requests.exceptions.RequestException: If there is an issue with the request, such as a timeout or a failed response.

        Logs:
            Info: Logs the successful retrieval of the address.
            Info: Logs the failure to retrieve the address along with the error message and response text.
        """
        url = self.base_url + "/address_request"
        params = {"username": target}
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
        }
        response = None
        try:
            response = requests.get(url, params=params, headers=headers, verify=False, timeout=5)
            response.raise_for_status()
            logger.info("Received address for %s", target)
            address = response.json()
            address["public_key"] = b64decode(address["public_key"])
            return address
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to get address: %s - %s", e, response.text)
            raise e

    def post_accept_location_request(self, target: str, latitude_hashes: bytes, longitude_hashes: bytes) -> dict:
        """
        Sends a POST request to accept a location request and retrieve rehashed location data.

        Args:
            target (str): The username of the target user.
            latitude_hashes (bytes): The hashed latitude values.
            longitude_hashes (bytes): The hashed longitude values.

        Returns:
            dict: A dictionary containing the rehashed latitude and longitude values.

        Raises:
            requests.exceptions.RequestException: If the request fails for any reason.
        """
        url = self.base_url + "/accept_location_request"
        params = {
            "username": target,
            "latitude_hashes": b64encode(latitude_hashes).decode("utf-8"),
            "longitude_hashes": b64encode(longitude_hashes).decode("utf-8"),
        }
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
        }
        response = None
        try:
            response = requests.post(url, params=params, headers=headers, verify=False, timeout=5)
            response.raise_for_status()
            logger.info("Received rehashes from server for exchange with %s", target)
            rehashes = response.json()
            rehashes["latitude_rehashes"] = b64decode(rehashes["latitude_rehashes"])  # noqa: E501
            rehashes["longitude_rehashes"] = b64decode(rehashes["longitude_rehashes"])  # noqa: E501
            return rehashes
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to get rehashes: %s - %s", e, response.text)
            raise e
