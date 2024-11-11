import base64
import logging

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebClient:
    def __init__(self, client_user, server_host: str, server_port: int):
        self.client_user = client_user
        self.server_host = server_host
        self.server_port = server_port
        self.base_url = f"https://{server_host}:{server_port}"
        self._auth_token = None

    def post_create_user(self, public_key):
        url = self.base_url + "/create_user"
        params = {
            "username": self.client_user.username,
            "host": self.client_user.host,
            "port": self.client_user.port,
        }
        encoded_public_key = base64.b64encode(public_key).decode("utf-8")
        headers = {
            "Authorization": f"PublicKey {encoded_public_key}",
        }
        response = None
        try:
            response = requests.post(
                url, params=params, headers=headers, verify=False, timeout=5
            )
            response.raise_for_status()
            self._auth_token = response.json().get("auth_token")
            logger.info("Success! %s", response.json().get("message"))
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to create user: %s - %s", e, response.text)
            raise e

    def post_add_friend(self, target: str):
        url = self.base_url + "/add_friend"
        params = {
            "username": target
        }
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
        }
        response = None
        try:
            response = requests.post(
                url, params=params, headers=headers, verify=False, timeout=5
            )
            response.raise_for_status()
            logger.info("Added %s as a friend", target)
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to add friend: %s - %s", e, response.text)
            raise e

    def post_accept_friend_request(self, friend_username: str):
        url = self.base_url + "/accept_friend_request"
        params = {
            "username": friend_username
        }
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
        }
        response = None
        try:
            response = requests.post(
                url, params=params, headers=headers, verify=False, timeout=5
            )
            response.raise_for_status()
            logger.info("Accepted friend request from %s", friend_username)
        except requests.exceptions.RequestException as e:
            if response:
                logger.info("Failed to accept friend request: %s - %s", e, response.text)  # noqa: E501
            raise e
