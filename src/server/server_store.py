import logging
import threading

from src.server.web_server import WebServer
from src.server.server_crypto import ServerCrypto

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServerStore:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.server_crypto = ServerCrypto()
        self._init_user_vars()
        self._start_web_server(host=host, port=port)

    def _init_user_vars(self):
        self._salt = self.server_crypto.create_salt()
        self._key = self.server_crypto.create_symmetric_key()
        self._users = set()
        self._users_address = {}
        self._friends_map = {}
        self._active_friends_requests = {}

    def _start_web_server(self, host="127.0.0.1", port=8080):
        self.web_server = WebServer(self, host=host, port=port)
        self.server_thread = threading.Thread(target=self.web_server.start)
        self.server_thread.start()
        logger.debug("Web server started")

    def post_create_user(self, username, host, port):
        username = username.lower()
        username_hash = self.server_crypto.hash_data(username, self._salt)
        if username_hash in self._users:
            return None

        self._users.add(username_hash)
        self._users_address[username_hash] = {"host": host, "port": port}
        self._friends_map[username_hash] = set()
        self._active_friends_requests[username_hash] = set()

        auth_token = self.server_crypto.encrypt_data(username, self._key)
        return auth_token

    def post_add_friend(self, auth_token, target):
        requester = self.server_crypto.decrypt_data(auth_token, self._key)
        requester_hash = self.server_crypto.hash_data(requester, self._salt)
        target_hash = self.server_crypto.hash_data(target, self._salt)

        if requester_hash not in self._users or target_hash not in self._users:
            return False
        self._active_friends_requests[requester_hash].add(target_hash)
        # TODO: send out friend request to target using message queue on target's port
        return True

    def get_address_request(self, auth_token, target):
        requester = self.server_crypto.decrypt_data(auth_token, self._key)
        requester_hash = self.server_crypto.hash_data(requester, self._salt)
        target_hash = self.server_crypto.hash_data(target, self._salt)

        if requester_hash not in self._users or target_hash not in self._users:
            return None
        if requester_hash not in self._friends_map[target_hash]:
            return None
        return self._users_address[target_hash]
