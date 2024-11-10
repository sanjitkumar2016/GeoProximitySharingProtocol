import base64
import logging
import threading

from src.server.server_crypto import ServerCrypto
from src.server.web_server import WebServer
from src.server.zmq_server import ZMQServer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServerStore:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.server_crypto = ServerCrypto()
        self.zmq_server = ZMQServer()
        self._init_user_vars()
        self._start_web_server(host=host, port=port)

    def _init_user_vars(self):
        self._users = set()
        self._users_address = {}
        self._users_public_key = {}
        self._friends_map = {}
        self._active_friends_requests = {}

    def _start_web_server(self, host="127.0.0.1", port=8080):
        self.web_server = WebServer(self, host=host, port=port)
        self.server_thread = threading.Thread(target=self.web_server.start)
        self.server_thread.start()
        logger.debug("Web server started")

    def post_create_user(self, username, host, port, public_key):
        username = username.lower()
        username_hash = self.server_crypto.hash_data(username)
        if username_hash in self._users:
            return None

        public_key = base64.b64decode(public_key)
        self._users.add(username_hash)
        self._users_address[username_hash] = {"host": host, "port": port}
        self._users_public_key[username_hash] = self.zmq_server.public_key_from_pem(public_key)  # noqa: E501
        self._friends_map[username_hash] = set()
        self._active_friends_requests[username_hash] = set()
        logger.info("User %s created at address %s:%s", username, host, port)

        auth_token = self.server_crypto.encrypt_data(username)
        return auth_token

    def post_add_friend(self, auth_token, target):
        requester = self.server_crypto.decrypt_data(auth_token)
        requester_hash = self.server_crypto.hash_data(requester)
        target_hash = self.server_crypto.hash_data(target)

        if requester_hash not in self._users or target_hash not in self._users:
            return False
        self._active_friends_requests[requester_hash].add(target_hash)
        # TODO: send out friend request to target using MQ on target's port
        self.zmq_server.send_message(
            self._users_address[target_hash]["host"],
            self._users_address[target_hash]["port"],
            requester,
            self._users_public_key[target_hash],
        )
        return True

    def get_address_request(self, auth_token, target):
        requester = self.server_crypto.decrypt_data(auth_token)
        requester_hash = self.server_crypto.hash_data(requester)
        target_hash = self.server_crypto.hash_data(target)

        if requester_hash not in self._users or target_hash not in self._users:
            return None
        if requester_hash not in self._friends_map[target_hash]:
            return None
        return self._users_address[target_hash]
