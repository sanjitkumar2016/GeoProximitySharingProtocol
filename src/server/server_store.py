import logging
import threading
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from src.server.web_server import WebServer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServerStore:
    def __init__(self, host="localhost", port=8080):
        self._init_user_vars()
        self._create_keys()
        self._start_web_server(host=host, port=port)

    def _init_user_vars(self):
        self._salt = secrets.token_hex(16)
        self._users = set()
        self._user_ports = {}
        self._friends_map = {}
        self._active_friends_requests = {}

    def _create_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        logger.debug("Keys created")

    def _start_web_server(self, host="localhost", port=8080):
        self.web_server = WebServer(self, host=host, port=port)
        self.server_thread = threading.Thread(target=self.web_server.start)
        self.server_thread.start()
        logger.debug("Web server started")
