import ipaddress
import logging
from base64 import b64decode, b64encode

from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class WebServer:
    """
    A class to represent a web server for handling user and friend management.

    Attributes:
        server_store (object): An instance of the server store to handle data operations.
        host (str): The hostname or IP address to bind the server to. Defaults to "127.0.0.1".
        port (int): The port number to bind the server to. Defaults to 8080.
        certfile (str): The path to the SSL certificate file. Defaults to "cert.pem".
        keyfile (str): The path to the SSL key file. Defaults to "key.pem".

    Methods:
        create_user():
            Handles the creation of a new user.
        add_friend():
            Handles sending a friend request to another user.
        accept_friend_request():
            Handles accepting a friend request from another user.
        address_request():
            Handles retrieving the address of a user.
        accept_location_request():
            Handles accepting a location request from another user.
        start():
            Starts the web server with SSL context.
    """

    def __init__(
        self,
        server_store,
        host="127.0.0.1",
        port=8080,
        certfile="cert.pem",
        keyfile="key.pem",
    ):
        self.server_store = server_store
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

        @app.route("/create_user", methods=["POST"])
        def create_user():
            query_params = request.args
            logger.info("Handling create user with params: %s", query_params)

            username = query_params.get("username")
            host = query_params.get("host")
            port = query_params.get("port")

            authorization = request.headers.get("Authorization")
            if not authorization:
                return "PublicKey required", 401
            if not authorization.startswith("PublicKey "):
                return "Invalid authorization header", 401
            public_key = b64decode(authorization[10:])

            if not username or not username.isalpha():
                return "Invalid username", 400
            if not host or not isinstance(host, str) or not ipaddress.ip_address(host):  # noqa: E501
                return "Invalid host", 400
            if not port or not port.isdigit() or int(port) < 0 or int(port) > 65535:  # noqa: E501
                return "Invalid port", 400
            if not public_key:
                return "Invalid public key", 400

            auth_token = self.server_store.post_create_user(username, host, int(port), public_key)
            if not auth_token:
                return "User already exists", 400

            response = {
                "message": f"User {username} created at address {host}:{port}",
                "auth_token": auth_token.hex(),
            }
            return jsonify(response), 201

        @app.route("/add_friend", methods=["POST"])
        def add_friend():
            query_params = request.args
            logger.info("Handling add friend with params: %s", query_params)
            username = query_params.get("username")

            authorization = request.headers.get("Authorization")
            if not authorization:
                return "Unauthorized", 401
            if not authorization.startswith("Bearer "):
                return "Invalid authorization header", 401
            auth_token = bytes.fromhex(authorization[7:])

            success = self.server_store.post_add_friend(auth_token, username)
            if not success:
                return "Bad friend request", 400

            return f"Friend request sent to {username}", 200

        @app.route("/accept_friend_request", methods=["POST"])
        def accept_friend_request():
            query_params = request.args
            logger.info("Handling accept friend request with params: %s", query_params)  # noqa: E501
            username = query_params.get("username")

            authorization = request.headers.get("Authorization")
            if not authorization:
                return "Unauthorized", 401
            if not authorization.startswith("Bearer "):
                return "Invalid authorization header", 401
            auth_token = bytes.fromhex(authorization[7:])

            success = self.server_store.post_accept_friend_request(auth_token, username)  # noqa: E501
            if not success:
                return "Bad friend request", 400

            return f"Friend request accepted from {username}", 200

        @app.route("/address_request", methods=["GET"])
        def address_request():
            query_params = request.args
            logger.info("Handling address request with params: %s", query_params)  # noqa: E501
            username = query_params.get("username")

            authorization = request.headers.get("Authorization")
            if not authorization:
                return "Unauthorized", 401
            if not authorization.startswith("Bearer "):
                return "Invalid authorization header", 401
            auth_token = bytes.fromhex(authorization[7:])

            address = self.server_store.get_address_request(auth_token, username)  # noqa: E501
            if not address:
                return "Bad address request", 400

            host, port, public_key = address

            response = {
                "username": username,
                "host": host,
                "port": port,
                "public_key": b64encode(public_key).decode("utf-8"),
            }
            return jsonify(response), 200

        @app.route("/accept_location_request", methods=["POST"])
        def accept_location_request():
            query_params = request.args
            logger.info("Handling accept location request with params: %s", query_params)
            username = query_params.get("username")
            latitude_hashes = b64decode(query_params.get("latitude_hashes")).decode("utf-8")
            longitude_hashes = b64decode(query_params.get("longitude_hashes")).decode("utf-8")

            authorization = request.headers.get("Authorization")
            if not authorization:
                return "Unauthorized", 401
            if not authorization.startswith("Bearer "):
                return "Invalid authorization header", 401
            auth_token = bytes.fromhex(authorization[7:])

            if not latitude_hashes or not longitude_hashes:
                return "Bad location request", 400

            rehashes = self.server_store.post_accept_location_request(
                auth_token, username, latitude_hashes, longitude_hashes
            )

            if not rehashes:
                return "Unable to rehash", 400

            latitude_rehashes = rehashes["latitude_rehashes"]
            longitude_rehashes = rehashes["longitude_rehashes"]
            response = {
                "latitude_rehashes": b64encode(latitude_rehashes).decode("utf-8"),  # noqa: E501
                "longitude_rehashes": b64encode(longitude_rehashes).decode("utf-8"),  # noqa: E501
            }

            return jsonify(response), 200

    def start(self):
        """
        Starts the web server with SSL context.

        This method initializes the SSL context using the provided certificate
        and key files, and then starts the Flask application on the specified
        host and port.

        Raises:
            Exception: If there is an issue starting the server.

        Logs:
            Info: Logs the server start message with the host and port details.
        """
        context = (self.certfile, self.keyfile)
        logger.info("Starting server at https://%s:%d", self.host, self.port)
        app.run(host=self.host, port=self.port, ssl_context=context)
