import ipaddress
import logging

from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class WebServer:
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
            logger.debug("Handling create user with params: %s", query_params)

            username = query_params.get("username")
            host = query_params.get("host")
            port = query_params.get("port")

            authorization = request.headers.get("Authorization")
            if not authorization:
                return "PublicKey required", 401
            if not authorization.startswith("PublicKey "):
                return "Invalid authorization header", 401
            public_key = authorization[10:]

            if not username or not username.isalpha():
                return "Invalid username", 400
            if not host or not isinstance(host, str) or not ipaddress.ip_address(host):  # noqa: E501
                return "Invalid host", 400
            if not port or not port.isdigit() or int(port) < 0 or int(port) > 65535:  # noqa: E501
                return "Invalid port", 400
            if not public_key:
                return "Invalid public key", 400

            auth_token = self.server_store.post_create_user(
                username, host, int(port), public_key
            )
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
            logger.debug("Handling add friend with params: %s", query_params)
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
            logger.debug("Handling accept friend request with params: %s", query_params)  # noqa: E501
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
            logger.debug("Handling address request with params: %s", query_params)  # noqa: E501
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

            response = {
                "username": username,
                "host": address.get("host"),
                "port": address.get("port"),
            }
            return jsonify(response), 200

    def start(self):
        context = (self.certfile, self.keyfile)
        logger.info("Starting server at https://%s:%d", self.host, self.port)
        app.run(host=self.host, port=self.port, ssl_context=context)
