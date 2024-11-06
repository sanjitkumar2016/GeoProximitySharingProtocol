from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import ssl

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebServer:
    def __init__(
        self,
        server_store,
        host="localhost",
        port=8080,
        certfile="cert.pem",
        keyfile="key.pem",
    ):
        self.server_store = server_store
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile

    class RequestHandler(BaseHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            self.server_store = kwargs.pop("server_store")
            super().__init__(*args, **kwargs)

        def do_POST(self):
            logger.info("POST request received")
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length)

            parsed_path = urlparse(self.path)
            path = parsed_path.path
            query_params = parse_qs(parsed_path.query)

            if path == "/create_user":
                self.handle_create_user(query_params)
            else:
                self.handle_not_found()

            self.end_headers()
            response = f"POST request received: {post_data.decode()}"
            self.wfile.write(response.encode())

        def do_GET(self):
            logger.info("GET request received")
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            query_params = parse_qs(parsed_path.query)

            if path == "/port_request":
                self.handle_port_request(query_params)
            else:
                self.handle_not_found()

        def handle_create_user(self, query_params):
            pass

        def handle_port_request(self, query_params):
            print(query_params)
            self.send_response(200)
            self.end_headers()
            data = "testing\n"
            response = f"Data: {data}"
            self.wfile.write(response.encode())

        def handle_not_found(self):
            self.send_response(404)
            self.end_headers()
            response = "404 Not Found"
            self.wfile.write(response.encode())

    def start(self):
        server = HTTPServer(
            (self.host, self.port),
            lambda *args, **kwargs: self.RequestHandler(
                *args, server_store=self.server_store, **kwargs
            ),
        )

        # Create an SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        # Wrap the server socket with SSL
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info("Starting server at http://%s:%d", self.host, self.port)
        server.serve_forever()
