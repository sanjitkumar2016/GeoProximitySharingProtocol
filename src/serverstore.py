import json
from threading import Thread

import zmq


class ServerStore:
    """
    A class to store and manage public keys and ports for users.
    """

    def __init__(self, zmq_port=5555):
        """
        Initializes the ServerStore with an empty dictionary and starts the ZeroMQ listener.

        Args:
            zmq_port (int, optional): Port number for ZeroMQ listener to bind to. Defaults to 5555.
        """
        # ServerStore attributes
        self.ids = {}
        self.keys = {}
        self.ports = {}

        # Message Queue
        self.zmq_port = zmq_port
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REP)
        self.socket.bind(f"tcp://*:{self.zmq_port}")

        # Start the listener thread
        self.listener_thread = Thread(target=self._listen_for_keys)
        self.listener_thread.daemon = True
        self.listener_thread.start()

    def _listen_for_keys(self):
        """
        Listens for incoming messages on ZeroMQ and updates the key store.
        """
        while True:
            message = self.socket.recv_string()
            try:
                data = json.loads(message)
                command = data.get("command")
                if command == "set":
                    self._set_data(data)
                elif command == "get":
                    self._get_data(data)
                else:
                    self.socket.send_string("Invalid command")
            except json.JSONDecodeError:
                self.socket.send_string("Invalid JSON format")

    def _set_data(self, data):
        """
        Parses the incoming set command and extracts user, key, and port.

        Args:
            message (dict): The JSON message as a dict.

        Returns:
            tuple: A tuple containing user, key, and port.
        """
        user = data.get("user")
        key = data.get("key")
        port = data.get("port")
        if user and key and port:
            self.set_key(user, key)
            self.set_port(user, port)
            self.socket.send_string("200 - Key added successfully")
        else:
            self.socket.send_string("400 - Invalid data format")

    def _get_data(self, data):
        user = data.get("user")
        if not user:
            self.socket.send_string("404 - User not found")
            return

        key = self.get_key(user)
        port = self.get_port(user)
        if key and port:
            response = {"user": user, "key": key, "port": port}
            self.socket.send_string(json.dumps(response))

    def set_key(self, user, key):
        """
        Sets the public key for a specific user.

        Args:
            user (str): The user identifier.
            key (str): The public key to be stored.
        """
        self.keys[user] = key

    def get_key(self, user) -> str | None:
        """
        Gets the public key for a specific user.

        Args:
            user (str): The user identifier.

        Returns:
            str: The public key for the user, or None if the user does not exist.
        """
        return self.keys.get(user)

    def set_port(self, user, port):
        """
        Sets the port for a specific user.

        Args:
            user (str): The user identifier.
            port (int): The port to be stored.
        """
        self.ports[user] = port

    def get_port(self, user) -> int | None:
        """
        Gets the port for a specific user.

        Args:
            user (str): The user identifier.

        Returns:
            int: The port for the user, or None if the user does not exist.
        """
        return self.ports.get(user)
