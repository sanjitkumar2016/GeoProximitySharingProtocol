import zmq
import threading
from cryptography.fernet import Fernet

class ZMQClient:
    def __init__(self, encryption_key, receive_port):
        self.context = zmq.Context()
        self.cipher = Fernet(encryption_key)
        self.running = True
        self.socket = self.context.socket(zmq.PULL)
        self.socket.bind(f"tcp://*:{receive_port}")
        self.thread = threading.Thread(target=self._receive_messages)
        self.thread.start()

    def send_message(self, host, port, message):
        socket = self.context.socket(zmq.REQ)
        socket.connect(f"tcp://{host}:{port}")
        encrypted_message = self.cipher.encrypt(message.encode('utf-8'))
        socket.send(encrypted_message)
        response = socket.recv()
        socket.close()
        return self.cipher.decrypt(response).decode('utf-8')

    def _receive_messages(self):
        while self.running:
            try:
                message = self.socket.recv(zmq.NOBLOCK)
                self._parse_message(message)
            except zmq.Again:
                continue

    def _parse_message(self, message):
        decrypted_message = self.cipher.decrypt(message).decode('utf-8')
        print(f"Received message: {decrypted_message}")

    def stop(self):
        self.running = False
        self.thread.join()
        self.context.term()
