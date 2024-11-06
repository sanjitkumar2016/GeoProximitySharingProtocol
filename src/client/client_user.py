import asyncio

from aiortc.contrib.signaling import TcpSocketSignaling

from src.client.webrtc_client import WebRTCClient


class ClientUser:
    def __init__(self, username, host="localhost", port=8080):
        self.username = username
        self.host = host
        self.port = port
        self.signaling = TcpSocketSignaling(self.host, self.port)
        self.client = WebRTCClient(self.signaling, self.username)
        self.start()

    async def run(self):
        await self.client.connect()
        await self.client.send_message("Hello, peer!")
        await self.client.close()

    def start(self):
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.run())
        except KeyboardInterrupt:
            loop.run_until_complete(self.client.close())
