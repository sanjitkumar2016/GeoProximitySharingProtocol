import logging
from aiortc import RTCPeerConnection
from aiortc.contrib.signaling import BYE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebRTCClient:
    def __init__(self, signaling, peer_id):
        self.signaling = signaling
        self.peer_id = peer_id
        self.pc = RTCPeerConnection()

        # Register event handlers
        self.pc.on("iceconnectionstatechange", self.on_iceconnectionstatechange)
        self.pc.on("datachannel", self.on_datachannel)

    async def connect(self):
        await self.signaling.connect()

        # Create an offer and set local description
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)

        # Send the offer to the signaling server
        await self.signaling.send(self.peer_id, self.pc.localDescription)

        # Wait for the answer
        answer = await self.signaling.receive()
        await self.pc.setRemoteDescription(answer)

    async def on_iceconnectionstatechange(self):
        logger.info(f"ICE connection state is {self.pc.iceConnectionState}")
        if self.pc.iceConnectionState == "failed":
            await self.pc.close()

    async def on_datachannel(self, channel):
        logger.info(f"Data channel created: {channel.label}")

        @channel.on("message")
        async def on_message(message):
            logger.info(f"Received message: {message}")
            if message == BYE:
                await self.pc.close()

    async def send_message(self, message):
        channel = self.pc.createDataChannel("chat")
        await channel.send(message)

    async def close(self):
        await self.pc.close()
        await self.signaling.close()
