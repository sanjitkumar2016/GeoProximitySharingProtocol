import json
import math
import secrets

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

MILES_PER_DEGREE = 69


class ClientLocation:
    def __init__(self):
        self._location_url = "http://localhost:8000/current_location"
        self.update_current_location()

    def _get_state(self, val: float) -> tuple:
        return math.floor(val), round(val), math.ceil(val)

    def generate_key(self) -> bytes:
        return secrets.token_bytes(64)

    def update_current_location(self):
        self._current_location = json.loads(
            requests.get(self._location_url).text
        )

    def latitude_values(self, radius) -> tuple:
        latitude = (self._current_location["latitude"] + 90)
        latitude = latitude * MILES_PER_DEGREE / radius
        return self._get_state(latitude)

    def longitude_values(self, radius) -> tuple:
        longitude = (self._current_location["longitude"] + 180)
        longitude = longitude * MILES_PER_DEGREE / radius
        return self._get_state(longitude)

    def latitude_hashes(self, radius, key) -> tuple:
        return self.hash_state(self.latitude_values(radius), key)

    def longitude_hashes(self, radius, key) -> tuple:
        return self.hash_state(self.longitude_values(radius), key)

    def hash_state(self, state: tuple, key: bytes) -> tuple:
        hashed_state = []
        for val in state:
            h = HMAC(key, hashes.SHA256())
            h.update(str(val).encode())
            hashed_state.append(h.finalize().hex())
        return tuple(hashed_state)

    def compare_hashes(self, hashes_1: tuple, hashes_2: tuple) -> bool:
        down_1, nearest_1, up_1 = hashes_1
        d2, n2, u2 = hashes_2
        # Check rounded values and nearest values
        if nearest_1 in hashes_2 or n2 in hashes_1:
            return True
        # Check for same down/up values
        if down_1 == d2 or up_1 == u2:
            return True
        return False
