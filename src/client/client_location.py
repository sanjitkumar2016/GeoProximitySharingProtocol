import json
import math
import secrets

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

MILES_PER_DEGREE = 69


class ClientLocation:
    """
    A class to represent the client's location and provide methods to handle location-based operations.
    Attributes:
        _location_url (str): The URL to fetch the current location.
        _current_location (dict): The current location data.
    Methods:
        __init__():
            Initializes the ClientLocation instance and updates the current location.
        _get_state(val: float) -> tuple:
            Returns the floor, rounded, and ceiling values of the given float.
        generate_key() -> bytes:
            Generates a 64-byte cryptographic key using a secure random number generator.
        update_current_location():
            Updates the current location of the client by sending a GET request to the specified URL.
        latitude_values(radius: float) -> tuple:
            Calculates and returns the state based on the latitude value adjusted by the given radius.
        longitude_values(radius: float) -> tuple:
            Calculates and returns the state based on the longitude value adjusted by the given radius.
        latitude_hashes(radius: float, key: bytes) -> tuple:
            Computes the hashed values of latitude coordinates within a given radius using the provided key.
        longitude_hashes(radius: float, key: bytes) -> tuple:
            Computes the hashed values of longitude coordinates within a given radius using the provided key.
        hash_state(state: tuple, key: bytes) -> tuple:
            Hashes the given state values using the provided key and returns the hashed values.
        compare_hashes(hashes_1: tuple, hashes_2: tuple) -> bool:
            Compares two sets of hashed values and returns True if they match based on specific criteria.
    """

    def __init__(self):
        self._location_url = "http://localhost:8000/current_location"
        self.update_current_location()

    def _get_state(self, val: float) -> tuple:
        return math.floor(val), round(val), math.ceil(val)

    def generate_key(self) -> bytes:
        """
        Generates a cryptographic key.

        This method generates a 64-byte cryptographic key using a secure random number generator.

        Returns:
            bytes: A 64-byte cryptographic key.
        """
        return secrets.token_bytes(64)

    def update_current_location(self):
        """
        Updates the current location of the client.

        This method sends a GET request to the URL specified by `_location_url` and
        updates the `_current_location` attribute with the JSON response.

        Raises:
            requests.exceptions.RequestException: If there is an issue with the GET request.
            json.JSONDecodeError: If the response is not valid JSON.
        """
        self._current_location = json.loads(requests.get(self._location_url).text)

    def latitude_values(self, radius: float) -> tuple:
        """
        Calculate and return the state based on the latitude value adjusted by the given radius.

        Args:
            radius (float): The radius value used to adjust the latitude.

        Returns:
            tuple: The state corresponding to the adjusted latitude value.
        """
        latitude = self._current_location["latitude"] + 90
        latitude = latitude * MILES_PER_DEGREE / radius
        return self._get_state(latitude)

    def longitude_values(self, radius: float) -> tuple:
        """
        Calculate the longitude values based on the current location and given radius.

        Args:
            radius (float): The radius within which to calculate the longitude values.

        Returns:
            tuple: A tuple representing the state based on the calculated longitude value.
        """
        longitude = self._current_location["longitude"] + 180
        longitude = longitude * MILES_PER_DEGREE / radius
        return self._get_state(longitude)

    def latitude_hashes(self, radius: float, key: bytes) -> tuple:
        """
        Computes the hashed values of latitude coordinates within a given radius.

        Args:
            radius (float): The radius within which to compute latitude values.
            key (bytes): The key used for hashing the latitude values.

        Returns:
            tuple: A tuple containing the hashed latitude values.
        """
        return self.hash_state(self.latitude_values(radius), key)

    def longitude_hashes(self, radius: float, key: bytes) -> tuple:
        """
        Generates hashed values for longitude based on a given radius and key.

        Args:
            radius (float): The radius within which to generate longitude values.
            key (bytes): The key used for hashing the longitude values.

        Returns:
            tuple: A tuple containing the hashed longitude values.
        """
        return self.hash_state(self.longitude_values(radius), key)

    def hash_state(self, state: tuple, key: bytes) -> tuple:
        """
        Hashes each element in the given state tuple using HMAC with SHA-256.

        Args:
            state (tuple): A tuple containing the elements to be hashed.
            key (bytes): The key to be used for the HMAC.

        Returns:
            tuple: A tuple containing the hashed elements as hexadecimal strings.
        """
        hashed_state = []
        for val in state:
            h = HMAC(key, hashes.SHA256())
            h.update(str(val).encode())
            hashed_state.append(h.finalize().hex())
        return tuple(hashed_state)

    def compare_hashes(self, hashes_1: tuple, hashes_2: tuple) -> bool:
        """
        Compares two sets of location hashes to determine if they are considered equivalent.

        Args:
            hashes_1 (tuple): A tuple containing three hash values (down_1, nearest_1, up_1).
            hashes_2 (tuple): A tuple containing three hash values (down_2, nearest_2, up_2).

        Returns:
            bool: True if the hashes are considered equivalent, False otherwise.

        The function checks for equivalence by:
        1. Checking if the nearest value of one set is in the other set.
        2. Checking if the down or up values of one set match the corresponding values in the other set.
        """
        down_1, nearest_1, up_1 = hashes_1
        down_2, nearest_2, up_2 = hashes_2
        # Check rounded values and nearest values
        if nearest_1 in hashes_2 or nearest_2 in hashes_1:
            return True
        # Check for same down/up values
        if down_1 == down_2 or up_1 == up_2:
            return True
        return False
