import json

import requests

MILES_PER_DEGREE = 69


class ClientLocation:
    def __init__(self):
        self._location_url = "http://localhost:8000/current_location"
        self.get_current_location()

    def get_current_location(self):
        self._current_location = json.loads(requests.get(self._location_url).text)  # noqa: E501
        return self._current_location

    def normalize_latitude(self, latitude, radius=1):
        return (latitude + 90) * MILES_PER_DEGREE / radius

    def normalize_longitude(self, longitude, radius=1):
        return (longitude + 180) * MILES_PER_DEGREE / radius
