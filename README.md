# GeoProximitySharingProtocol
Project to test an algorithm that allows users to check their proximity from one another without sharing their actual location

## Creating keys
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Getting location
https://github.com/RhetTbull/locationator?tab=readme-ov-file
curl http://localhost:8000/current_location