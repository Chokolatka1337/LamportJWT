# LamportJWT

A Python module that implements a **one-time signature-based JWT** using **Lamport signatures**.
## Installation

Clone this repository and install it as a dependency using GitHub:
```sh
git clone https://github.com/Chokolatka1337/LamportJWT.git
```

Or add it to your `requirements.txt`:
`git+https://github.com/Chokolatka1337/LamportJWT.git#egg=LamportJWT`

## Usage Example

A full example of how to use this module is provided in the **`example/`** folder.

Basic usage:
```python
from lamport_jwt.jwt import LamportJWT

# Generate a new private key (only needed once)
LamportJWT.generate_private_key("private_key.json")

# Create a signed JWT
payload = {"user": "alice", "role": "admin"}
token = LamportJWT.encode(payload, "private_key.json")
print("Generated JWT:", token)

# Decode and verify the JWT
decoded_payload = LamportJWT.decode(token, "private_key.json")
print("Decoded payload:", decoded_payload)
```

## Example API

In the **`example/`** folder, there is a simple **Flask API** demonstrating LamportJWT authentication.

To run the example:
```sh
pip install requirements.txt
python -m example.app
```

Then, access the API at `http://127.0.0.1:5000/`.

Example of a request to create a token with payload:

```sh
curl -X POST http://127.0.0.1:5000/generate_token \
    -H "Content-Type: application/json" \
    -d '{"user_id": 123, "role": "admin"}'
```

Response example:
```json
{
    "token": "YOUR_GENERATED_JWT_TOKEN"
}
```

Example of a token verification request:
```sh
curl -X POST http://127.0.0.1:5000/verify_token \
    -H "Content-Type: application/json" \
    -d '{"token": "YOUR_GENERATED_JWT_TOKEN"}'
```

Response example (if the token is valid):
```json
{
    "payload": {
        "user_id": 123,
        "role": "admin"
    }
}
```
