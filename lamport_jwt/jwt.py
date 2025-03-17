import json
import hashlib
import secrets
import base64 
from typing import List, Dict, Any, Optional, Tuple


class InvalidKeyError(Exception):
    pass

class InvalidTokenError(Exception):
    pass

class SignatureVerificationError(Exception):
    pass

class LamportJWT:

    HASH_FUNC = hashlib.md5
    KEY_SIZE = HASH_FUNC().digest_size * 8
    DEFAULT_KEY_FILE = "private_key.json"

    @staticmethod
    def _validate_private_key(private_key: List[Tuple[bytes, bytes]]) -> None:
        if not isinstance(private_key, list) or len(private_key) != LamportJWT.KEY_SIZE:
            raise InvalidKeyError("The private key must contain 256 pairs of values.")

        for pair in private_key:
            if not (isinstance(pair, tuple) and len(pair) == 2):
                raise InvalidKeyError("Each key entry must be a tuple of two elements.")
            if not (isinstance(pair[0], bytes) and isinstance(pair[1], bytes)):
                raise InvalidKeyError("Each element of the key pair must be a bytes object.")

    @staticmethod
    def generate_private_key(filename: str = DEFAULT_KEY_FILE) -> None:
        private_key: List[Tuple[bytes, bytes]] = [
            (secrets.token_bytes(LamportJWT.KEY_SIZE//8), secrets.token_bytes(LamportJWT.KEY_SIZE//8)) for _ in range(LamportJWT.KEY_SIZE)
        ]

        with open(filename, "w") as f:
            json.dump(
                [[base64.b85encode(k[0]).decode(), base64.b85encode(k[1]).decode()] for k in private_key],
                f,
            )

    @staticmethod
    def _load_private_key(filename: str) -> List[Tuple[bytes, bytes]]:
        with open(filename, "r") as f:
            key_data = json.load(f)

        private_key = [(base64.b85decode(k[0]), base64.b85decode(k[1])) for k in key_data]
        LamportJWT._validate_private_key(private_key)

        return private_key

    @staticmethod
    def _generate_public_key(private_key: List[Tuple[bytes, bytes]]) -> List[Tuple[bytes, bytes]]:
        return [(LamportJWT.HASH_FUNC(k[0]).digest(), LamportJWT.HASH_FUNC(k[1]).digest()) for k in private_key]

    @staticmethod
    def encode(payload: Dict[str, Any], filename: str = DEFAULT_KEY_FILE) -> str:

        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary.")

        private_key = LamportJWT._load_private_key(filename)

        payload_str: str = json.dumps(payload, separators=(",", ":"))
        payload_hash: bytes = LamportJWT.HASH_FUNC(payload_str.encode()).digest()
        payload_hash_bits: str = ''.join(f'{byte:08b}' for byte in payload_hash)

        signature: List[str] = [
            base64.b85encode(private_key[i][int(payload_hash_bits[i])]).decode()
            for i in range(LamportJWT.KEY_SIZE)
        ]

        header: Dict[str, str] = {"alg": "Lamport", "typ": "JWT"}
        jwt_data: Dict[str, Any] = {
            "header": header,
            "payload": payload,
            "signature": signature
        }

        return base64.b85encode(json.dumps(jwt_data, separators=(",", ":")).encode()).decode()

    @staticmethod
    def decode(token: str, filename: str = DEFAULT_KEY_FILE) -> Dict[str, Any]:

        try:
            jwt_data: Dict[str, Any] = json.loads(base64.b85decode(token).decode())

        except (json.JSONDecodeError, ValueError):
            raise InvalidTokenError("Invalid JWT: Failed to decode JSON.")

        if not isinstance(jwt_data, dict) or "header" not in jwt_data or "payload" not in jwt_data or "signature" not in jwt_data:
            raise InvalidTokenError("Invalid JWT: Incorrect structure.")

        if jwt_data["header"].get("alg") != "Lamport" or jwt_data["header"].get("typ") != "JWT":
            raise InvalidTokenError("Invalid JWT: Incorrect header.")

        if not isinstance(jwt_data["signature"], list) or len(jwt_data["signature"]) != LamportJWT.KEY_SIZE:
            raise InvalidTokenError("Invalid JWT: Signature has incorrect length.")

        private_key = LamportJWT._load_private_key(filename)
        public_key = LamportJWT._generate_public_key(private_key)

        payload_str: str = json.dumps(jwt_data["payload"], separators=(",", ":"))
        payload_hash: bytes = LamportJWT.HASH_FUNC(payload_str.encode()).digest()
        payload_hash_bits: str = ''.join(f'{byte:08b}' for byte in payload_hash)

        for i in range(LamportJWT.KEY_SIZE):
            try:
                signature_piece: bytes = base64.b85decode(jwt_data["signature"][i])
            except ValueError:
                raise InvalidTokenError("Invalid JWT: Signature contains invalid Base64 encoding.")

            if public_key[i][int(payload_hash_bits[i])] != LamportJWT.HASH_FUNC(signature_piece).digest():
                raise SignatureVerificationError("Signature verification failed.")

        return jwt_data["payload"]

    @staticmethod
    def decode_complete(token: str) -> Dict[str, Any]:
        try:
            return json.loads(base64.b85decode(token).decode())
        except (json.JSONDecodeError, ValueError):
            raise InvalidTokenError("Invalid JWT: Failed to decode JSON.")

    @staticmethod
    def get_unverified_header(token: str) -> Dict[str, str]:
        jwt_data = LamportJWT.decode_complete(token)
        if "header" not in jwt_data:
            raise InvalidTokenError("Invalid JWT: Missing header.")
        return jwt_data["header"]
