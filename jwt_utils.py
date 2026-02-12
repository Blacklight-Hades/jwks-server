import jwt
import time
import base64
from cryptography.hazmat.primitives import serialization


def int_to_base64(n):
    return base64.urlsafe_b64encode(
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(key, kid):
    numbers = key.public_numbers()

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64(numbers.n),
        "e": int_to_base64(numbers.e),
    }


def issue_jwt(private_key, kid, expired=False):
    payload = {
        "sub": "user123",
        "iss": "jwks-server",
        "aud": "example-client",
        "iat": int(time.time()),
        "exp": (
            int(time.time()) - 300
            if expired
            else int(time.time()) + 3600
        ),
    }

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(
        payload,
        pem,
        algorithm="RS256",
        headers={"kid": kid},
    )

    return token