import jwt
import time
import base64
from cryptography.hazmat.primitives import serialization


def int_to_base64(n):
    """Convert an integer to a URL-safe base64 string (used for JWK n and e values)."""
    return base64.urlsafe_b64encode(
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(key, kid):
    """Convert an RSA public key object to a JWK dictionary."""
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
    """
    Issue a signed JWT using the provided RSA private key.
    - expired=True: sets exp to 5 minutes in the past.
    - expired=False: sets exp to 1 hour in the future.
    """
    now = int(time.time())
    payload = {
        "sub": "userABC",
        "iss": "jwks-server",
        "aud": "example-client",
        "iat": now,
        "exp": now - 300 if expired else now + 3600,
    }

    # Serialize private key to PEM for PyJWT signing
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS1
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(
        payload,
        pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return token
