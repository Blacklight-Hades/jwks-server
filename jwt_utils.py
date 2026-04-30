"""
JWT utility functions for the JWKS server.

Provides helpers for:
  - Converting RSA public keys to JWK (JSON Web Key) format.
  - Issuing signed JWTs using RS256.
"""

import jwt
import time
import base64
from cryptography.hazmat.primitives import serialization


def int_to_base64(n: int) -> str:
    """
    Convert an integer to a URL-safe base64 string (no padding).

    Used for encoding the RSA modulus (n) and exponent (e) in JWK format.

    Args:
        n: A positive integer to encode.

    Returns:
        A URL-safe base64-encoded string without trailing ``=`` padding.
    """
    return base64.urlsafe_b64encode(
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(key, kid: str) -> dict:
    """
    Convert an RSA public key object to a JWK dictionary.

    Args:
        key: An RSA public key object (from ``cryptography`` library).
        kid: The key identifier string.

    Returns:
        A dictionary conforming to the JWK specification with fields:
        ``kty``, ``kid``, ``use``, ``alg``, ``n``, and ``e``.
    """
    numbers = key.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64(numbers.n),
        "e": int_to_base64(numbers.e),
    }


def issue_jwt(private_key, kid: str, expired: bool = False) -> str:
    """
    Issue a signed JWT using the provided RSA private key.

    Args:
        private_key: An RSA private key object (from ``cryptography``).
        kid: The key identifier to include in the JWT header.
        expired: If True, sets the ``exp`` claim to 5 minutes in the past.
                 If False (default), sets ``exp`` to 1 hour in the future.

    Returns:
        A signed JWT string (compact serialisation).
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
