from fastapi import FastAPI, Query, Header
from db import init_db, get_valid_keys_from_db, get_expired_key_from_db
from jwt_utils import public_key_to_jwk, issue_jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sqlite3
import time
import base64

DB_FILE = "totally_not_my_privateKeys.db"

app = FastAPI()


def generate_and_store_keys():
    """Generate one valid and one expired RSA key and persist them to the DB."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    for expired in (False, True):
        # Generate a 2048-bit RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Serialize to PEM (PKCS1) for storage as a string/blob
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS1
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Set expiry: past for expired key, 1 hour ahead for valid key
        exp = int(time.time()) - 3600 if expired else int(time.time()) + 3600

        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem.decode("utf-8"), exp),
        )

    conn.commit()
    conn.close()


# Initialize DB and seed keys on startup
init_db(DB_FILE)
generate_and_store_keys()


@app.get("/.well-known/jwks.json")
def jwks():
    """Return all valid (non-expired) public keys as a JWKS JSON response."""
    keys = []
    for kid, private_key in get_valid_keys_from_db(DB_FILE):
        jwk = public_key_to_jwk(private_key.public_key(), str(kid))
        keys.append(jwk)
    return {"keys": keys}


@app.post("/auth")
def auth(
    expired: bool = Query(False),
    authorization: str = Header(default=None)
):
    # Accept HTTP Basic auth or JSON body - we don't actually validate,
    # just need to accept and return a valid JWT
    if expired:
        result = get_expired_key_from_db(DB_FILE)
    else:
        results = get_valid_keys_from_db(DB_FILE)
        result = results[0] if results else None

    if result is None:
        return {"error": "No suitable key found"}

    kid, private_key = result
    token = issue_jwt(private_key, str(kid), expired=expired)
    return {"token": token}
