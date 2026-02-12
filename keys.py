from cryptography.hazmat.primitives.asymmetric import rsa
import time
import uuid

KEYS = []


def generate_key(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()
    kid = str(uuid.uuid4())

    expiry = int(time.time()) - 3600 if expired else int(time.time()) + 3600

    key_data = {
        "kid": kid,
        "private": private_key,
        "public": public_key,
        "expiry": expiry
    }

    KEYS.append(key_data)
    return key_data


def get_valid_keys():
    now = int(time.time())
    return [k for k in KEYS if k["expiry"] > now]


def get_expired_key():
    for k in KEYS:
        if k["expiry"] < int(time.time()):
            return k
    return generate_key(expired=True)
