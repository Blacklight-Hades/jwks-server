from fastapi import FastAPI, Query
from keys import generate_key, get_valid_keys, get_expired_key
from jwt_utils import public_key_to_jwk, issue_jwt

app = FastAPI()

generate_key(expired=False)
generate_key(expired=True)


@app.get("/.well-known/jwks.json")
def jwks():
    keys = []
    for k in get_valid_keys():
        jwk = public_key_to_jwk(k["public"], k["kid"])
        keys.append(jwk)
    return {"keys": keys}


@app.post("/auth")
def auth(expired: bool = Query(False)):
    if expired:
        key = get_expired_key()
        token = issue_jwt(key["private"], key["kid"], expired=True)
    else:
        key = get_valid_keys()[0]
        token = issue_jwt(key["private"], key["kid"])
    return {"token": token}
