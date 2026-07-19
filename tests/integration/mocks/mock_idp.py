"""Mock IdP for the integration stack: static JWKS + token minter.

GET /jwks                       → JWKS with the test signing key
POST /token {sub, roles, groups, ttl?, aud?} → signed RS256 JWT
"""

from __future__ import annotations

import json
import time
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from pydantic import BaseModel

ISSUER = "https://mock-idp.test/realm"
AUDIENCE = "litellm-proxy"
KID = "mock-kid-1"

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
app = FastAPI(title="mock-idp")


class TokenRequest(BaseModel):
    sub: str = "user-1"
    email: str = "user@example.com"
    roles: list[str] = ["llm-engineer"]
    groups: list[str] = []
    ttl: int = 3600
    aud: str = AUDIENCE


@app.get("/jwks")
def jwks() -> dict[str, Any]:
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(_key.public_key()))
    jwk.update(kid=KID, alg="RS256", use="sig")
    return {"keys": [jwk]}


@app.post("/token")
def mint(request: TokenRequest) -> dict[str, str]:
    now = int(time.time())
    token = pyjwt.encode(
        {
            "iss": ISSUER,
            "aud": request.aud,
            "sub": request.sub,
            "email": request.email,
            "roles": request.roles,
            "groups": request.groups,
            "iat": now,
            "nbf": now - 10,
            "exp": now + request.ttl,
        },
        _key,
        algorithm="RS256",
        headers={"kid": KID},
    )
    return {"access_token": token}
