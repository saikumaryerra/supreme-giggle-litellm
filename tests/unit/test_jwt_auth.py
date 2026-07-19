"""F1 acceptance criteria (§5.5) at unit level."""

from __future__ import annotations

import time
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from starlette.requests import Request

from litellm_ext.auth import jwt_auth
from litellm_ext.auth.jwks import JwksError
from litellm_ext.settings import reset_settings_cache

ISSUER = "https://idp.test/realm"
AUDIENCE = "litellm-proxy"
KID = "test-kid-1"

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class StubJwks:
    def __init__(self, keys: dict[str, Any]) -> None:
        self._keys = keys

    async def get_key(self, kid: str) -> Any:
        if kid not in self._keys:
            raise JwksError("unknown kid after refetch")
        return self._keys[kid]


@pytest.fixture(autouse=True)
def stub_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        jwt_auth, "get_jwks_cache", lambda: StubJwks({KID: PUBLIC_KEY})
    )


def make_token(
    roles: list[str] | None = None,
    *,
    key: rsa.RSAPrivateKey = PRIVATE_KEY,
    kid: str = KID,
    exp_delta: int = 3600,
    audience: str = AUDIENCE,
    groups: list[str] | None = None,
    alg: str = "RS256",
) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": audience,
        "sub": "user-1",
        "email": "user@example.com",
        "exp": now + exp_delta,
        "nbf": now - 10,
        "roles": roles if roles is not None else ["llm-engineer"],
        "groups": groups or [],
    }
    return pyjwt.encode(payload, key, algorithm=alg, headers={"kid": kid})


def make_request(client_ip: str = "10.1.2.3", headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/chat/completions",
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "query_string": b"",
        "client": (client_ip, 40000),
    }
    return Request(scope)


async def auth(token: str, **request_kwargs: Any) -> Any:
    return await jwt_auth.user_api_key_auth(make_request(**request_kwargs), token)


class TestHappyPath:
    async def test_engineer_gets_mapped_permissions(self) -> None:
        result = await auth(make_token())
        assert result.user_id == "user-1"
        assert result.user_role == "internal_user"
        assert result.models == ["gpt-4o", "claude-sonnet", "gpt-4o-mini"]
        assert result.tpm_limit == 200000
        assert result.metadata["auth_method"] == "jwt"
        assert result.metadata["priority"] == "standard"

    async def test_raw_jwt_never_stored(self) -> None:
        token = make_token()
        result = await auth(token)
        assert token not in result.api_key
        assert result.api_key.startswith("jwt-")

    async def test_team_from_first_group(self) -> None:
        result = await auth(make_token(groups=["data-science", "x"]))
        assert result.team_id == "data-science"
        assert "o3" in result.models  # team extra_models merged


class TestDenials:
    async def test_expired_token_401(self) -> None:
        # Delta beyond the 60 s clock skew.
        with pytest.raises(HTTPException) as exc:
            await auth(make_token(exp_delta=-3600))
        assert exc.value.status_code == 401

    async def test_within_clock_skew_accepted(self) -> None:
        result = await auth(make_token(exp_delta=-30))  # inside 60 s leeway
        assert result.user_id == "user-1"

    async def test_tampered_signature_401(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await auth(make_token(key=OTHER_KEY))
        assert exc.value.status_code == 401

    async def test_wrong_audience_401(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await auth(make_token(audience="other-api"))
        assert exc.value.status_code == 401

    async def test_unknown_kid_401(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await auth(make_token(kid="rotated-away"))
        assert exc.value.status_code == 401

    async def test_unmapped_role_default_deny_403(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await auth(make_token(roles=["random-role"]))
        assert exc.value.status_code == 403

    async def test_garbage_token_401(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await auth("not-a-jwt-at-all")
        assert exc.value.status_code == 401

    async def test_error_detail_never_contains_token(self) -> None:
        token = make_token(audience="other-api")
        with pytest.raises(HTTPException) as exc:
            await auth(token)
        assert token not in str(exc.value.detail)


class TestPassthrough:
    async def test_sk_key_delegates_to_default_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sentinel = object()

        async def fake_passthrough(request: Any, api_key: str) -> Any:
            assert api_key == "sk-virtual-1"
            return sentinel

        import litellm_ext.auth.passthrough as passthrough

        monkeypatch.setattr(passthrough, "default_virtual_key_auth", fake_passthrough)
        assert await auth("sk-virtual-1") is sentinel

    async def test_sk_key_rejected_when_passthrough_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_ALLOW_VIRTUAL_KEYS", "false")
        reset_settings_cache()
        with pytest.raises(HTTPException) as exc:
            await auth("sk-virtual-1")
        assert exc.value.status_code == 401


class TestIpAllowlist:
    async def test_blocked_cidr_403_before_token_work(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_IP_ALLOWLIST", "10.0.0.0/8")
        reset_settings_cache()
        with pytest.raises(HTTPException) as exc:
            await auth(make_token(), client_ip="203.0.113.7")
        assert exc.value.status_code == 403

    async def test_allowed_cidr_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_EXT_IP_ALLOWLIST", "10.0.0.0/8")
        reset_settings_cache()
        result = await auth(make_token(), client_ip="10.9.9.9")
        assert result.user_id == "user-1"

    async def test_xff_from_untrusted_peer_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_IP_ALLOWLIST", "10.0.0.0/8")
        reset_settings_cache()
        # Untrusted peer spoofs XFF claiming an allowed source; must still block.
        with pytest.raises(HTTPException) as exc:
            await auth(
                make_token(),
                client_ip="203.0.113.7",
                headers={"X-Forwarded-For": "10.1.1.1"},
            )
        assert exc.value.status_code == 403
