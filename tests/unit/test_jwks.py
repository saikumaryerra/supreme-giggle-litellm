from __future__ import annotations

import json
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from litellm_ext.auth import jwks as jwks_module
from litellm_ext.auth.jwks import JwksCache, JwksError

KEY_A = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KEY_B = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_for(kid: str, private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update(kid=kid, alg="RS256", use="sig")
    return jwk


class FakeJwksEndpoint:
    def __init__(self, jwks: dict[str, Any]) -> None:
        self.jwks = jwks
        self.calls = 0
        self.down = False

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        endpoint = self

        def handler(request: httpx.Request) -> httpx.Response:
            endpoint.calls += 1
            if endpoint.down:
                raise httpx.ConnectError("jwks endpoint down")
            return httpx.Response(200, json=endpoint.jwks)

        transport = httpx.MockTransport(handler)
        original_client = httpx.AsyncClient

        def client_factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return original_client(**kwargs)

        monkeypatch.setattr(jwks_module.httpx, "AsyncClient", client_factory)


class TestJwksCache:
    async def test_fetch_and_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        endpoint = FakeJwksEndpoint({"keys": [jwk_for("a", KEY_A)]})
        endpoint.install(monkeypatch)
        cache = JwksCache(jwks_url="https://idp.test/jwks", ttl=3600, min_refetch=0)

        await cache.get_key("a")
        await cache.get_key("a")
        assert endpoint.calls == 1  # warm cache: no network on hot path

    async def test_unknown_kid_triggers_single_refetch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = FakeJwksEndpoint({"keys": [jwk_for("a", KEY_A)]})
        endpoint.install(monkeypatch)
        cache = JwksCache(jwks_url="https://idp.test/jwks", ttl=3600, min_refetch=0)
        await cache.get_key("a")

        # IdP rotates: kid "b" appears.
        endpoint.jwks = {"keys": [jwk_for("a", KEY_A), jwk_for("b", KEY_B)]}
        await cache.get_key("b")
        assert endpoint.calls == 2

    async def test_unknown_kid_after_refetch_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = FakeJwksEndpoint({"keys": [jwk_for("a", KEY_A)]})
        endpoint.install(monkeypatch)
        cache = JwksCache(jwks_url="https://idp.test/jwks", ttl=3600, min_refetch=0)
        with pytest.raises(JwksError):
            await cache.get_key("never-existed")

    async def test_endpoint_down_cached_key_keeps_working(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        endpoint = FakeJwksEndpoint({"keys": [jwk_for("a", KEY_A)]})
        endpoint.install(monkeypatch)
        cache = JwksCache(jwks_url="https://idp.test/jwks", ttl=0, min_refetch=0)
        await cache.get_key("a")

        endpoint.down = True
        assert await cache.get_key("a") is not None  # stale-but-cached survives
        with pytest.raises(JwksError):
            await cache.get_key("new-kid")  # new kid fails closed

    async def test_unknown_kid_refetch_is_throttled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pre-auth DoS guard: a flood of distinct bogus kids must not each
        # trigger an outbound JWKS fetch while the cache is warm.
        endpoint = FakeJwksEndpoint({"keys": [jwk_for("a", KEY_A)]})
        endpoint.install(monkeypatch)
        cache = JwksCache(jwks_url="https://idp.test/jwks", ttl=3600, min_refetch=3600)
        await cache.get_key("a")  # warm the cache (calls == 1)
        for i in range(50):
            with pytest.raises(JwksError):
                await cache.get_key(f"bogus-{i}")
        assert endpoint.calls == 1  # no extra fetches despite 50 unknown kids
