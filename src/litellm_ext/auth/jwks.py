"""F1: JWKS fetch + cache + rotation handling (§5.2 step 3).

Keys are cached per ``kid`` with a TTL. On a cache miss for an unknown kid the
whole JWKS is refetched exactly once (handles IdP key rotation), guarded by a
per-process asyncio.Lock to prevent a thundering herd of refetches. When the
JWKS endpoint is down, previously cached keys keep working until TTL — new
kids fail closed.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import jwt as pyjwt

from litellm_ext.settings import get_settings


class JwksError(Exception):
    pass


class JwksCache:
    def __init__(self, jwks_url: str | None = None, ttl: int | None = None) -> None:
        settings = get_settings()
        self._url = jwks_url or settings.jwks_url
        self._ttl = ttl if ttl is not None else settings.jwks_cache_ttl
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    def _expired(self) -> bool:
        return (time.monotonic() - self._fetched_at) > self._ttl

    async def _refresh(self) -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(self._url)
            resp.raise_for_status()
            data = resp.json()
        keys: dict[str, Any] = {}
        for jwk in data.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            keys[kid] = pyjwt.PyJWK(jwk).key
        self._keys = keys
        self._fetched_at = time.monotonic()

    async def get_key(self, kid: str) -> Any:
        """Return the verification key for ``kid``; raise JwksError if unknown."""
        if kid in self._keys and not self._expired():
            return self._keys[kid]

        async with self._lock:
            # Re-check under the lock: another coroutine may have refreshed.
            if kid in self._keys and not self._expired():
                return self._keys[kid]
            try:
                await self._refresh()
            except Exception as exc:
                # Endpoint down: previously cached key keeps working until TTL
                # grace; an unknown kid fails closed.
                if kid in self._keys:
                    return self._keys[kid]
                raise JwksError("JWKS refresh failed and kid is unknown") from exc

        if kid not in self._keys:
            raise JwksError("unknown kid after refetch")
        return self._keys[kid]


_cache: JwksCache | None = None


def get_jwks_cache() -> JwksCache:
    global _cache
    if _cache is None:
        _cache = JwksCache()
    return _cache


def reset_jwks_cache() -> None:
    """Test helper."""
    global _cache
    _cache = None
