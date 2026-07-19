"""Readiness helpers: report degraded state without failing liveness.

LiteLLM's built-in /health/readiness probe covers the proxy itself; these
helpers add ext-specific checks (JWKS reachable, audit DB up) that the
deployment can surface via a sidecar route or startup validation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from litellm_ext.settings import get_settings


@dataclass
class HealthStatus:
    ready: bool
    degraded: bool = False
    checks: dict[str, str] = field(default_factory=dict)


async def check_jwks() -> tuple[bool, str]:
    settings = get_settings()
    if not settings.jwks_url:
        return True, "jwks not configured"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(settings.jwks_url)
            resp.raise_for_status()
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 - health check reports, never raises
        return False, f"unreachable: {type(exc).__name__}"


async def check_audit_db() -> tuple[bool, str]:
    settings = get_settings()
    if not settings.audit_db_url:
        return True, "audit db not configured"
    try:
        import asyncpg

        dsn = settings.audit_db_url.replace("postgresql+asyncpg://", "postgresql://")
        conn = await asyncpg.connect(dsn, timeout=3.0)
        try:
            await conn.execute("SELECT 1")
        finally:
            await conn.close()
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, f"unreachable: {type(exc).__name__}"


async def readiness() -> HealthStatus:
    """Aggregate readiness.

    JWKS being down is *degraded* (cached keys keep working until TTL) rather
    than not-ready; a missing audit DB is also degraded because audit is
    fail-open by design.
    """
    (jwks_ok, jwks_msg), (db_ok, db_msg) = await asyncio.gather(
        check_jwks(), check_audit_db()
    )
    return HealthStatus(
        ready=True,
        degraded=not (jwks_ok and db_ok),
        checks={"jwks": jwks_msg, "audit_db": db_msg},
    )
