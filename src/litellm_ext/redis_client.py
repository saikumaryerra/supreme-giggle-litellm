"""Shared async Redis access for enforcement sets.

Used by: F6 deactivation set, F8d blocked users, F9 budget exhaustion /
downgrade, F12 QoS queue. All callers treat Redis being unconfigured or down
as "no entry" — enforcement sets fail open individually while auth itself
stays fail-closed on token validity.
"""

from __future__ import annotations

import logging
from typing import Any

from litellm_ext.settings import get_settings

logger = logging.getLogger("litellm_ext.redis")

DEACTIVATED_USERS_SET = "ext:deactivated_users"
BLOCKED_USERS_SET = "ext:blocked_users"
BUDGET_EXHAUSTED_SET = "ext:budget_exhausted"
BUDGET_DOWNGRADE_PREFIX = "ext:budget_downgrade:"

_client: Any = None


def get_redis() -> Any:
    """Lazily build a shared redis.asyncio client; None when unconfigured."""
    global _client
    settings = get_settings()
    if not settings.redis_host:
        return None
    if _client is None:
        import redis.asyncio as aioredis

        _client = aioredis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password or None,
            decode_responses=True,
            socket_timeout=0.5,
            socket_connect_timeout=0.5,
        )
    return _client


def reset_client() -> None:
    """Test helper."""
    global _client
    _client = None


async def set_contains(set_name: str, member: str) -> bool:
    client = get_redis()
    if client is None or not member:
        return False
    try:
        return bool(await client.sismember(set_name, member))
    except Exception:  # noqa: BLE001 - Redis outage must not break auth
        logger.warning("redis check failed for %s; treating as absent", set_name)
        return False


async def get_downgrade_models(team_id: str) -> list[str] | None:
    """Model allowlist for a budget-downgraded team; None = not downgraded."""
    client = get_redis()
    if client is None or not team_id:
        return None
    try:
        raw = await client.get(BUDGET_DOWNGRADE_PREFIX + team_id)
    except Exception:  # noqa: BLE001
        logger.warning("redis downgrade lookup failed for team %s", team_id)
        return None
    if not raw:
        return None
    return [m.strip() for m in raw.split(",") if m.strip()]
