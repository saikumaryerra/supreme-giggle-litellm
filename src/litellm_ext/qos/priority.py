"""F12 v2: weighted fair queueing on Redis (§7B.8).

Tier comes from RBAC (UserAPIKeyAuth.metadata["priority"]). Token bucket per
tier sized from LITELLM_EXT_QOS_CAPACITY_RPS x weight share
(interactive:70 / standard:25 / batch:5 by default). Interactive is NEVER
queued: it always takes a token (bucket may go negative — capacity planning
handles sustained overload). Standard/batch wait up to QOS_MAX_WAIT_MS for a
token, else 429 queued_timeout with Retry-After. State lives in Redis so
queueing survives pod restarts and is fair across replicas.

v1 (per-tier rpm/tpm ceilings via RBAC) needs no code here — the rbac.yaml
tier limits are enforced by LiteLLM's own limiters.

Registered as a CustomGuardrail pre_call hook when QOS_ENABLED=true.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from litellm_ext.metrics import ext_qos_rejections_total, ext_qos_wait_seconds
from litellm_ext.settings import get_settings

BUCKET_KEY = "ext:qos:bucket:{tier}"
POLL_INTERVAL_S = 0.05

# Atomic token-bucket take: refill by elapsed-time x rate (capped at burst),
# then take one token if available (or unconditionally for interactive).
TOKEN_BUCKET_LUA = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local force = tonumber(ARGV[4])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then tokens = burst ts = now end
tokens = math.min(burst, tokens + (now - ts) * rate)
local granted = 0
if tokens >= 1 or force == 1 then
  tokens = tokens - 1
  granted = 1
end
redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, 300)
return granted
"""


def tier_of(user_api_key_dict: Any) -> str:
    metadata = getattr(user_api_key_dict, "metadata", None) or {}
    tier = str(metadata.get("priority", "standard"))
    return tier if tier in ("interactive", "standard", "batch") else "standard"


def tier_rate(tier: str) -> float:
    settings = get_settings()
    weights = settings.qos_weights
    total = sum(weights.values()) or 1
    return settings.qos_capacity_rps * weights.get(tier, 0) / total


class QosPriorityGuardrail(CustomGuardrail):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._script_sha: str | None = None

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict[str, Any],
        call_type: str,
    ) -> dict[str, Any] | None:
        settings = get_settings()
        if not settings.qos_enabled:
            return data
        from litellm_ext.redis_client import get_redis

        redis = get_redis()
        if redis is None:
            return data  # no Redis → no queueing (v1 tier limits still apply)

        tier = tier_of(user_api_key_dict)
        rate = tier_rate(tier)
        burst = max(1.0, rate)  # burst = 1s of tier capacity
        started = time.monotonic()
        deadline = started + settings.qos_max_wait_ms / 1000.0
        force = 1 if tier == "interactive" else 0

        while True:
            try:
                granted = await self._take_token(redis, tier, rate, burst, force)
            except Exception:  # noqa: BLE001 — Redis outage: fail open for QoS
                return data
            if granted:
                ext_qos_wait_seconds.labels(tier=tier).observe(
                    time.monotonic() - started
                )
                return data
            if time.monotonic() >= deadline:
                ext_qos_rejections_total.labels(tier=tier).inc()
                retry_after = max(1, int(1.0 / rate)) if rate > 0 else 30
                raise HTTPException(
                    status_code=429,
                    detail={"error": "queued_timeout", "tier": tier},
                    headers={"Retry-After": str(retry_after)},
                )
            await asyncio.sleep(POLL_INTERVAL_S)

    async def _take_token(
        self, redis: Any, tier: str, rate: float, burst: float, force: int
    ) -> bool:
        if self._script_sha is None:
            self._script_sha = await redis.script_load(TOKEN_BUCKET_LUA)
        try:
            result = await redis.evalsha(
                self._script_sha,
                1,
                BUCKET_KEY.format(tier=tier),
                rate,
                burst,
                time.time(),
                force,
            )
        except Exception:
            # NOSCRIPT after Redis restart: reload once.
            self._script_sha = await redis.script_load(TOKEN_BUCKET_LUA)
            result = await redis.evalsha(
                self._script_sha,
                1,
                BUCKET_KEY.format(tier=tier),
                rate,
                burst,
                time.time(),
                force,
            )
        return bool(int(result))
