"""Pydantic models for config/keypool.yaml (F4, region fields for F13).

The keypool file is the declarative source of truth for provider keys:
keys are data, not hand-edited model_list YAML. The generator expands
pools × models × enabled keys into LiteLLM model_list deployments.
"""

from __future__ import annotations

import os
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class PoolModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    model_name: str  # public name exposed to clients
    upstream_model: str  # litellm provider/model string, e.g. openai/gpt-4o


class PoolKey(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    key_id: str  # stable logical ID — never the secret itself
    api_key_env: str  # env var name injected from K8s Secret
    weight: int = 1
    tpm: int | None = None
    rpm: int | None = None
    enabled: bool = True
    region: str | None = None  # F13: eu | us | ...
    api_base: str | None = None  # F13: regional endpoint override


class Pool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str
    models: list[PoolModel]
    keys: list[PoolKey]
    failover: dict[str, list[str]] = Field(default_factory=dict)  # F13: {eu: [us]}


class KeypoolConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pools: list[Pool] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> KeypoolConfig:
        seen_key_ids: set[str] = set()
        for pool in self.pools:
            for key in pool.keys:
                if key.key_id in seen_key_ids:
                    raise ValueError(f"duplicate key_id: {key.key_id!r}")
                seen_key_ids.add(key.key_id)
        for pool in self.pools:
            if not pool.models:
                raise ValueError(f"pool {pool.provider!r} defines no models")
            if not any(k.enabled for k in pool.keys):
                raise ValueError(
                    f"pool {pool.provider!r} has no enabled keys; every exposed "
                    "model_name needs at least one enabled key"
                )
        return self

    def validate_env(self, environ: dict[str, str] | None = None) -> None:
        """Fail fast when a referenced api_key_env is absent (§7A.3 rule 2).

        Names the missing variable — never a value.
        """
        env = environ if environ is not None else dict(os.environ)
        missing = sorted(
            {
                key.api_key_env
                for pool in self.pools
                for key in pool.keys
                if key.enabled and key.api_key_env not in env
            }
        )
        if missing:
            raise RuntimeError(
                "keypool references environment variables that are not set: "
                + ", ".join(missing)
            )


def load_keypool(path: str) -> KeypoolConfig:
    with open(path) as fh:
        raw: Any = yaml.safe_load(fh) or {}
    return KeypoolConfig.model_validate(raw)
