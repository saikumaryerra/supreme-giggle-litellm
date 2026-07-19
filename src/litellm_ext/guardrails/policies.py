"""F3/F8: per-team guardrail policy resolution (§7.3.3).

Defaults come from settings; optional per-team overrides map
team_id → {action, entities, threshold, skip_system_message, cache_opt_out,
moderation_categories}. Overrides live in the rbac.yaml file under
``guardrail_policies:`` so config stays in one mounted ConfigMap.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from litellm_ext.settings import PiiAction, get_settings


@dataclass(frozen=True)
class PiiPolicy:
    action: PiiAction
    entities: list[str]
    threshold: float
    skip_system_message: bool = False
    response_action: PiiAction = PiiAction.log_only


@dataclass(frozen=True)
class TeamPolicies:
    pii: PiiPolicy
    moderation_enabled: bool = False
    moderation_categories: dict[str, float] = field(default_factory=dict)
    injection_action: str = "log_only"  # log_only | block
    cache_opt_out: bool = False  # F11


DEFAULT_MODERATION_CATEGORIES: dict[str, float] = {
    "hate": 0.7,
    "violence": 0.8,
    "sexual": 0.8,
    "self-harm": 0.7,
}

_overrides: dict[str, Any] | None = None
_loaded_mtime: float = 0.0


def _load_overrides() -> dict[str, Any]:
    """Read guardrail_policies from the RBAC config file (hot-reload on mtime)."""
    global _overrides, _loaded_mtime
    path = get_settings().rbac_config_path
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _overrides is None or mtime != _loaded_mtime:
        with open(path) as fh:
            config = yaml.safe_load(fh) or {}
        _overrides = config.get("guardrail_policies") or {}
        _loaded_mtime = mtime
    return _overrides


def resolve(team_id: str | None) -> TeamPolicies:
    settings = get_settings()
    team_cfg: dict[str, Any] = _load_overrides().get(team_id or "", {}) or {}
    pii_cfg: dict[str, Any] = team_cfg.get("pii", {}) or {}

    pii = PiiPolicy(
        action=PiiAction(pii_cfg.get("action", settings.pii_action.value)),
        entities=list(pii_cfg.get("entities", settings.pii_entities)),
        threshold=float(pii_cfg.get("threshold", settings.pii_score_threshold)),
        skip_system_message=bool(pii_cfg.get("skip_system_message", False)),
        response_action=PiiAction(
            pii_cfg.get("response_action", settings.pii_response_action.value)
        ),
    )
    return TeamPolicies(
        pii=pii,
        moderation_enabled=bool(team_cfg.get("moderation_enabled", False)),
        moderation_categories=dict(
            team_cfg.get("moderation_categories", DEFAULT_MODERATION_CATEGORIES)
        ),
        injection_action=str(team_cfg.get("injection_action", "log_only")),
        cache_opt_out=bool(team_cfg.get("cache_opt_out", False)),
    )


def reset_overrides() -> None:
    """Test helper."""
    global _overrides, _loaded_mtime
    _overrides = None
    _loaded_mtime = 0.0
