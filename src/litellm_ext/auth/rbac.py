"""F1: role → permission mapping engine (§5.2 step 6, rbac.yaml schema §4).

Match roles against rbac.yaml in file order (first match wins), merge team
overrides, apply the default action when nothing matches. Hook points for
extended features: allowed_cidrs (F5), priority tier (F12), allowed_regions
(F13 via regions/residency.py).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from litellm_ext.regions.residency import pin_models_to_regions
from litellm_ext.settings import get_settings


class RbacDenied(Exception):
    """Valid token, but no role mapping and default action is deny → 403."""


@dataclass(frozen=True)
class ResolvedPermissions:
    matched_role: str
    litellm_role: str
    models: list[str] = field(default_factory=list)
    tpm_limit: int | None = None
    rpm_limit: int | None = None
    max_budget: float | None = None
    allowed_routes: list[str] = field(default_factory=lambda: ["*"])
    priority: str = "standard"  # F12 tier: interactive | standard | batch
    allowed_cidrs: list[str] = field(default_factory=list)  # F5 per-team CIDRs
    allowed_regions: list[str] = field(default_factory=list)  # F13 residency pin


class RbacEngine:
    def __init__(self, config: dict[str, Any]) -> None:
        self._roles: dict[str, Any] = config.get("roles") or {}
        self._default: dict[str, Any] = config.get("default") or {"action": "deny"}
        self._teams: dict[str, Any] = config.get("teams") or {}

    def resolve(self, roles: list[str], team_id: str | None) -> ResolvedPermissions:
        role_name, mapping = self._first_match(roles)
        team_cfg: dict[str, Any] = self._teams.get(team_id or "", {}) or {}

        models = list(mapping.get("models") or [])
        models += [m for m in team_cfg.get("extra_models", []) if m not in models]

        allowed_regions = list(
            team_cfg.get("allowed_regions") or mapping.get("allowed_regions") or []
        )
        if allowed_regions:
            models = pin_models_to_regions(models, allowed_regions)

        allowed_cidrs = list(mapping.get("allowed_cidrs") or []) + list(
            team_cfg.get("allowed_cidrs") or []
        )

        return ResolvedPermissions(
            matched_role=role_name,
            litellm_role=str(mapping.get("litellm_role", "internal_user")),
            models=models,
            tpm_limit=mapping.get("tpm_limit"),
            rpm_limit=mapping.get("rpm_limit"),
            max_budget=mapping.get("max_budget"),
            allowed_routes=list(mapping.get("allowed_routes") or ["*"]),
            priority=str(mapping.get("priority", "standard")),
            allowed_cidrs=allowed_cidrs,
            allowed_regions=allowed_regions,
        )

    def _first_match(self, roles: list[str]) -> tuple[str, dict[str, Any]]:
        # rbac.yaml file order wins, not token role order (dict preserves
        # insertion order from YAML).
        for role_name, mapping in self._roles.items():
            if role_name in roles:
                return role_name, mapping or {}
        action = str(self._default.get("action", "deny"))
        if action == "map":
            return "default", {
                k: v for k, v in self._default.items() if k != "action"
            }
        raise RbacDenied(f"no role mapping for {roles!r} and default action is deny")


_engine: RbacEngine | None = None
_loaded_mtime: float = 0.0


def get_engine(path: str | None = None) -> RbacEngine:
    """Load rbac.yaml, reloading when the file changes (ConfigMap updates)."""
    global _engine, _loaded_mtime
    rbac_path = path or get_settings().rbac_config_path
    try:
        mtime = os.path.getmtime(rbac_path)
    except OSError as exc:
        raise RuntimeError(f"rbac config not found: {rbac_path}") from exc
    if _engine is None or mtime != _loaded_mtime:
        with open(rbac_path) as fh:
            config = yaml.safe_load(fh) or {}
        _engine = RbacEngine(config)
        _loaded_mtime = mtime
    return _engine


def reset_engine() -> None:
    """Test helper."""
    global _engine, _loaded_mtime
    _engine = None
    _loaded_mtime = 0.0
