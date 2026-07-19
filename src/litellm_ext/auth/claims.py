"""F1: claim extraction & validation (§5.2 step 5).

Supports dot-notation claim paths (e.g. ``realm_access.roles``) and both
list and space-delimited-string role forms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from litellm_ext.settings import get_settings


class ClaimError(Exception):
    pass


def resolve_path(payload: dict[str, Any], path: str) -> Any:
    """Walk a dot-notation path through nested dicts; None when absent."""
    node: Any = payload
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def as_list(value: Any) -> list[str]:
    """Normalize a claim to a list of strings (list or space-delimited)."""
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


@dataclass(frozen=True)
class Claims:
    sub: str
    exp: int
    email: str | None = None
    roles: list[str] = field(default_factory=list)
    team: str | None = None


def extract_claims(payload: dict[str, Any]) -> Claims:
    settings = get_settings()
    sub = payload.get("sub")
    if not sub:
        raise ClaimError("token missing sub claim")
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise ClaimError("token missing exp claim")

    roles = as_list(resolve_path(payload, settings.role_claim))
    teams = as_list(resolve_path(payload, settings.team_claim))
    return Claims(
        sub=str(sub),
        exp=int(exp),
        email=payload.get("email"),
        roles=roles,
        team=teams[0] if teams else None,  # first group; selector configurable later
    )
