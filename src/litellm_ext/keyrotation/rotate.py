"""F10: automated virtual-key rotation (§7B.6). Daily CronJob:

    python -m litellm_ext.keyrotation.rotate [--dry-run]

For LiteLLM virtual keys (service accounts on the F1 passthrough path):
 1. /key/list → managed keys (metadata.rotation == "managed") older than
    LITELLM_EXT_KEY_MAX_AGE_DAYS.
 2. /key/generate cloning models/limits/team/metadata (+rotated_from);
    deliver the new key to Vault (metadata.vault_path — preferred) or via
    the notifier.
 3. /key/update: old key expires = now + grace days.
 4. After grace: /key/delete.
Idempotent: keys already mid-rotation (metadata.rotation_state) are skipped.
Every step emits admin.action{key_rotation} audit events. Unmanaged keys are
never touched. --dry-run prints the plan and mutates nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from litellm_ext.audit import emit_event
from litellm_ext.costgov.notify import notify
from litellm_ext.settings import get_settings


class KeyAdminClient:
    def __init__(self) -> None:
        settings = get_settings()
        self._base = settings.litellm_api_base.rstrip("/")
        self._headers = {"Authorization": f"Bearer {settings.litellm_master_key}"}

    async def list_keys(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self._base}/key/list",
                params={"return_full_object": "true", "size": 100},
                headers=self._headers,
            )
            resp.raise_for_status()
            payload = resp.json()
        return list(payload.get("keys") or payload.get("data") or [])

    async def generate_key(self, spec: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base}/key/generate", json=spec, headers=self._headers
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def update_key(self, token: str, updates: dict[str, Any]) -> None:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base}/key/update",
                json={"key": token, **updates},
                headers=self._headers,
            )
            resp.raise_for_status()

    async def delete_key(self, token: str) -> None:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base}/key/delete", json={"keys": [token]}, headers=self._headers
            )
            resp.raise_for_status()


def _metadata(key: dict[str, Any]) -> dict[str, Any]:
    metadata = key.get("metadata") or {}
    return metadata if isinstance(metadata, dict) else {}


def _created_at(key: dict[str, Any]) -> datetime | None:
    raw = key.get("created_at")
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def classify(key: dict[str, Any], now: datetime, max_age_days: int) -> str:
    """Returns: rotate | expire_due | skip."""
    metadata = _metadata(key)
    if metadata.get("rotation") != "managed":
        return "skip"
    state = metadata.get("rotation_state")
    if state == "replaced":
        expires = key.get("expires")
        if expires:
            try:
                exp_dt = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=UTC)
                if exp_dt <= now:
                    return "expire_due"
            except ValueError:
                pass
        return "skip"  # mid-rotation, grace not over
    created = _created_at(key)
    if created is None:
        return "skip"
    if (now - created) > timedelta(days=max_age_days):
        return "rotate"
    return "skip"


def clone_spec(key: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(_metadata(key))
    metadata["rotated_from"] = key.get("token") or key.get("key_name")
    metadata.pop("rotation_state", None)
    spec: dict[str, Any] = {"metadata": metadata}
    for field in ("models", "team_id", "user_id", "tpm_limit", "rpm_limit", "max_budget", "key_alias"):
        if key.get(field) is not None:
            spec[field] = key[field]
    if spec.get("key_alias"):
        spec["key_alias"] = f"{spec['key_alias']}-r{int(datetime.now(tz=UTC).timestamp())}"
    return spec


async def deliver(new_key: dict[str, Any], old_key: dict[str, Any], dry_run: bool) -> str:
    """Deliver the new secret: Vault path from metadata (preferred) or notifier."""
    vault_path = _metadata(old_key).get("vault_path")
    if dry_run:
        return "dry-run"
    if vault_path:
        try:
            from litellm_ext.secretsmgr.providers.vault import VaultResolver

            resolver = VaultResolver()
            token = resolver._login()
            with httpx.Client(timeout=10.0, verify=resolver._verify) as client:
                mount, _, path = str(vault_path).partition("/")
                resp = client.post(  # noqa: ASYNC212 — batch CronJob, sync Vault client reused
                    f"{resolver._addr}/v1/{mount}/data/{path}",
                    headers={"X-Vault-Token": token},
                    json={"data": {"api_key": new_key.get("key")}},
                )
                resp.raise_for_status()
            return f"vault:{vault_path}"
        except Exception:  # noqa: BLE001 — fall through to notifier
            pass
    owner = old_key.get("user_id") or old_key.get("team_id") or "owner"
    await notify(
        "LiteLLM virtual key rotated",
        f"A new key was issued for {owner} (alias {old_key.get('key_alias')}). "
        "Retrieve it from the key admin — the old key expires after the grace period.",
    )
    return "notifier"


async def run(dry_run: bool = False) -> dict[str, int]:
    settings = get_settings()
    client = KeyAdminClient()
    now = datetime.now(tz=UTC)
    stats = {"rotated": 0, "expired": 0, "skipped": 0}

    for key in await client.list_keys():
        action = classify(key, now, settings.key_max_age_days)
        token = key.get("token") or key.get("key") or ""
        if action == "skip":
            stats["skipped"] += 1
            continue

        if action == "rotate":
            print(f"{'DRY-RUN ' if dry_run else ''}rotate: {key.get('key_alias') or token[:12]}")
            if not dry_run:
                new_key = await client.generate_key(clone_spec(key))
                channel = await deliver(new_key, key, dry_run)
                grace_end = now + timedelta(days=settings.key_rotation_grace_days)
                metadata = dict(_metadata(key))
                metadata["rotation_state"] = "replaced"
                await client.update_key(
                    token,
                    {"expires": grace_end.isoformat(), "metadata": metadata},
                )
                emit_event(
                    "admin.action",
                    user_id="key-rotation",
                    team_id=key.get("team_id"),
                    extra={
                        "action": "key_rotation",
                        "step": "replaced",
                        "key_alias": key.get("key_alias"),
                        "delivery": channel,
                    },
                )
            stats["rotated"] += 1

        elif action == "expire_due":
            print(f"{'DRY-RUN ' if dry_run else ''}delete: {key.get('key_alias') or token[:12]}")
            if not dry_run:
                await client.delete_key(token)
                emit_event(
                    "admin.action",
                    user_id="key-rotation",
                    team_id=key.get("team_id"),
                    extra={
                        "action": "key_rotation",
                        "step": "deleted_after_grace",
                        "key_alias": key.get("key_alias"),
                    },
                )
            stats["expired"] += 1

    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    stats = asyncio.run(run(dry_run=args.dry_run))
    print(f"rotation summary: {stats}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
