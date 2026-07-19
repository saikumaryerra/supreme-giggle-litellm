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
import logging
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from litellm_ext.audit import emit_event
from litellm_ext.settings import get_settings

logger = logging.getLogger("litellm_ext.keyrotation")


class KeyAdminClient:
    def __init__(self) -> None:
        settings = get_settings()
        self._base = settings.litellm_api_base.rstrip("/")
        self._headers = {"Authorization": f"Bearer {settings.litellm_master_key}"}

    async def list_keys(self) -> list[dict[str, Any]]:
        """All virtual keys, following pagination (size=100 is the server max)."""
        keys: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=15.0) as client:
            page = 1
            while True:
                resp = await client.get(
                    f"{self._base}/key/list",
                    params={"return_full_object": "true", "size": 100, "page": page},
                    headers=self._headers,
                )
                resp.raise_for_status()
                payload = resp.json()
                batch = list(payload.get("keys") or payload.get("data") or [])
                keys.extend(batch)
                total_pages = payload.get("total_pages") or payload.get("num_pages")
                if total_pages is not None:
                    if page >= int(total_pages):
                        break
                elif len(batch) < 100:
                    break
                page += 1
        return keys

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
    # Epoch seconds (some LiteLLM builds return created_at as a number).
    if isinstance(raw, int | float):
        return datetime.fromtimestamp(raw, tz=UTC)
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
        return "skip"  # replaced, grace not over
    if state:
        # Any other non-terminal marker (e.g. in_progress) means a rotation is
        # mid-flight — never start a second one for the same key (idempotency).
        return "skip"
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


class DeliveryError(Exception):
    """The rotated secret could not be delivered — abort before expiring old."""


async def deliver(new_key: dict[str, Any], old_key: dict[str, Any]) -> str:
    """Deliver the new secret to the Vault path named in the old key's metadata.

    Delivery MUST succeed before the old key is expired, otherwise the raw
    replacement is lost (LiteLLM stores only hashes). A notifier can't carry
    the secret safely, so a managed key without a ``vault_path`` cannot be
    auto-rotated — raise so the caller skips it and alerts, rather than
    minting an unrecoverable orphan.
    """
    vault_path = _metadata(old_key).get("vault_path")
    if not vault_path:
        raise DeliveryError("managed key has no metadata.vault_path for delivery")
    if not new_key.get("key"):
        raise DeliveryError("generated key response carried no raw key material")
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
    except Exception as exc:  # noqa: BLE001
        raise DeliveryError(f"vault write to {vault_path} failed") from exc
    return f"vault:{vault_path}"


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
                # Stamp in_progress BEFORE minting so a crash mid-rotation makes
                # the next run skip this key (classify treats any non-terminal
                # rotation_state as skip) instead of minting another orphan.
                in_progress_meta = dict(_metadata(key))
                in_progress_meta["rotation_state"] = "in_progress"
                await client.update_key(token, {"metadata": in_progress_meta})
                try:
                    new_key = await client.generate_key(clone_spec(key))
                    channel = await deliver(new_key, key)
                except DeliveryError as exc:
                    logger.error("rotation aborted for %s: %s", key.get("key_alias"), exc)
                    # Roll the marker back so a fixed config retries next run.
                    await client.update_key(token, {"metadata": _metadata(key)})
                    stats["skipped"] += 1
                    continue
                # Grace expiry via `duration` (the field LiteLLM's /key/update
                # honors — `expires` is silently dropped).
                metadata = dict(_metadata(key))
                metadata["rotation_state"] = "replaced"
                await client.update_key(
                    token,
                    {
                        "duration": f"{settings.key_rotation_grace_days}d",
                        "metadata": metadata,
                    },
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
