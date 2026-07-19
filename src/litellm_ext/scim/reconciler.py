"""F6: translate SCIM changes into LiteLLM management-API calls (§7B.2).

group create → /team/new; membership change → /team/member_add /
/team/member_delete; user deactivate → deactivation set (Redis + audit
event). team_id = SCIM group id (stable), alias = displayName — a group
rename never orphans team spend history.

Deactivation must not wait for JWT expiry: jwt_auth step 6.5 checks the
Redis set on every request (~0.2 ms).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from litellm_ext.audit import emit_event
from litellm_ext.redis_client import DEACTIVATED_USERS_SET, get_redis
from litellm_ext.settings import get_settings

logger = logging.getLogger("litellm_ext.scim")


class LiteLLMAdminClient:
    """Thin client for LiteLLM's management APIs using the master key."""

    def __init__(self) -> None:
        settings = get_settings()
        self._base = settings.litellm_api_base.rstrip("/")
        self._headers = {"Authorization": f"Bearer {settings.litellm_master_key}"}

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self._base}{path}", json=payload, headers=self._headers
            )
            resp.raise_for_status()
            return dict(resp.json()) if resp.content else {}

    async def team_new(self, team_id: str, alias: str) -> None:
        await self._post("/team/new", {"team_id": team_id, "team_alias": alias})

    async def team_update_alias(self, team_id: str, alias: str) -> None:
        await self._post("/team/update", {"team_id": team_id, "team_alias": alias})

    async def team_member_add(self, team_id: str, user_id: str) -> None:
        await self._post(
            "/team/member_add",
            {"team_id": team_id, "member": {"user_id": user_id, "role": "user"}},
        )

    async def team_member_delete(self, team_id: str, user_id: str) -> None:
        await self._post(
            "/team/member_delete", {"team_id": team_id, "user_id": user_id}
        )


class Reconciler:
    def __init__(self, admin_client: LiteLLMAdminClient | None = None) -> None:
        self._admin = admin_client or LiteLLMAdminClient()

    def _managed_group(self, display_name: str) -> bool:
        prefix = get_settings().scim_team_prefix
        return display_name.startswith(prefix) if prefix else True

    @staticmethod
    def _identities(resource: dict[str, Any]) -> list[str]:
        """Every value the JWT `sub` might carry for this user.

        The IdP's token `sub` may equal externalId, userName, or the SCIM id
        depending on provider config, and auth checks the deactivation set by
        `sub`. Add all of them so deactivation matches whichever is presented,
        rather than silently failing to revoke.
        """
        return [
            str(v)
            for v in (
                resource.get("externalId"),
                resource.get("userName"),
                resource.get("id"),
            )
            if v
        ]

    async def user_changed(self, before: dict[str, Any] | None, after: dict[str, Any]) -> None:
        was_active = bool(before.get("active", True)) if before else True
        now_active = bool(after.get("active", True))
        identities = self._identities(after)
        if not identities:
            return
        if was_active and not now_active:
            await self._deactivate(identities)
        elif not was_active and now_active:
            await self._reactivate(identities)

    async def user_deleted(self, resource: dict[str, Any]) -> None:
        identities = self._identities(resource)
        if identities:
            await self._deactivate(identities)

    async def group_changed(
        self, before: dict[str, Any] | None, after: dict[str, Any]
    ) -> None:
        name = after.get("displayName", "")
        if not self._managed_group(name):
            return
        team_id = str(after["id"])
        if before is None:
            try:
                await self._admin.team_new(team_id, name)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 400:  # already exists
                    raise
        elif before.get("displayName") != name:
            await self._admin.team_update_alias(team_id, name)

        old_members = {m["value"] for m in (before or {}).get("members", []) if m.get("value")}
        new_members = {m["value"] for m in after.get("members", []) if m.get("value")}
        for user_id in sorted(new_members - old_members):
            await self._admin.team_member_add(team_id, user_id)
        for user_id in sorted(old_members - new_members):
            await self._admin.team_member_delete(team_id, user_id)
        if old_members != new_members or before is None:
            emit_event(
                "admin.action",
                user_id="scim",
                team_id=team_id,
                guardrail_info=None,
                extra={
                    "action": "scim_group_sync",
                    "added": sorted(new_members - old_members),
                    "removed": sorted(old_members - new_members),
                },
            )

    async def group_deleted(self, resource: dict[str, Any]) -> None:
        if not self._managed_group(resource.get("displayName", "")):
            return
        team_id = str(resource.get("id"))
        for member in resource.get("members", []):
            if member.get("value"):
                try:
                    await self._admin.team_member_delete(team_id, member["value"])
                except httpx.HTTPError:
                    logger.error("failed to remove %s during group delete", member["value"])
        emit_event(
            "admin.action",
            user_id="scim",
            team_id=team_id,
            extra={"action": "scim_group_deleted"},
        )

    async def _deactivate(self, user_ids: list[str]) -> None:
        client = get_redis()
        if client is not None and user_ids:
            try:
                await client.sadd(DEACTIVATED_USERS_SET, *user_ids)
            except Exception:  # noqa: BLE001
                logger.error("failed to add %s to deactivation set", user_ids)
        emit_event(
            "admin.action", user_id=user_ids[0] if user_ids else None,
            extra={"action": "scim_deactivate", "identities": user_ids},
        )

    async def _reactivate(self, user_ids: list[str]) -> None:
        client = get_redis()
        if client is not None and user_ids:
            try:
                await client.srem(DEACTIVATED_USERS_SET, *user_ids)
            except Exception:  # noqa: BLE001
                logger.error("failed to remove %s from deactivation set", user_ids)
        emit_event(
            "admin.action", user_id=user_ids[0] if user_ids else None,
            extra={"action": "scim_reactivate", "identities": user_ids},
        )
