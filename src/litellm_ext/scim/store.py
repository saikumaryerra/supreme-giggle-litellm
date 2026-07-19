"""F6: SCIM resource persistence.

Two implementations of one interface: PostgresScimStore (scim_users /
scim_groups tables in the audit DB) for production, InMemoryScimStore for
tests and single-pod evaluation.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol


class ScimStore(Protocol):
    async def get_user(self, user_id: str) -> dict[str, Any] | None: ...
    async def find_user_by_username(self, user_name: str) -> dict[str, Any] | None: ...
    async def list_users(self) -> list[dict[str, Any]]: ...
    async def upsert_user(self, resource: dict[str, Any]) -> dict[str, Any]: ...
    async def delete_user(self, user_id: str) -> bool: ...
    async def get_group(self, group_id: str) -> dict[str, Any] | None: ...
    async def find_group_by_name(self, name: str) -> dict[str, Any] | None: ...
    async def list_groups(self) -> list[dict[str, Any]]: ...
    async def upsert_group(self, resource: dict[str, Any]) -> dict[str, Any]: ...


def _ensure_id(resource: dict[str, Any]) -> dict[str, Any]:
    if not resource.get("id"):
        resource["id"] = str(uuid.uuid4())
    return resource


class InMemoryScimStore:
    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        return self.users.get(user_id)

    async def find_user_by_username(self, user_name: str) -> dict[str, Any] | None:
        for user in self.users.values():
            if user.get("userName") == user_name:
                return user
        return None

    async def list_users(self) -> list[dict[str, Any]]:
        return list(self.users.values())

    async def upsert_user(self, resource: dict[str, Any]) -> dict[str, Any]:
        resource = _ensure_id(dict(resource))
        self.users[resource["id"]] = resource
        return resource

    async def delete_user(self, user_id: str) -> bool:
        return self.users.pop(user_id, None) is not None

    async def get_group(self, group_id: str) -> dict[str, Any] | None:
        return self.groups.get(group_id)

    async def find_group_by_name(self, name: str) -> dict[str, Any] | None:
        for group in self.groups.values():
            if group.get("displayName") == name:
                return group
        return None

    async def list_groups(self) -> list[dict[str, Any]]:
        return list(self.groups.values())

    async def upsert_group(self, resource: dict[str, Any]) -> dict[str, Any]:
        resource = _ensure_id(dict(resource))
        self.groups[resource["id"]] = resource
        return resource


class PostgresScimStore:
    """scim_users/scim_groups in the audit Postgres (created by migration 0001)."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn.replace("postgresql+asyncpg://", "postgresql://")

    async def _conn(self) -> Any:
        import asyncpg

        return await asyncpg.connect(self._dsn, timeout=5.0)

    async def get_user(self, user_id: str) -> dict[str, Any] | None:
        conn = await self._conn()
        try:
            row = await conn.fetchrow("SELECT raw FROM scim_users WHERE id = $1", user_id)
            return json.loads(row["raw"]) if row else None
        finally:
            await conn.close()

    async def find_user_by_username(self, user_name: str) -> dict[str, Any] | None:
        conn = await self._conn()
        try:
            row = await conn.fetchrow(
                "SELECT raw FROM scim_users WHERE user_name = $1", user_name
            )
            return json.loads(row["raw"]) if row else None
        finally:
            await conn.close()

    async def list_users(self) -> list[dict[str, Any]]:
        conn = await self._conn()
        try:
            rows = await conn.fetch("SELECT raw FROM scim_users ORDER BY user_name")
            return [json.loads(r["raw"]) for r in rows]
        finally:
            await conn.close()

    async def upsert_user(self, resource: dict[str, Any]) -> dict[str, Any]:
        resource = _ensure_id(dict(resource))
        conn = await self._conn()
        try:
            await conn.execute(
                """
                INSERT INTO scim_users (id, external_id, user_name, email, active, raw, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (id) DO UPDATE SET
                  external_id = EXCLUDED.external_id, user_name = EXCLUDED.user_name,
                  email = EXCLUDED.email, active = EXCLUDED.active,
                  raw = EXCLUDED.raw, updated_at = EXCLUDED.updated_at
                """,
                resource["id"],
                resource.get("externalId"),
                resource.get("userName", ""),
                _primary_email(resource),
                bool(resource.get("active", True)),
                json.dumps(resource),
                datetime.now(tz=UTC),
            )
            return resource
        finally:
            await conn.close()

    async def delete_user(self, user_id: str) -> bool:
        conn = await self._conn()
        try:
            result = await conn.execute("DELETE FROM scim_users WHERE id = $1", user_id)
            return bool(result.endswith("1"))
        finally:
            await conn.close()

    async def get_group(self, group_id: str) -> dict[str, Any] | None:
        conn = await self._conn()
        try:
            row = await conn.fetchrow("SELECT raw FROM scim_groups WHERE id = $1", group_id)
            return json.loads(row["raw"]) if row else None
        finally:
            await conn.close()

    async def find_group_by_name(self, name: str) -> dict[str, Any] | None:
        conn = await self._conn()
        try:
            row = await conn.fetchrow(
                "SELECT raw FROM scim_groups WHERE display_name = $1", name
            )
            return json.loads(row["raw"]) if row else None
        finally:
            await conn.close()

    async def list_groups(self) -> list[dict[str, Any]]:
        conn = await self._conn()
        try:
            rows = await conn.fetch("SELECT raw FROM scim_groups ORDER BY display_name")
            return [json.loads(r["raw"]) for r in rows]
        finally:
            await conn.close()

    async def upsert_group(self, resource: dict[str, Any]) -> dict[str, Any]:
        resource = _ensure_id(dict(resource))
        conn = await self._conn()
        try:
            await conn.execute(
                """
                INSERT INTO scim_groups (id, display_name, members, raw, updated_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (id) DO UPDATE SET
                  display_name = EXCLUDED.display_name, members = EXCLUDED.members,
                  raw = EXCLUDED.raw, updated_at = EXCLUDED.updated_at
                """,
                resource["id"],
                resource.get("displayName", ""),
                json.dumps(resource.get("members", [])),
                json.dumps(resource),
                datetime.now(tz=UTC),
            )
            return resource
        finally:
            await conn.close()


def _primary_email(resource: dict[str, Any]) -> str | None:
    emails = resource.get("emails") or []
    for email in emails:
        if isinstance(email, dict) and email.get("primary"):
            return email.get("value")
    if emails and isinstance(emails[0], dict):
        return emails[0].get("value")
    return None
