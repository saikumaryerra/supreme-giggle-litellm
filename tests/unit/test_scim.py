"""F6 acceptance criteria (§7B.2) at unit level: Okta smoke sequence."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from litellm_ext.scim.app import apply_patch, create_app
from litellm_ext.scim.models import PatchRequest
from litellm_ext.scim.reconciler import Reconciler
from litellm_ext.scim.store import InMemoryScimStore
from litellm_ext.settings import reset_settings_cache

TOKEN = "scim-secret-token"


class FakeAdmin:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    async def team_new(self, team_id: str, alias: str) -> None:
        self.calls.append(("team_new", (team_id, alias)))

    async def team_update_alias(self, team_id: str, alias: str) -> None:
        self.calls.append(("team_update_alias", (team_id, alias)))

    async def team_member_add(self, team_id: str, user_id: str) -> None:
        self.calls.append(("member_add", (team_id, user_id)))

    async def team_member_delete(self, team_id: str, user_id: str) -> None:
        self.calls.append(("member_delete", (team_id, user_id)))


class FakeRedis:
    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}

    async def sadd(self, name: str, member: str) -> None:
        self.sets.setdefault(name, set()).add(member)

    async def srem(self, name: str, member: str) -> None:
        self.sets.get(name, set()).discard(member)


@pytest.fixture()
def scim(monkeypatch: pytest.MonkeyPatch) -> tuple[httpx.AsyncClient, FakeAdmin, FakeRedis]:
    monkeypatch.setenv("LITELLM_EXT_SCIM_TOKEN", TOKEN)
    monkeypatch.setenv("LITELLM_EXT_SCIM_TEAM_PREFIX", "llm-")
    reset_settings_cache()

    fake_redis = FakeRedis()
    import litellm_ext.scim.reconciler as reconciler_module

    monkeypatch.setattr(reconciler_module, "get_redis", lambda: fake_redis)

    admin = FakeAdmin()
    app = create_app(store=InMemoryScimStore(), reconciler=Reconciler(admin_client=admin))
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://scim",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    return client, admin, fake_redis


class TestAuth:
    async def test_missing_token_401(self, scim: Any) -> None:
        client, _, _ = scim
        resp = await client.get("/Users", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401


class TestOktaSmokeSequence:
    async def test_create_user_group_deactivate(self, scim: Any) -> None:
        client, admin, fake_redis = scim

        # 1. Create user.
        resp = await client.post(
            "/Users",
            json={
                "userName": "jane@example.com",
                "externalId": "okta-jane",
                "emails": [{"value": "jane@example.com", "primary": True}],
                "active": True,
            },
        )
        assert resp.status_code == 201
        user_id = resp.json()["id"]

        # 2. Filter lookup (the only filter Okta needs).
        resp = await client.get("/Users", params={"filter": 'userName eq "jane@example.com"'})
        assert resp.json()["totalResults"] == 1

        # 3. Create managed group with member → /team/new + member_add.
        resp = await client.post(
            "/Groups",
            json={
                "displayName": "llm-data-science",
                "members": [{"value": "okta-jane"}],
            },
        )
        assert resp.status_code == 201
        group_id = resp.json()["id"]
        assert ("team_new", (group_id, "llm-data-science")) in admin.calls
        assert ("member_add", (group_id, "okta-jane")) in admin.calls

        # 4. Membership PATCH remove.
        resp = await client.patch(
            f"/Groups/{group_id}",
            json={
                "Operations": [
                    {"op": "remove", "path": 'members[value eq "okta-jane"]'}
                ]
            },
        )
        assert resp.status_code == 200
        assert ("member_delete", (group_id, "okta-jane")) in admin.calls

        # 5. Deactivate via PATCH → deactivation set, immediately enforced.
        resp = await client.patch(
            f"/Users/{user_id}",
            json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        )
        assert resp.status_code == 200
        assert "okta-jane" in fake_redis.sets.get("ext:deactivated_users", set())

        # 6. Reactivate clears the set.
        await client.patch(
            f"/Users/{user_id}",
            json={"Operations": [{"op": "replace", "path": "active", "value": True}]},
        )
        assert "okta-jane" not in fake_redis.sets.get("ext:deactivated_users", set())

    async def test_group_rename_keeps_team_id(self, scim: Any) -> None:
        client, admin, _ = scim
        resp = await client.post("/Groups", json={"displayName": "llm-alpha"})
        group_id = resp.json()["id"]
        await client.patch(
            f"/Groups/{group_id}",
            json={
                "Operations": [
                    {"op": "replace", "path": "displayName", "value": "llm-beta"}
                ]
            },
        )
        # team_id stable = SCIM group id; only the alias changes (§7B.2).
        assert ("team_update_alias", (group_id, "llm-beta")) in admin.calls

    async def test_unmanaged_group_prefix_ignored(self, scim: Any) -> None:
        client, admin, _ = scim
        await client.post("/Groups", json={"displayName": "hr-payroll"})
        assert not any(c[0] == "team_new" for c in admin.calls)

    async def test_duplicate_username_409(self, scim: Any) -> None:
        client, _, _ = scim
        body = {"userName": "dup@example.com"}
        assert (await client.post("/Users", json=body)).status_code == 201
        assert (await client.post("/Users", json=body)).status_code == 409

    async def test_delete_user_deactivates(self, scim: Any) -> None:
        client, _, fake_redis = scim
        resp = await client.post(
            "/Users", json={"userName": "gone@example.com", "externalId": "okta-gone"}
        )
        user_id = resp.json()["id"]
        resp = await client.delete(f"/Users/{user_id}")
        assert resp.status_code == 204
        assert "okta-gone" in fake_redis.sets.get("ext:deactivated_users", set())


class TestApplyPatch:
    def test_add_members_dedupes(self) -> None:
        resource = {"members": [{"value": "a"}]}
        patch = PatchRequest(
            Operations=[
                {"op": "add", "path": "members", "value": [{"value": "a"}, {"value": "b"}]}
            ]
        )
        result = apply_patch(resource, patch)
        assert [m["value"] for m in result["members"]] == ["a", "b"]

    def test_string_boolean_coerced(self) -> None:
        patch = PatchRequest(
            Operations=[{"op": "Replace", "path": "active", "value": "False"}]
        )
        assert apply_patch({"active": True}, patch)["active"] is False
