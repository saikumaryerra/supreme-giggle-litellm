"""F6: SCIM 2.0 sidecar app (§7B.2) — FastAPI on port 8090.

Endpoints: the RFC 7643/7644 subset Okta/Entra call. Auth: static bearer
token (K8s Secret) with constant-time compare. Exposed at /scim/v2/* via
ingress, reachable only from the IdP's egress ranges.

Run:  uvicorn litellm_ext.scim.app:create_app --factory --port 8090
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from litellm_ext.costgov.access_requests import router as access_router
from litellm_ext.scim.models import (
    PatchRequest,
    ScimGroupResource,
    ScimUserResource,
    error_response,
    list_response,
)
from litellm_ext.scim.reconciler import Reconciler
from litellm_ext.scim.store import InMemoryScimStore, PostgresScimStore, ScimStore
from litellm_ext.settings import get_settings


def _bearer_guard(request: Request) -> None:
    settings = get_settings()
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip()
    if not settings.scim_token or not hmac.compare_digest(token, settings.scim_token):
        raise HTTPException(status_code=401, detail=error_response(401, "invalid token"))


def _parse_username_filter(filter_expr: str | None) -> str | None:
    # The only filter Okta needs: userName eq "value"
    if not filter_expr:
        return None
    parts = filter_expr.split(" ", 2)
    if len(parts) == 3 and parts[0] == "userName" and parts[1].lower() == "eq":
        return parts[2].strip().strip('"')
    raise HTTPException(
        status_code=400, detail=error_response(400, "unsupported filter")
    )


def apply_patch(resource: dict[str, Any], patch: PatchRequest) -> dict[str, Any]:
    """Apply RFC 7644 PATCH ops (replace/add/remove on active and members)."""
    result = dict(resource)
    for operation in patch.Operations:
        op = operation.op.lower()
        path = (operation.path or "").strip()
        if op in ("replace", "add") and not path and isinstance(operation.value, dict):
            result.update(operation.value)
        elif op in ("replace", "add") and path == "active":
            result["active"] = _to_bool(operation.value)
        elif op in ("replace", "add") and path == "members":
            value = operation.value or []
            if op == "add":
                existing = {m.get("value") for m in result.get("members", [])}
                result["members"] = result.get("members", []) + [
                    m for m in value if m.get("value") not in existing
                ]
            else:
                result["members"] = list(value)
        elif op == "remove" and path.startswith("members"):
            if "[" in path:  # members[value eq "id"]
                target = path.split('"')[1] if '"' in path else None
                result["members"] = [
                    m for m in result.get("members", []) if m.get("value") != target
                ]
            else:
                result["members"] = []
        elif op == "replace" and path == "displayName":
            result["displayName"] = operation.value
        elif op == "replace" and path == "userName":
            result["userName"] = operation.value
        # Unknown paths are ignored (SCIM providers send many optional attrs).
    return result


def _to_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)


def create_app(
    store: ScimStore | None = None, reconciler: Reconciler | None = None
) -> FastAPI:
    settings = get_settings()
    if store is None:
        store = (
            PostgresScimStore(settings.audit_db_url)
            if settings.audit_db_url
            else InMemoryScimStore()
        )
    if reconciler is None:
        reconciler = Reconciler()

    app = FastAPI(title="litellm-ext SCIM", dependencies=[Depends(_bearer_guard)])
    app.include_router(access_router)  # F9: /ext/access-request rides the sidecar

    # --- discovery -------------------------------------------------------
    @app.get("/ServiceProviderConfig")
    async def service_provider_config() -> dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {"type": "httpbearer", "name": "Bearer token", "description": ""}
            ],
        }

    @app.get("/ResourceTypes")
    async def resource_types() -> dict[str, Any]:
        return list_response(
            [
                {"id": "User", "name": "User", "endpoint": "/Users"},
                {"id": "Group", "name": "Group", "endpoint": "/Groups"},
            ]
        )

    @app.get("/Schemas")
    async def schemas() -> dict[str, Any]:
        return list_response([])

    # --- users -----------------------------------------------------------
    @app.get("/Users")
    async def list_users(filter: str | None = Query(default=None)) -> dict[str, Any]:
        user_name = _parse_username_filter(filter)
        if user_name is not None:
            user = await store.find_user_by_username(user_name)
            return list_response([user] if user else [])
        return list_response(await store.list_users())

    @app.post("/Users", status_code=201)
    async def create_user(resource: ScimUserResource) -> dict[str, Any]:
        existing = await store.find_user_by_username(resource.userName)
        if existing:
            raise HTTPException(
                status_code=409, detail=error_response(409, "userName already exists")
            )
        stored = await store.upsert_user(resource.model_dump(exclude_none=True))
        await reconciler.user_changed(None, stored)
        return stored

    @app.get("/Users/{user_id}")
    async def get_user(user_id: str) -> dict[str, Any]:
        user = await store.get_user(user_id)
        if not user:
            raise HTTPException(status_code=404, detail=error_response(404, "not found"))
        return user

    @app.put("/Users/{user_id}")
    async def replace_user(user_id: str, resource: ScimUserResource) -> dict[str, Any]:
        before = await store.get_user(user_id)
        if not before:
            raise HTTPException(status_code=404, detail=error_response(404, "not found"))
        data = resource.model_dump(exclude_none=True)
        data["id"] = user_id
        stored = await store.upsert_user(data)
        await reconciler.user_changed(before, stored)
        return stored

    @app.patch("/Users/{user_id}")
    async def patch_user(user_id: str, patch: PatchRequest) -> dict[str, Any]:
        before = await store.get_user(user_id)
        if not before:
            raise HTTPException(status_code=404, detail=error_response(404, "not found"))
        after = apply_patch(before, patch)
        stored = await store.upsert_user(after)
        await reconciler.user_changed(before, stored)
        return stored

    @app.delete("/Users/{user_id}", status_code=204)
    async def delete_user(user_id: str) -> Response:
        resource = await store.get_user(user_id)
        if resource:
            await store.delete_user(user_id)
            await reconciler.user_deleted(resource)
        return Response(status_code=204)

    # --- groups ----------------------------------------------------------
    @app.get("/Groups")
    async def list_groups() -> dict[str, Any]:
        return list_response(await store.list_groups())

    @app.post("/Groups", status_code=201)
    async def create_group(resource: ScimGroupResource) -> dict[str, Any]:
        stored = await store.upsert_group(resource.model_dump(exclude_none=True))
        await reconciler.group_changed(None, stored)
        return stored

    @app.get("/Groups/{group_id}")
    async def get_group(group_id: str) -> dict[str, Any]:
        group = await store.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail=error_response(404, "not found"))
        return group

    @app.patch("/Groups/{group_id}")
    async def patch_group(group_id: str, patch: PatchRequest) -> dict[str, Any]:
        before = await store.get_group(group_id)
        if not before:
            raise HTTPException(status_code=404, detail=error_response(404, "not found"))
        after = apply_patch(before, patch)
        stored = await store.upsert_group(after)
        await reconciler.group_changed(before, stored)
        return stored

    return app
