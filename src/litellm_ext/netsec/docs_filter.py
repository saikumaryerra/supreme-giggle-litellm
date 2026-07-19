"""F5: route lockdown & docs filtering ASGI middleware (§7B.1b).

(a) When DOCS_FILTERED, intercept GET /openapi.json and strip all paths not
in the public set, rewriting info.title/description from branding env vars.
(b) When ROUTE_LOCKDOWN, hard-404 management routes unless the resolved role
is proxy_admin — belt-and-braces on top of allowed_routes.

Registered by adding ``litellm_ext.netsec.docs_filter.DocsFilterMiddleware``
to the app when the pinned LiteLLM version supports custom middleware
(feature-flagged; the contract test skips gracefully when the hook is absent).
"""

from __future__ import annotations

import json
from typing import Any

from litellm_ext.settings import get_settings

PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/chat/completions",
    "/completions",
    "/embeddings",
    "/models",
    "/health",
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/models",
)

MANAGEMENT_PREFIXES: tuple[str, ...] = (
    "/key/",
    "/team/",
    "/user/",
    "/model/",
    "/organization/",
    "/budget/",
    "/config/",
)


def filter_openapi(spec: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    filtered = dict(spec)
    filtered["paths"] = {
        path: ops
        for path, ops in (spec.get("paths") or {}).items()
        if path.startswith(PUBLIC_PATH_PREFIXES)
    }
    info = dict(filtered.get("info") or {})
    info["title"] = settings.docs_title
    info["description"] = settings.docs_description
    filtered["info"] = info
    return filtered


def is_management_route(path: str) -> bool:
    normalized = path.removeprefix("/v1")
    return normalized.startswith(MANAGEMENT_PREFIXES)


class DocsFilterMiddleware:
    """Pure-ASGI middleware (no starlette dependency on the hot path)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        settings = get_settings()
        path = scope.get("path", "")

        if settings.route_lockdown and is_management_route(path):
            role = _resolved_role(scope)
            if role != "proxy_admin":
                await _send_json(send, 404, {"error": "not_found"})
                return

        if settings.docs_filtered and path == "/openapi.json":
            await self._filtered_openapi(scope, receive, send)
            return

        await self.app(scope, receive, send)

    async def _filtered_openapi(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        body_parts: list[bytes] = []
        status_holder: dict[str, Any] = {}

        async def capture(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            elif message["type"] == "http.response.body":
                body_parts.append(message.get("body", b""))

        await self.app(scope, receive, capture)
        raw = b"".join(body_parts)
        try:
            spec = json.loads(raw)
            payload = filter_openapi(spec)
        except (ValueError, TypeError):
            await _send_json(send, 500, {"error": "openapi_filter_failed"})
            return
        await _send_json(send, int(status_holder.get("status", 200)), payload)


def _resolved_role(scope: dict[str, Any]) -> str | None:
    # LiteLLM stores the resolved UserAPIKeyAuth on request state when
    # available; fall back to None (locked down) otherwise.
    state = scope.get("state") or {}
    auth = state.get("user_api_key_auth") if isinstance(state, dict) else None
    return getattr(auth, "user_role", None) or (
        auth.get("user_role") if isinstance(auth, dict) else None
    )


async def _send_json(send: Any, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
