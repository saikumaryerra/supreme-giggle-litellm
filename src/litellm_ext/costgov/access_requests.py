"""F9: model-access requests, GitOps-native (§7B.5).

POST /ext/access-request {model, justification} (JWT-authenticated via F1)
→ opens a GitHub issue proposing the rbac.yaml diff. Approval = merging the
resulting PR; the existing config rollout applies it. Rides the SCIM sidecar
app, so the proxy itself gains no new routes.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from litellm_ext.audit import emit_event
from litellm_ext.settings import get_settings

router = APIRouter()


class AccessRequest(BaseModel):
    model: str = Field(min_length=1, max_length=200)
    justification: str = Field(min_length=1, max_length=2000)
    team_id: str | None = None


def proposed_rbac_diff(team_id: str, model: str) -> str:
    return (
        f"```yaml\n"
        f"# proposed change to config/rbac.yaml\n"
        f"teams:\n"
        f"  {team_id}:\n"
        f"    extra_models:\n"
        f"      - {model}   # + requested\n"
        f"```"
    )


async def open_issue(title: str, body: str) -> str:
    """Create a GitHub issue; returns its URL. repo_url is the API repo URL."""
    settings = get_settings()
    if not (settings.repo_url and settings.repo_token):
        raise HTTPException(
            status_code=503, detail={"error": "access_requests_not_configured"}
        )
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{settings.repo_url.rstrip('/')}/issues",
            json={"title": title, "body": body, "labels": ["access-request"]},
            headers={
                "Authorization": f"Bearer {settings.repo_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        resp.raise_for_status()
        return str(resp.json().get("html_url", ""))


@router.post("/ext/access-request", status_code=202)
async def create_access_request(request: Request, body: AccessRequest) -> dict[str, Any]:
    # The sidecar sits behind the same JWT auth as the proxy when routed via
    # ingress; identity headers are forwarded by oauth2-proxy/F1 middleware.
    user_id = request.headers.get("x-forwarded-user") or "unknown"
    team_id = body.team_id or request.headers.get("x-forwarded-groups") or "unknown"

    issue_url = await open_issue(
        title=f"[access-request] {team_id}: {body.model}",
        body=(
            f"Requested by: `{user_id}`\nTeam: `{team_id}`\nModel: `{body.model}`\n\n"
            f"Justification:\n> {body.justification}\n\n"
            + proposed_rbac_diff(team_id, body.model)
        ),
    )
    emit_event(
        "admin.access_requested",
        user_id=user_id,
        team_id=team_id,
        model_requested=body.model,
        extra={"issue_url": issue_url},
    )
    return {"status": "submitted", "issue_url": issue_url}
