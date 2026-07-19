"""F6: SCIM 2.0 resource models — the RFC 7643 subset Okta/Entra actually send."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimEmail(BaseModel):
    model_config = ConfigDict(extra="allow")
    value: str
    primary: bool = False


class ScimUserResource(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    schemas: list[str] = Field(default_factory=lambda: [USER_SCHEMA])
    id: str | None = None
    externalId: str | None = None
    userName: str
    active: bool = True
    emails: list[ScimEmail] = Field(default_factory=list)

    def primary_email(self) -> str | None:
        for email in self.emails:
            if email.primary:
                return email.value
        return self.emails[0].value if self.emails else None


class ScimMember(BaseModel):
    model_config = ConfigDict(extra="allow")
    value: str  # user id
    display: str | None = None


class ScimGroupResource(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    schemas: list[str] = Field(default_factory=lambda: [GROUP_SCHEMA])
    id: str | None = None
    externalId: str | None = None
    displayName: str
    members: list[ScimMember] = Field(default_factory=list)


class PatchOperation(BaseModel):
    model_config = ConfigDict(extra="allow")
    op: str  # replace | add | remove (case-insensitive per RFC)
    path: str | None = None
    value: Any = None


class PatchRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    schemas: list[str] = Field(default_factory=lambda: [PATCH_SCHEMA])
    Operations: list[PatchOperation]


def list_response(resources: list[dict[str, Any]], start_index: int = 1) -> dict[str, Any]:
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


def error_response(status: int, detail: str) -> dict[str, Any]:
    return {"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}
