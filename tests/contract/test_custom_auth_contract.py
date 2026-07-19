"""§9.3: interface assertions against the INSTALLED litellm version.

These tests are the upgrade safety net: a Renovate bump that renames or
reshapes anything litellm-ext depends on fails here — in CI, not production.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime

import pytest

pytestmark = pytest.mark.contract


class TestUserApiKeyAuth:
    def test_importable_from_documented_path(self) -> None:
        from litellm.proxy._types import UserAPIKeyAuth  # noqa: F401

    def test_constructible_with_every_field_we_use(self) -> None:
        from litellm.proxy._types import UserAPIKeyAuth

        obj = UserAPIKeyAuth(
            api_key="jwt-abc123",
            user_id="user-1",
            user_email="a@b.com",
            user_role="internal_user",
            team_id="team-a",
            models=["gpt-4o"],
            tpm_limit=1000,
            rpm_limit=10,
            max_budget=100.0,
            allowed_routes=["/v1/chat/completions"],
            expires=datetime.now(tz=UTC),
            metadata={"auth_method": "jwt", "idp_roles": ["r"], "priority": "standard"},
        )
        # Fields we read downstream must round-trip.
        assert obj.user_id == "user-1"
        assert obj.team_id == "team-a"
        assert obj.models == ["gpt-4o"]
        assert obj.metadata["priority"] == "standard"

    def test_litellm_user_roles_values_we_map_to(self) -> None:
        from litellm.proxy._types import LitellmUserRoles

        values = {r.value for r in LitellmUserRoles}
        assert {"proxy_admin", "internal_user"} <= values


class TestVirtualKeyPassthrough:
    def test_internal_builder_still_resolves(self) -> None:
        # §5.3: the ONLY litellm-internal import, isolated in passthrough.py.
        from litellm.proxy.auth.user_api_key_auth import _user_api_key_auth_builder

        params = inspect.signature(_user_api_key_auth_builder).parameters
        for required in ("request", "api_key", "request_data"):
            assert required in params, f"builder lost parameter {required}"

    def test_request_body_reader_still_resolves(self) -> None:
        from litellm.proxy.common_utils.http_parsing_utils import (  # noqa: F401
            _read_request_body,
        )
