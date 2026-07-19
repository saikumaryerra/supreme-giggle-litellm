from __future__ import annotations

import pytest

from litellm_ext.auth.claims import ClaimError, as_list, extract_claims, resolve_path
from litellm_ext.settings import reset_settings_cache


class TestResolvePath:
    def test_flat(self) -> None:
        assert resolve_path({"roles": ["a"]}, "roles") == ["a"]

    def test_dot_notation(self) -> None:
        payload = {"realm_access": {"roles": ["admin"]}}
        assert resolve_path(payload, "realm_access.roles") == ["admin"]

    def test_absent_returns_none(self) -> None:
        assert resolve_path({}, "realm_access.roles") is None


class TestAsList:
    def test_list_form(self) -> None:
        assert as_list(["a", "b"]) == ["a", "b"]

    def test_space_delimited_string(self) -> None:
        assert as_list("a b c") == ["a", "b", "c"]

    def test_none(self) -> None:
        assert as_list(None) == []


class TestExtractClaims:
    PAYLOAD = {
        "sub": "user-1",
        "exp": 2000000000,
        "email": "a@b.com",
        "roles": ["llm-engineer"],
        "groups": ["data-science", "other"],
    }

    def test_happy_path(self) -> None:
        claims = extract_claims(self.PAYLOAD)
        assert claims.sub == "user-1"
        assert claims.roles == ["llm-engineer"]
        assert claims.team == "data-science"  # first group

    def test_missing_sub_raises(self) -> None:
        with pytest.raises(ClaimError):
            extract_claims({"exp": 1})

    def test_dot_notation_role_claim(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_EXT_ROLE_CLAIM", "realm_access.roles")
        reset_settings_cache()
        payload = dict(self.PAYLOAD, realm_access={"roles": ["nested-role"]})
        assert extract_claims(payload).roles == ["nested-role"]
