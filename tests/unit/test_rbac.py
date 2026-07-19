from __future__ import annotations

import pytest

from litellm_ext.auth.rbac import RbacDenied, RbacEngine

CONFIG = {
    "roles": {
        "llm-admin": {
            "litellm_role": "proxy_admin",
            "models": ["*"],
            "allowed_routes": ["*"],
        },
        "llm-engineer": {
            "litellm_role": "internal_user",
            "models": ["gpt-4o", "gpt-4o-mini"],
            "tpm_limit": 200000,
            "rpm_limit": 500,
            "max_budget": 500.0,
            "allowed_routes": ["/v1/chat/completions"],
            "priority": "standard",
        },
    },
    "default": {"action": "deny"},
    "teams": {
        "data-science": {"extra_models": ["o3"]},
        "eu-finance": {"allowed_regions": ["eu"], "allowed_cidrs": ["10.0.0.0/8"]},
    },
}


class TestRbacEngine:
    def engine(self, config: dict = CONFIG) -> RbacEngine:
        return RbacEngine(config)

    def test_first_match_wins_in_file_order(self) -> None:
        # Token carries both roles; llm-admin is listed first in the file.
        resolved = self.engine().resolve(["llm-engineer", "llm-admin"], None)
        assert resolved.matched_role == "llm-admin"
        assert resolved.litellm_role == "proxy_admin"

    def test_engineer_mapping(self) -> None:
        resolved = self.engine().resolve(["llm-engineer"], None)
        assert resolved.models == ["gpt-4o", "gpt-4o-mini"]
        assert resolved.tpm_limit == 200000
        assert resolved.max_budget == 500.0

    def test_team_extra_models_merged(self) -> None:
        resolved = self.engine().resolve(["llm-engineer"], "data-science")
        assert "o3" in resolved.models

    def test_no_match_default_deny(self) -> None:
        with pytest.raises(RbacDenied):
            self.engine().resolve(["unknown-role"], None)

    def test_default_map(self) -> None:
        config = dict(
            CONFIG,
            default={
                "action": "map",
                "litellm_role": "internal_user",
                "models": ["gpt-4o-mini"],
            },
        )
        resolved = self.engine(config).resolve(["unknown-role"], None)
        assert resolved.matched_role == "default"
        assert resolved.models == ["gpt-4o-mini"]

    def test_residency_pins_models_to_region_aliases(self) -> None:
        resolved = self.engine().resolve(["llm-engineer"], "eu-finance")
        assert resolved.allowed_regions == ["eu"]
        assert resolved.models == ["gpt-4o-eu", "gpt-4o-mini-eu"]

    def test_team_cidrs_carried(self) -> None:
        resolved = self.engine().resolve(["llm-engineer"], "eu-finance")
        assert resolved.allowed_cidrs == ["10.0.0.0/8"]
