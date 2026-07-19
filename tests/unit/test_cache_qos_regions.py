"""F11 (§7B.7), F12 (§7B.8), F13 (§7B.9) unit tests."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from litellm_ext.cache.semantic_cache import (
    cache_namespace,
    normalize_prompt,
    should_cache,
)
from litellm_ext.qos.priority import tier_of, tier_rate
from litellm_ext.regions.residency import pin_models_to_regions
from litellm_ext.settings import reset_settings_cache

USER = SimpleNamespace(user_id="u1", team_id="team-a", metadata={})


def data(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}],
    }
    base.update(overrides)
    return base


class TestCacheSafetyRules:
    def test_plain_request_cacheable(self) -> None:
        assert should_cache(data(), USER) == (True, "ok")

    def test_streaming_never_cached(self) -> None:
        assert should_cache(data(stream=True), USER)[1] == "streaming"

    def test_high_temperature_not_cached(self) -> None:
        assert should_cache(data(temperature=0.9), USER)[1] == "temperature"

    def test_masked_pii_never_cached(self) -> None:
        result = should_cache(data(metadata={"pii_masked": True}), USER)
        assert result == (False, "guardrail_flagged")

    def test_tool_calls_not_cached(self) -> None:
        assert should_cache(data(tools=[{"type": "function"}]), USER)[1] == "tools_present"

    def test_namespace_isolates_tenants(self) -> None:
        # Tenant isolation is namespace-level (hard rule §13).
        assert cache_namespace("team:a", "gpt-4o") != cache_namespace("team:b", "gpt-4o")
        assert "team:a" in cache_namespace("team:a", "gpt-4o")

    def test_teamless_keys_do_not_share_namespace(self) -> None:
        from types import SimpleNamespace

        from litellm_ext.cache.semantic_cache import tenant_key

        a = SimpleNamespace(team_id=None, user_id="svc-a", api_key="k1")
        b = SimpleNamespace(team_id=None, user_id="svc-b", api_key="k2")
        assert tenant_key(a) != tenant_key(b)  # distinct teamless service keys
        anon1 = SimpleNamespace(team_id=None, user_id=None, api_key="k1")
        anon2 = SimpleNamespace(team_id=None, user_id=None, api_key="k2")
        assert tenant_key(anon1) != tenant_key(anon2)

    def test_normalize_strips_whitespace_and_user(self) -> None:
        first = normalize_prompt(data(messages=[{"role": "user", "content": "a   b\n c"}], user="x"))
        second = normalize_prompt(data(messages=[{"role": "user", "content": "a b c"}], user="y"))
        assert first == second


class TestQos:
    def test_tier_from_auth_metadata(self) -> None:
        assert tier_of(SimpleNamespace(metadata={"priority": "batch"})) == "batch"
        assert tier_of(SimpleNamespace(metadata={})) == "standard"
        assert tier_of(SimpleNamespace(metadata={"priority": "bogus"})) == "standard"

    def test_tier_rates_follow_weights(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_EXT_QOS_CAPACITY_RPS", "100")
        reset_settings_cache()
        assert tier_rate("interactive") == pytest.approx(70.0)
        assert tier_rate("standard") == pytest.approx(25.0)
        assert tier_rate("batch") == pytest.approx(5.0)

    async def test_disabled_qos_is_passthrough(self) -> None:
        from litellm_ext.qos.priority import QosPriorityGuardrail

        payload = data()
        result = await QosPriorityGuardrail().async_pre_call_hook(
            USER, None, payload, "completion"
        )
        assert result is payload


class TestResidency:
    def test_bare_models_pinned_to_region_alias(self) -> None:
        assert pin_models_to_regions(["gpt-4o"], ["eu"]) == ["gpt-4o-eu"]

    def test_allowed_region_alias_kept(self) -> None:
        assert pin_models_to_regions(["gpt-4o-eu"], ["eu"]) == ["gpt-4o-eu"]

    def test_disallowed_region_alias_dropped(self) -> None:
        assert pin_models_to_regions(["gpt-4o-us"], ["eu"]) == []

    def test_wildcard_dropped_under_pin(self) -> None:
        # Wildcards cannot be region-scoped; explicit aliases only.
        assert pin_models_to_regions(["*"], ["eu"]) == []

    def test_no_pin_passthrough(self) -> None:
        assert pin_models_to_regions(["gpt-4o", "*"], []) == ["gpt-4o", "*"]
