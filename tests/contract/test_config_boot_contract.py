"""§9.3 config smoke: the generated proxy config parses and references
resolvable extension points. (Full proxy boot happens in the integration
suite; here we assert every dotted path in the template imports, so a config
typo or module rename fails fast.)"""

from __future__ import annotations

import importlib
import pathlib

import pytest
import yaml

pytestmark = pytest.mark.contract

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load_template() -> dict:
    with open(ROOT / "config" / "proxy_config.template.yaml") as fh:
        return yaml.safe_load(fh)


def resolve_dotted(path: str) -> object:
    module_path, _, attr = path.rpartition(".")
    module = importlib.import_module(module_path)
    return getattr(module, attr)


class TestTemplateReferences:
    def test_custom_auth_resolves(self) -> None:
        template = load_template()
        target = template["general_settings"]["custom_auth"]
        func = resolve_dotted(target)
        assert callable(func)

    def test_common_checks_enabled(self) -> None:
        # §5.1: budget/model checks must also run against DB records.
        template = load_template()
        assert template["general_settings"]["custom_auth_run_common_checks"] is True

    def test_all_callbacks_resolve(self) -> None:
        from litellm.integrations.custom_logger import CustomLogger

        template = load_template()
        callbacks = template["litellm_settings"]["callbacks"]
        assert len(callbacks) >= 2  # audit + keypool telemetry
        for path in callbacks:
            instance = resolve_dotted(path)
            assert isinstance(instance, CustomLogger), path

    def test_all_guardrails_resolve(self) -> None:
        from litellm.integrations.custom_guardrail import CustomGuardrail

        template = load_template()
        guardrails = template["guardrails"]
        assert len(guardrails) >= 5  # pii, secrets, injection, lists, moderation
        for entry in guardrails:
            cls = resolve_dotted(entry["litellm_params"]["guardrail"])
            assert isinstance(cls, type) and issubclass(cls, CustomGuardrail), entry

    def test_cache_config_matches_supported_type(self) -> None:
        from litellm.types.caching import LiteLLMCacheType

        template = load_template()
        cache_type = template["litellm_settings"]["cache_params"]["type"]
        assert cache_type in {t.value for t in LiteLLMCacheType}

    def test_router_settings_shape(self) -> None:
        template = load_template()
        router = template["router_settings"]
        assert router["routing_strategy"] == "simple-shuffle"
        assert router["num_retries"] >= 1
        assert router["cooldown_time"] >= 1
