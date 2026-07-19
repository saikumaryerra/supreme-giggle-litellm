"""F4 generator unit tests (§7A.3 rules, §13 drift risk)."""

from __future__ import annotations

import pathlib

import pytest
import yaml

from litellm_ext.keypool.generator import (
    expand_model_list,
    region_fallbacks,
    render_config,
)
from litellm_ext.keypool.schema import KeypoolConfig, load_keypool

POOL = {
    "pools": [
        {
            "provider": "openai",
            "models": [
                {"model_name": "gpt-4o", "upstream_model": "openai/gpt-4o"},
                {"model_name": "gpt-4o-mini", "upstream_model": "openai/gpt-4o-mini"},
            ],
            "keys": [
                {
                    "key_id": "a",
                    "api_key_env": "KEY_A",
                    "weight": 2,
                    "tpm": 1000,
                    "rpm": 10,
                },
                {"key_id": "b", "api_key_env": "KEY_B"},
                {"key_id": "old", "api_key_env": "KEY_OLD", "enabled": False},
            ],
        }
    ]
}


def config(raw: dict = POOL) -> KeypoolConfig:
    return KeypoolConfig.model_validate(raw)


class TestExpansion:
    def test_deployments_equal_models_times_enabled_keys(self) -> None:
        entries = expand_model_list(config())
        assert len(entries) == 2 * 2  # 2 models x 2 enabled keys

    def test_disabled_key_produces_no_deployment(self) -> None:
        ids = [e["model_info"]["id"] for e in expand_model_list(config())]
        assert not any("::old" in i for i in ids)

    def test_deployment_shape(self) -> None:
        entry = next(
            e
            for e in expand_model_list(config())
            if e["model_info"]["id"] == "gpt-4o::a"
        )
        assert entry["model_name"] == "gpt-4o"
        assert entry["litellm_params"] == {
            "model": "openai/gpt-4o",
            "api_key": "os.environ/KEY_A",  # env ref — secret never on disk
            "weight": 2,
            "tpm": 1000,
            "rpm": 10,
        }
        assert entry["model_info"]["key_id"] == "a"

    def test_deterministic_sorted_output(self) -> None:
        entries = expand_model_list(config())
        keys = [(e["model_name"], e["model_info"]["id"]) for e in entries]
        assert keys == sorted(keys)


class TestValidation:
    def test_duplicate_key_id_rejected(self) -> None:
        raw = {
            "pools": [
                {
                    "provider": "openai",
                    "models": [{"model_name": "m", "upstream_model": "openai/m"}],
                    "keys": [
                        {"key_id": "dup", "api_key_env": "X"},
                        {"key_id": "dup", "api_key_env": "Y"},
                    ],
                }
            ]
        }
        with pytest.raises(ValueError, match="duplicate key_id"):
            config(raw)

    def test_no_enabled_keys_rejected(self) -> None:
        raw = {
            "pools": [
                {
                    "provider": "openai",
                    "models": [{"model_name": "m", "upstream_model": "openai/m"}],
                    "keys": [{"key_id": "k", "api_key_env": "X", "enabled": False}],
                }
            ]
        }
        with pytest.raises(ValueError, match="no enabled keys"):
            config(raw)

    def test_missing_env_named_but_never_value(self) -> None:
        with pytest.raises(RuntimeError) as exc_info:
            config().validate_env({"KEY_A": "sk-secret"})
        assert "KEY_B" in str(exc_info.value)
        assert "sk-secret" not in str(exc_info.value)

    def test_disabled_key_env_not_required(self) -> None:
        config().validate_env({"KEY_A": "x", "KEY_B": "y"})  # KEY_OLD absent → ok


class TestRegions:
    RAW = {
        "pools": [
            {
                "provider": "azure",
                "models": [{"model_name": "gpt-4o", "upstream_model": "azure/gpt-4o"}],
                "failover": {"eu": ["us"]},
                "keys": [
                    {"key_id": "eu1", "api_key_env": "K_EU", "region": "eu",
                     "api_base": "https://eu.example.com"},
                    {"key_id": "us1", "api_key_env": "K_US", "region": "us",
                     "api_base": "https://us.example.com"},
                ],
            }
        ]
    }

    def test_region_alias_emitted(self) -> None:
        names = {e["model_name"] for e in expand_model_list(config(self.RAW))}
        assert names == {"gpt-4o", "gpt-4o-eu", "gpt-4o-us"}

    def test_cross_region_fallback(self) -> None:
        assert region_fallbacks(config(self.RAW)) == [{"gpt-4o-eu": ["gpt-4o-us"]}]

    def test_fallback_skipped_when_target_region_absent(self) -> None:
        raw = {
            "pools": [
                {
                    "provider": "azure",
                    "models": [{"model_name": "m", "upstream_model": "azure/m"}],
                    "failover": {"eu": ["us"]},
                    "keys": [{"key_id": "eu1", "api_key_env": "K", "region": "eu"}],
                }
            ]
        }
        assert region_fallbacks(config(raw)) == []


class TestRenderConfig:
    def test_merges_template_and_writes_fallbacks(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("K_EU", "sk-secret-eu-XYZ")
        monkeypatch.setenv("K_US", "sk-secret-us-XYZ")
        template = tmp_path / "template.yaml"
        template.write_text(
            yaml.safe_dump(
                {
                    "model_list": [
                        {"model_name": "manual", "litellm_params": {"model": "openai/x"}}
                    ],
                    "general_settings": {"master_key": "os.environ/MK"},
                }
            )
        )
        keypool = tmp_path / "keypool.yaml"
        keypool.write_text(yaml.safe_dump(TestRegions.RAW))
        out = tmp_path / "out.yaml"

        render_config(str(template), str(keypool), str(out))
        result = yaml.safe_load(out.read_text())

        names = [e["model_name"] for e in result["model_list"]]
        assert names[0] == "manual"  # template's own model_list preserved
        assert set(names[1:]) == {"gpt-4o", "gpt-4o-eu", "gpt-4o-us"}
        assert result["router_settings"]["fallbacks"] == [{"gpt-4o-eu": ["gpt-4o-us"]}]
        assert result["general_settings"] == {"master_key": "os.environ/MK"}
        assert "sk-secret" not in out.read_text()  # env refs only, never values

    def test_example_config_renders(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in (
            "OPENAI_API_KEY_A",
            "OPENAI_API_KEY_B",
            "ANTHROPIC_API_KEY_1",
            "ANTHROPIC_API_KEY_2",
        ):
            monkeypatch.setenv(var, "dummy")
        root = pathlib.Path(__file__).resolve().parents[2]
        out = tmp_path / "proxy_config.yaml"
        render_config(
            str(root / "config" / "proxy_config.template.yaml"),
            str(root / "config" / "keypool.yaml"),
            str(out),
        )
        result = yaml.safe_load(out.read_text())
        # 2 openai models x 2 enabled keys + 1 anthropic model x 2 keys
        assert len(result["model_list"]) == 6
        cfg = load_keypool(str(root / "config" / "keypool.yaml"))
        enabled = sum(
            len(p.models) * sum(1 for k in p.keys if k.enabled) for p in cfg.pools
        )
        assert len(result["model_list"]) == enabled
