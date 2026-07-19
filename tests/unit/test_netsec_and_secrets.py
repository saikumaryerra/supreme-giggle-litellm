"""F5 (§7B.1) and F7 (§7B.3) unit tests."""

from __future__ import annotations

import logging

import pytest
from starlette.requests import Request

from litellm_ext.netsec.docs_filter import filter_openapi, is_management_route
from litellm_ext.netsec.ip_allowlist import (
    check_global_allowlist,
    check_team_cidrs,
    privacy_masked,
    resolve_client_ip,
)
from litellm_ext.secretsmgr import resolver
from litellm_ext.settings import reset_settings_cache


def make_request(client_ip: str, xff: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": headers,
            "query_string": b"",
            "client": (client_ip, 40000),
        }
    )


class TestClientIpResolution:
    def test_direct_peer_when_no_trusted_proxies(self) -> None:
        assert resolve_client_ip(make_request("203.0.113.9", xff="10.0.0.1")) == "203.0.113.9"

    def test_xff_honored_only_from_trusted_proxy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_TRUSTED_PROXIES", "192.168.0.0/16")
        reset_settings_cache()
        request = make_request("192.168.1.1", xff="203.0.113.9, 192.168.1.5")
        assert resolve_client_ip(request) == "203.0.113.9"

    def test_rightmost_untrusted_hop_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_EXT_TRUSTED_PROXIES", "192.168.0.0/16")
        reset_settings_cache()
        # Client spoofs an extra hop on the left; right-most untrusted is real.
        request = make_request("192.168.1.1", xff="1.1.1.1, 203.0.113.9")
        assert resolve_client_ip(request) == "203.0.113.9"


class TestAllowlist:
    def test_empty_allowlist_disables_check(self) -> None:
        assert check_global_allowlist("203.0.113.9") is True

    def test_cidr_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_EXT_IP_ALLOWLIST", "10.0.0.0/8,192.168.0.0/16")
        reset_settings_cache()
        assert check_global_allowlist("10.1.2.3") is True
        assert check_global_allowlist("203.0.113.9") is False

    def test_team_cidrs(self) -> None:
        assert check_team_cidrs("10.20.1.1", ["10.20.0.0/16"]) is True
        assert check_team_cidrs("10.30.1.1", ["10.20.0.0/16"]) is False
        assert check_team_cidrs("anything-invalid", []) is True

    def test_privacy_mask_logs_slash24(self) -> None:
        assert privacy_masked("203.0.113.9") == "203.0.113.0/24"


class TestDocsFilter:
    SPEC = {
        "info": {"title": "LiteLLM", "description": "upstream"},
        "paths": {
            "/chat/completions": {"post": {}},
            "/v1/models": {"get": {}},
            "/key/generate": {"post": {}},
            "/team/new": {"post": {}},
            "/health/readiness": {"get": {}},
        },
    }

    def test_only_public_paths_survive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_EXT_DOCS_TITLE", "Acme LLM Gateway")
        reset_settings_cache()
        filtered = filter_openapi(self.SPEC)
        assert set(filtered["paths"]) == {
            "/chat/completions",
            "/v1/models",
            "/health/readiness",
        }
        assert filtered["info"]["title"] == "Acme LLM Gateway"

    def test_management_route_detection(self) -> None:
        assert is_management_route("/key/generate") is True
        assert is_management_route("/v1/team/new") is True
        assert is_management_route("/chat/completions") is False


class TestSecretRefs:
    def test_find_refs(self) -> None:
        env = {
            "PLAIN": "value",
            "V": "vault://kv/llm/openai#api_key",
            "S": "awssm://prod/keys#openai",
            "K": "awskms://Zm9v",
        }
        assert set(resolver.find_refs(env)) == {"V", "S", "K"}

    def test_vault_ref_without_addr_fails_fast(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("LITELLM_EXT_VAULT_ADDR", raising=False)
        with pytest.raises(resolver.SecretResolutionError, match="VAULT_ADDR"):
            resolver.resolve_all({"V": "vault://kv/path#field"})

    def test_failure_names_ref_never_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_EXT_VAULT_ADDR", "https://vault.test")
        reset_settings_cache()

        def boom(ref: str) -> str:
            raise ConnectionError("secret-value-would-be-here")

        monkeypatch.setattr(resolver, "resolve_ref", boom)
        with pytest.raises(resolver.SecretResolutionError) as exc:
            resolver.resolve_all({"OPENAI_KEY": "vault://kv/llm#key"})
        assert "OPENAI_KEY" in str(exc.value)
        assert "vault://kv/llm" in str(exc.value)
        assert "secret-value" not in str(exc.value)

    def test_resolved_values_scrubbed_from_logs(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        filt = resolver.RedactionFilter(["sk-supersecret123"])
        caplog.handler.addFilter(filt)
        try:
            with caplog.at_level(logging.INFO):
                logging.getLogger("any.module").info(
                    "connecting with key sk-supersecret123 now"
                )
            assert "sk-supersecret123" not in caplog.text
            assert "***REDACTED***" in caplog.text
        finally:
            caplog.handler.removeFilter(filt)

    def test_redaction_scrubs_traceback(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        filt = resolver.RedactionFilter(["sk-tracebacksecret"])
        caplog.handler.addFilter(filt)
        try:
            with caplog.at_level(logging.ERROR):
                try:
                    raise ValueError("boom sk-tracebacksecret in message")
                except ValueError:
                    logging.getLogger("x").exception("failed")
            assert "sk-tracebacksecret" not in caplog.text
        finally:
            caplog.handler.removeFilter(filt)

    def test_export_mode_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(resolver, "resolve_ref", lambda ref: "resolved'val")
        monkeypatch.setenv("MY_SECRET", "awssm://name#key")
        assert resolver.main(["--export"]) == 0
        out = capsys.readouterr().out
        assert out.startswith("export MY_SECRET=")
        assert "resolved" in out  # shell-quoted

    def test_no_refs_is_noop(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert resolver.main(["--export"]) == 0
