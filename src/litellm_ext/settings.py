"""Central configuration for litellm-ext.

Every tunable is an environment variable with prefix ``LITELLM_EXT_``,
validated once at import of the consuming module via :func:`get_settings`.
Settings objects are immutable; tests construct their own instances.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Env lists accept comma-separated strings ("a,b") or JSON ('["a","b"]');
# NoDecode defers parsing to the _split_csv validator below.
StrList = Annotated[list[str], NoDecode]


class BodyPolicy(str, Enum):
    none = "none"
    hash = "hash"
    redacted = "redacted"
    full = "full"


class PiiAction(str, Enum):
    mask = "mask"
    block = "block"
    log_only = "log_only"


class FailMode(str, Enum):
    closed = "closed"
    open = "open"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LITELLM_EXT_", frozen=True, extra="ignore"
    )

    # --- F1: JWT / SSO auth -------------------------------------------------
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwks_url: str = ""
    jwks_cache_ttl: int = 3600
    jwt_algorithms: StrList = Field(default_factory=lambda: ["RS256"])
    jwt_clock_skew: int = 60
    role_claim: str = "roles"
    team_claim: str = "groups"
    rbac_config_path: str = "/app/config/rbac.yaml"
    allow_virtual_keys: bool = True

    # --- F2: audit ----------------------------------------------------------
    audit_db_url: str = ""
    audit_log_bodies: BodyPolicy = BodyPolicy.hash
    audit_queue_size: int = 10000
    audit_retention_days: int = 365
    audit_admin_routes: bool = False

    # --- F3: PII guardrail --------------------------------------------------
    presidio_analyzer_url: str = ""
    presidio_anonymizer_url: str = ""
    pii_action: PiiAction = PiiAction.mask
    pii_entities: StrList = Field(
        default_factory=lambda: [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "IBAN_CODE",
            "IP_ADDRESS",
            "PERSON",
        ]
    )
    pii_score_threshold: float = 0.5
    pii_response_action: PiiAction = PiiAction.log_only
    guardrail_fail_mode: FailMode = FailMode.closed
    guardrail_timeout_ms: int = 1500

    # --- F5: network & surface security ------------------------------------
    ip_allowlist: StrList = Field(default_factory=list)  # CIDRs; empty = disabled
    trusted_proxies: StrList = Field(default_factory=list)  # CIDRs whose XFF is honored
    docs_filtered: bool = False
    docs_title: str = "LLM Gateway"
    docs_description: str = "Enterprise LLM gateway"
    route_lockdown: bool = False  # hard-404 management routes for non-admins

    # --- F6: SCIM -----------------------------------------------------------
    scim_enabled: bool = False
    scim_token: str = ""
    scim_team_prefix: str = ""  # only map IdP groups with this prefix (e.g. "llm-")
    litellm_api_base: str = "http://localhost:4000"
    litellm_master_key: str = Field(default="", alias="LITELLM_MASTER_KEY")

    # --- F7: secrets manager ------------------------------------------------
    vault_addr: str = ""
    vault_role: str = ""
    vault_auth_mount: str = "kubernetes"
    vault_ca_cert: str = ""  # path to CA bundle for Vault TLS
    aws_region: str = ""

    # --- F8: advanced guardrails --------------------------------------------
    injection_model: str = ""  # cheap classifier model routed via this proxy
    injection_threshold: float = 0.8
    injection_phrases_path: str = ""  # jailbreak phrase list file
    moderation_model: str = ""
    banned_keywords_path: str = ""
    blocked_users_reload_seconds: int = 60

    # --- F9: cost governance ------------------------------------------------
    budgets_config_path: str = "/app/config/budgets.yaml"
    slack_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_from: str = ""
    smtp_to: StrList = Field(default_factory=list)
    reports_bucket: str = ""  # S3-compatible bucket for chargeback reports
    repo_token: str = ""  # GitHub/GitLab token for access-request PRs
    repo_url: str = ""  # e.g. https://api.github.com/repos/org/litellm-ext

    # --- F10: virtual-key rotation ------------------------------------------
    key_max_age_days: int = 90
    key_rotation_grace_days: int = 7

    # --- F11: semantic cache ------------------------------------------------
    cache_similarity_threshold: float = 0.90
    cache_ttl: int = 3600
    cache_temperature_max: float = 0.2  # above this, responses are not cached

    # --- F12: QoS -----------------------------------------------------------
    qos_enabled: bool = False
    qos_capacity_rps: float = 50.0
    qos_max_wait_ms: int = 10000
    qos_weights: dict[str, int] = Field(
        default_factory=lambda: {"interactive": 70, "standard": 25, "batch": 5}
    )

    # --- shared infra -------------------------------------------------------
    redis_host: str = ""
    redis_port: int = 6379
    redis_password: str = ""

    @field_validator(
        "jwt_algorithms",
        "pii_entities",
        "ip_allowlist",
        "trusted_proxies",
        "smtp_to",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, v: Any) -> Any:
        """Accept comma-separated strings in env vars as well as JSON lists."""
        if isinstance(v, str):
            stripped = v.strip()
            if stripped.startswith("["):
                import json

                return json.loads(stripped)
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("jwt_algorithms")
    @classmethod
    def _forbid_weak_algs(cls, v: list[str]) -> list[str]:
        forbidden = {a for a in v if a.lower() == "none" or a.upper().startswith("HS")}
        if forbidden:
            raise ValueError(f"forbidden JWT algorithms configured: {sorted(forbidden)}")
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test helper: force re-read of environment on next get_settings()."""
    get_settings.cache_clear()
