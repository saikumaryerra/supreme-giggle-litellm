# litellm-ext — Self-Built Enterprise Layer for LiteLLM Proxy

An independent Python package that adds enterprise-grade capabilities to the
open-source [LiteLLM proxy](https://docs.litellm.ai/) **without forking or
modifying LiteLLM source code**. Everything attaches via LiteLLM's documented
OSS extension points.

Pinned LiteLLM version: **1.92.0** (single source of truth: `ARG LITELLM_VERSION`
in `docker/Dockerfile`; the test extra in `pyproject.toml` is CI-substituted to
match).

## Features

| Feature | What | LiteLLM extension point |
|---------|------|-------------------------|
| F1 | SSO / JWT authentication & RBAC | `general_settings.custom_auth` |
| F2 | Audit logging & compliance trail | `CustomLogger` callback |
| F3 | Guardrails & PII masking (Presidio) | `CustomGuardrail` hooks |
| F4 | Multi-key provider pools (load balancing, rotation, per-key telemetry) | native router `model_list` + config generator |
| F5 | Network & surface security (IP allowlists, docs filtering) | custom_auth pre-checks + ASGI docs filter |
| F6 | SCIM 2.0 provisioning | sidecar FastAPI app → LiteLLM management APIs |
| F7 | Secrets-manager integration (Vault / AWS) | entrypoint-time secret resolver |
| F8 | Advanced guardrails (secrets scanning, prompt injection, moderation, block/ban lists) | `CustomGuardrail` hooks |
| F9 | Cost governance (budget alerts/enforcement, chargeback, access requests) | CronJobs over audit DB + Redis enforcement sets |
| F10 | Automated virtual-key rotation | CronJob against `/key/*` APIs |
| F11 | Semantic caching | native LiteLLM `redis-semantic` cache (custom hook fallback) |
| F12 | Priority tiers / QoS | RBAC tier limits + Redis fair queue pre_call hook |
| F13 | Multi-region failover & data residency | keypool regions + router fallbacks + RBAC region filter |

## Design principles

- **Zero-fork**: LiteLLM is a pinned pip/Docker dependency, never a submodule or vendored copy.
- **Fail-closed** for auth and guardrails; **fail-open** for audit (an audit DB
  outage must not take down inference — events buffer, spill to stdout JSON, and alert).
- Everything configurable via env vars (`LITELLM_EXT_*`) + one YAML each for
  key pools, RBAC, and budgets (12-factor, K8s-friendly).
- **Contract-tested** against LiteLLM's hook interfaces so upstream upgrades
  are safe and mechanical.
- No code from LiteLLM's `enterprise/` directory or `litellm_enterprise`
  package is imported, copied, or depended on (CI-enforced).

## Layout

```
src/litellm_ext/     the package (auth/, audit/, guardrails/, keypool/, netsec/,
                     scim/, secretsmgr/, costgov/, keyrotation/, cache/, qos/, regions/)
config/              proxy_config.template.yaml, keypool.yaml, rbac.yaml, budgets.yaml
docker/              Dockerfile (FROM ghcr.io/berriai/litellm:<pin>), entrypoint.sh
deploy/k8s/          Deployments, Services, Ingress, NetworkPolicies, HPA, PDB, CronJobs
migrations/          Alembic migrations for the audit database
tests/               unit/ · contract/ · integration/ (docker-compose e2e)
```

## Quick start (development)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test,dev]'
pytest tests/unit tests/contract      # contract tests run against pinned litellm
ruff check src tests && mypy
```

Generate the proxy config from a key pool definition:

```bash
python -m litellm_ext.keypool.generator \
  --template config/proxy_config.template.yaml \
  --keypool  config/keypool.yaml \
  --out      /tmp/proxy_config.yaml
```

Boot the full dev stack (proxy + Postgres + Redis + Presidio + mock IdP + mock provider):

```bash
docker compose -f tests/integration/docker-compose.test.yaml up --build
```

## Request lifecycle

```
ingress → user_api_key_auth (F1/F5: IP check, JWT verify, RBAC, deactivation/budget sets)
        → pre_call guardrails (F3 PII mask/block, F8 secrets/injection/lists, F12 QoS)
        → router (F4 key pools, F13 region fallbacks)
        → provider
        → post_call guardrails (F3/F8 response scan)
        → response
        → async audit callback (F2) + per-key telemetry (F4)
```

## Upgrading LiteLLM

Renovate opens a weekly PR bumping `LITELLM_VERSION`; `upgrade.yaml` runs the
full contract + integration suite against the new image. Contract tests
(`tests/contract/`) assert every interface this package touches, so a breaking
upstream change fails the PR — not production. See `scripts/upgrade_check.sh`.
