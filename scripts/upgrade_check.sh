#!/usr/bin/env bash
# §9: run the contract + integration suites against a candidate LiteLLM tag.
#   scripts/upgrade_check.sh 1.93.0
set -euo pipefail

VERSION="${1:?usage: upgrade_check.sh <litellm-version>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Bumping pin to litellm ${VERSION}"
sed -i.bak "s/^ARG LITELLM_VERSION=.*/ARG LITELLM_VERSION=${VERSION}/" docker/Dockerfile
python scripts/sync_litellm_pin.py

echo "==> Contract suite against litellm ${VERSION}"
pip install -e '.[test]' --quiet
pytest tests/contract -m contract --tb=long

echo "==> Integration suite against the bumped image"
python -m build --wheel --quiet
docker compose -f tests/integration/docker-compose.test.yaml up -d --build
trap 'docker compose -f tests/integration/docker-compose.test.yaml down -v' EXIT
pytest tests/integration -m integration --tb=short

echo "==> ${VERSION}: contract + integration green. Review the upstream"
echo "    changelog for auth/hook/guardrail/config changes (§9.7), then merge."
