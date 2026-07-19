#!/usr/bin/env bash
set -euo pipefail

# Step 0 (F7): resolve vault:// awssm:// awskms:// env refs in-process.
# Nothing is written to disk; the child litellm process inherits resolved env.
# Capture separately so a resolver failure aborts startup — `eval "$(...)"`
# would discard the non-zero exit and boot with unresolved vault:// literals.
if ! RESOLVED_EXPORTS="$(python -m litellm_ext.secretsmgr.resolver --export)"; then
  echo "FATAL: secret resolution failed; refusing to start" >&2
  exit 1
fi
eval "$RESOLVED_EXPORTS"

# Step 1 (F4): expand key pools into model_list. Fails fast (naming the env
# var, never the value) when a referenced api_key_env is missing.
python -m litellm_ext.keypool.generator \
  --template /app/config/proxy_config.template.yaml \
  --keypool  /app/config/keypool.yaml \
  --out      /app/config/proxy_config.yaml

exec litellm --config /app/config/proxy_config.yaml --port 4000
