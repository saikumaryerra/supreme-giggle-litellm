# Single source of truth for the LiteLLM pin (§9.1). Renovate bumps this ARG;
# scripts/sync_litellm_pin.py mirrors it into pyproject's test extra.
# Pin the bare content tag — never :latest, never -dev builds.
ARG LITELLM_VERSION=1.92.0
FROM ghcr.io/berriai/litellm:${LITELLM_VERSION}

# The base image is wolfi + a uv-managed venv at /app/.venv (no system pip),
# and litellm runs from that venv — so install litellm_ext INTO it with uv,
# not the system python, or the proxy can't import it.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY dist/litellm_ext-*.whl /tmp/
RUN uv pip install --python /app/.venv/bin/python --no-cache /tmp/litellm_ext-*.whl \
    && rm /tmp/*.whl

COPY config/proxy_config.template.yaml /app/config/proxy_config.template.yaml
COPY config/keypool.yaml               /app/config/keypool.yaml
COPY config/rbac.yaml                  /app/config/rbac.yaml
COPY docker/entrypoint.sh              /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Escape hatch for unavoidable core fixes (§9.5): patches/ is normally empty;
# CI fails the build when a patch no longer applies, forcing review on bumps.
# `patch` isn't in the wolfi runtime set, so install it only when a real patch
# is present (keeps the steady-state image lean and still fails loudly on a
# stale patch rather than a missing-tool error).
COPY patches/ /patches/
RUN set -e; \
    if ls /patches/*.patch >/dev/null 2>&1; then \
      apk add --no-cache patch; \
      litellm_dir=$(/app/.venv/bin/python -c 'import litellm,os;print(os.path.dirname(litellm.__file__))'); \
      for p in /patches/*.patch; do \
        echo "applying $p"; patch -p1 -d "$litellm_dir" < "$p"; \
      done; \
    fi

# entrypoint resolves secret refs (F7), expands keypool.yaml → model_list (F4),
# then execs litellm (§7A.3)
ENTRYPOINT ["/app/entrypoint.sh"]
