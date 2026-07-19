# Single source of truth for the LiteLLM pin (§9.1). Renovate bumps this ARG;
# scripts/sync_litellm_pin.py mirrors it into pyproject's test extra.
# Pin the bare content tag — never :latest, never -dev builds.
ARG LITELLM_VERSION=1.92.0
FROM ghcr.io/berriai/litellm:${LITELLM_VERSION}

COPY dist/litellm_ext-*.whl /tmp/
RUN pip install --no-cache-dir /tmp/litellm_ext-*.whl && rm /tmp/*.whl

COPY config/proxy_config.template.yaml /app/config/proxy_config.template.yaml
COPY config/keypool.yaml               /app/config/keypool.yaml
COPY config/rbac.yaml                  /app/config/rbac.yaml
COPY docker/entrypoint.sh              /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Escape hatch for unavoidable core fixes (§9.5): patches/ is normally empty;
# CI fails the build when a patch no longer applies, forcing review on bumps.
COPY patches/ /patches/
RUN set -e; \
    litellm_dir=$(python -c 'import litellm,os;print(os.path.dirname(litellm.__file__))'); \
    for p in /patches/*.patch; do \
      [ -e "$p" ] || continue; \
      echo "applying $p"; patch -p1 -d "$litellm_dir" < "$p"; \
    done

# entrypoint resolves secret refs (F7), expands keypool.yaml → model_list (F4),
# then execs litellm (§7A.3)
ENTRYPOINT ["/app/entrypoint.sh"]
