"""F4/F13: expand keypool.yaml into LiteLLM model_list deployments.

Invoked from docker/entrypoint.sh before the proxy starts:

    python -m litellm_ext.keypool.generator \
        --template /app/config/proxy_config.template.yaml \
        --keypool  /app/config/keypool.yaml \
        --out      /app/config/proxy_config.yaml

Rules (§7A.3):
- one model_list entry per pool × model × enabled key;
- api_key is an ``os.environ/VAR`` reference — the secret is never written to disk;
- model_info.id = "<model_name>::<key_id>" (stable deployment id) and
  model_info.key_id feeds per-key telemetry;
- deterministic (sorted) output so config diffs are reviewable;
- the template's own model_list (if any) is preserved and merged.

F13 (§7B.9): keys carrying ``region`` produce an additional region-suffixed
alias (e.g. gpt-4o-eu) per deployment, and pool ``failover: {eu: [us]}``
emits router fallbacks between region aliases. Residency-pinned teams are
granted only the region alias via RBAC; the cross-region fallback list is
attached only to the *bare* model name, so pinned aliases never fail over.
"""

from __future__ import annotations

import argparse
import copy
import os
import sys
from typing import Any

import yaml

from litellm_ext.keypool.schema import KeypoolConfig, load_keypool


def _deployment(
    model_name: str, upstream_model: str, key: Any, provider: str
) -> dict[str, Any]:
    litellm_params: dict[str, Any] = {
        "model": upstream_model,
        "api_key": f"os.environ/{key.api_key_env}",
        "weight": key.weight,
    }
    if key.tpm is not None:
        litellm_params["tpm"] = key.tpm
    if key.rpm is not None:
        litellm_params["rpm"] = key.rpm
    if key.api_base:
        litellm_params["api_base"] = key.api_base
    return {
        "model_name": model_name,
        "litellm_params": litellm_params,
        "model_info": {
            "id": f"{model_name}::{key.key_id}",
            "key_id": key.key_id,
            "provider": provider,
            **({"region": key.region} if key.region else {}),
        },
    }


def expand_model_list(config: KeypoolConfig) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for pool in config.pools:
        for model in pool.models:
            for key in pool.keys:
                if not key.enabled:
                    continue
                entries.append(
                    _deployment(model.model_name, model.upstream_model, key, pool.provider)
                )
                if key.region:
                    entries.append(
                        _deployment(
                            f"{model.model_name}-{key.region}",
                            model.upstream_model,
                            key,
                            pool.provider,
                        )
                    )
    entries.sort(key=lambda e: (e["model_name"], e["model_info"]["id"]))
    return entries


def region_fallbacks(config: KeypoolConfig) -> list[dict[str, list[str]]]:
    """Router fallbacks for cross-region failover (F13).

    For pool.failover {eu: [us]} and model gpt-4o (with keys in both regions):
    ``{"gpt-4o-eu": ["gpt-4o-us"]}``. Only emitted when both region aliases
    exist. Residency-pinned aliases keep exactly these entries out of *their*
    alias by RBAC granting only the pinned alias — the fallback entry maps the
    source region alias, so a team allowed only ``gpt-4o-eu`` still hard-fails
    when EU is down unless it is also granted the bare name.
    """
    fallbacks: list[dict[str, list[str]]] = []
    for pool in config.pools:
        if not pool.failover:
            continue
        regions_present = {k.region for k in pool.keys if k.enabled and k.region}
        for model in pool.models:
            for src, targets in sorted(pool.failover.items()):
                if src not in regions_present:
                    continue
                valid_targets = [
                    f"{model.model_name}-{t}" for t in targets if t in regions_present
                ]
                if valid_targets:
                    fallbacks.append({f"{model.model_name}-{src}": valid_targets})
    return fallbacks


def render_config(template_path: str, keypool_path: str, out_path: str) -> None:
    """Expand keypool.yaml into model_list entries merged into the template."""
    config = load_keypool(keypool_path)
    config.validate_env()

    with open(template_path) as fh:
        template: dict[str, Any] = yaml.safe_load(fh) or {}

    merged = copy.deepcopy(template)
    existing: list[dict[str, Any]] = merged.get("model_list") or []
    merged["model_list"] = existing + expand_model_list(config)

    fallbacks = region_fallbacks(config)
    if fallbacks:
        router_settings = merged.setdefault("router_settings", {})
        router_settings["fallbacks"] = (router_settings.get("fallbacks") or []) + fallbacks

    with open(out_path, "w") as fh:
        yaml.safe_dump(merged, fh, sort_keys=False, default_flow_style=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", required=True)
    parser.add_argument("--keypool", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        render_config(args.template, args.keypool, args.out)
    except (RuntimeError, ValueError) as exc:
        print(f"keypool generator failed: {exc}", file=sys.stderr)
        return 1
    count = len(expand_model_list(load_keypool(args.keypool)))
    print(f"wrote {args.out} ({count} deployments)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
