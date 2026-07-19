"""F13: per-team data-residency filtering (§7B.9), consulted by rbac.py.

Residency beats availability by design: a team pinned to ``allowed_regions:
[eu]`` is granted only region-pinned aliases (``gpt-4o-eu``), never the bare
name that carries cross-region fallbacks — so when EU is down they get 503,
not a US call.
"""

from __future__ import annotations


def pin_models_to_regions(models: list[str], allowed_regions: list[str]) -> list[str]:
    """Rewrite a model grant list for a residency-pinned team.

    - ``*`` stays ``*`` only if no pin is set; with a pin it is dropped
      (wildcards cannot be safely region-scoped — grant aliases explicitly).
    - A model already carrying an allowed region suffix is kept as-is.
    - A model carrying a *disallowed* region suffix is dropped.
    - A bare model name becomes one alias per allowed region.
    """
    if not allowed_regions:
        return models

    known = _known_regions(allowed_regions, models)
    pinned: list[str] = []
    for model in models:
        if model == "*":
            continue
        suffix = model.rsplit("-", 1)[-1] if "-" in model else None
        if suffix in known:  # already region-qualified
            if suffix in allowed_regions:
                pinned.append(model)
            continue
        pinned.extend(f"{model}-{region}" for region in allowed_regions)
    return pinned


def _known_regions(allowed: list[str], models: list[str]) -> set[str]:
    # Regions we can recognize as suffixes: the allowed set plus common codes.
    return set(allowed) | {"eu", "us", "ap", "uk", "ca", "au", "in", "jp"}
