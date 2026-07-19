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

    # Residency is a security control, so ambiguity resolves toward denying,
    # never leaking: a model whose suffix looks like a *disallowed* region is
    # dropped (over-restriction is a visible config bug; keeping a cross-region
    # alias would be a silent breach). Caveat: a legitimate model whose name
    # coincidentally ends in a region token (`-in`, `-ca`) is treated as a
    # region alias — use a non-colliding naming convention for such models, or
    # pass the deployment's real region set once it's threaded through here.
    known = set(allowed_regions) | KNOWN_REGION_CODES
    allowed = set(allowed_regions)
    pinned: list[str] = []
    for model in models:
        if model == "*":
            continue
        suffix = model.rsplit("-", 1)[-1] if "-" in model else None
        if suffix in known:  # already region-qualified
            if suffix in allowed:
                pinned.append(model)
            continue  # disallowed region → dropped (no access)
        pinned.extend(f"{model}-{region}" for region in allowed_regions)
    return pinned


KNOWN_REGION_CODES = {"eu", "us", "ap", "uk", "ca", "au", "in", "jp"}
