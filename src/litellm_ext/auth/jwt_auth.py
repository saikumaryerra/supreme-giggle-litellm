"""F1 entrypoint: LiteLLM custom_auth (§5.2). MUST raise on failure (fail closed).

Registered in proxy config as:

    general_settings:
      custom_auth: litellm_ext.auth.jwt_auth.user_api_key_auth
      custom_auth_run_common_checks: true

Algorithm (spec §5.2, extended by F5/F6/F9/F12/F13):
  0. IP allowlist (F5) — before any token work.
  1. Token classification: JWT / sk- passthrough / 401.
  2. Unverified header parse for kid+alg; reject alg outside allowlist.
  3. JWKS key lookup (cached, one refetch on unknown kid).
  4. Verify signature, iss, aud, exp, nbf with clock skew.
  5. Extract claims (sub, email, roles, team).
  6. RBAC resolve; 6.4 per-team CIDR check (F5); 6.5 deactivation set (F6);
     6.6 budget exhaustion / downgrade sets (F9).
  7. Return UserAPIKeyAuth carrying models/limits/routes/tier metadata.
  8. Failures raise HTTPException 401/403 (or 429 for exhausted budgets) and
     emit auth.denied audit events with a reason code — never the token.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import jwt as pyjwt
from fastapi import HTTPException, Request

from litellm_ext.audit import emit_event
from litellm_ext.auth.claims import ClaimError, Claims, extract_claims
from litellm_ext.auth.jwks import JwksError, get_jwks_cache
from litellm_ext.auth.rbac import RbacDenied, ResolvedPermissions, get_engine
from litellm_ext.metrics import ext_auth_denied_total, ext_auth_success_total
from litellm_ext.netsec.ip_allowlist import (
    check_global_allowlist,
    check_team_cidrs,
    privacy_masked,
    resolve_client_ip,
)
from litellm_ext.redis_client import (
    BLOCKED_USERS_SET,
    BUDGET_EXHAUSTED_SET,
    DEACTIVATED_USERS_SET,
    RedisUnavailable,
    get_downgrade_models,
    set_contains,
    set_contains_strict,
)
from litellm_ext.regions.residency import pin_models_to_regions
from litellm_ext.settings import get_settings


def hash_token(raw: str) -> str:
    """Stable hash — the raw JWT is never stored or logged."""
    return "jwt-" + hashlib.sha256(raw.encode()).hexdigest()


def looks_like_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def _deny(
    status: int, reason: str, detail: str, client_ip: str = "", user_id: str = "",
    headers: dict[str, str] | None = None,
) -> HTTPException:
    ext_auth_denied_total.labels(reason=reason).inc()
    emit_event(
        "auth.denied",
        status="blocked",
        error_class=reason,
        http_status=status,
        user_id=user_id or None,
        client_ip=privacy_masked(client_ip) if client_ip else None,
    )
    return HTTPException(status_code=status, detail={"error": detail}, headers=headers)


async def user_api_key_auth(request: Request, api_key: str) -> Any:
    """LiteLLM custom_auth entrypoint. Raises on failure (fail closed)."""
    from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth

    settings = get_settings()

    # Step 0 (F5): IP allowlist before any token work.
    client_ip = resolve_client_ip(request)
    if not check_global_allowlist(client_ip):
        raise _deny(403, "ip_blocked", "source address not permitted", client_ip)

    # Step 1: token classification.
    token = (api_key or "").removeprefix("Bearer ").strip()
    if not token:
        raise _deny(401, "missing_token", "authentication required", client_ip)
    if not looks_like_jwt(token):
        if settings.allow_virtual_keys and token.startswith("sk-"):
            from litellm_ext.auth.passthrough import default_virtual_key_auth

            return await default_virtual_key_auth(request, token)
        raise _deny(401, "malformed_token", "invalid credentials", client_ip)

    # Step 2: unverified header parse; enforce algorithm allowlist.
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError:
        raise _deny(401, "bad_header", "invalid credentials", client_ip) from None
    alg = header.get("alg")
    if alg not in settings.jwt_algorithms:
        raise _deny(401, "alg_not_allowed", "invalid credentials", client_ip)
    kid = header.get("kid")
    if not kid:
        raise _deny(401, "missing_kid", "invalid credentials", client_ip)

    # Step 3: key lookup (cached JWKS; single refetch handles rotation).
    try:
        key = await get_jwks_cache().get_key(kid)
    except JwksError:
        raise _deny(401, "unknown_kid", "invalid credentials", client_ip) from None

    # Step 4: full verification.
    try:
        payload = pyjwt.decode(
            token,
            key=key,
            algorithms=settings.jwt_algorithms,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            leeway=settings.jwt_clock_skew,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except pyjwt.ExpiredSignatureError:
        raise _deny(401, "token_expired", "token expired", client_ip) from None
    except pyjwt.PyJWTError:
        raise _deny(401, "verification_failed", "invalid credentials", client_ip) from None

    # Step 5: claims.
    try:
        claims: Claims = extract_claims(payload)
    except ClaimError:
        raise _deny(401, "missing_claims", "invalid credentials", client_ip) from None

    # Step 6: RBAC resolve.
    try:
        resolved: ResolvedPermissions = get_engine().resolve(claims.roles, claims.team)
    except RbacDenied:
        raise _deny(
            403, "role_unmapped", "no access mapping for your roles",
            client_ip, claims.sub,
        ) from None

    # Step 6.4 (F5): per-role/team network restriction — valid JWT, wrong
    # network. Role and team CIDRs are an INTERSECTION: the IP must satisfy
    # both non-empty sets, so a permissive team can't widen a restrictive role.
    if not check_team_cidrs(client_ip, resolved.role_cidrs) or not check_team_cidrs(
        client_ip, resolved.team_cidrs
    ):
        raise _deny(403, "ip_blocked_team", "source address not permitted", client_ip, claims.sub)

    # Step 6.5 (F6): SCIM deactivation must not wait for token expiry. This is
    # a revocation check — fail closed if a configured Redis is unreachable.
    try:
        revoked = await set_contains_strict(
            DEACTIVATED_USERS_SET, claims.sub
        ) or await set_contains_strict(BLOCKED_USERS_SET, claims.sub)
    except RedisUnavailable:
        if settings.revocation_fail_closed:
            raise _deny(
                403, "revocation_unavailable", "user_check_unavailable",
                client_ip, claims.sub,
            ) from None
        revoked = False
    if revoked:
        raise _deny(403, "user_deactivated", "user_deactivated", client_ip, claims.sub)

    # Step 6.6 (F9): budget enforcement / downgrade.
    models = resolved.models
    if claims.team:
        if await set_contains(BUDGET_EXHAUSTED_SET, claims.team):
            raise _deny(
                429, "budget_exceeded", "budget_exceeded", client_ip, claims.sub,
                headers={"Retry-After": str(_seconds_to_next_month())},
            )
        downgrade = await get_downgrade_models(claims.team)
        if downgrade is not None:
            # Intersect only — never grant a model the role didn't already have.
            # Re-apply residency pinning so a downgraded EU-pinned team can't be
            # handed un-suffixed names that reach cross-region fallbacks (F13).
            allowed_downgrade = downgrade
            if resolved.allowed_regions:
                allowed_downgrade = pin_models_to_regions(
                    downgrade, resolved.allowed_regions
                )
            models = [m for m in models if m in allowed_downgrade]

    # Step 7: hand LiteLLM the enforcement surface. A typo'd litellm_role in
    # rbac.yaml is a config error → deny cleanly (fail closed), not a 500.
    try:
        litellm_role = LitellmUserRoles(resolved.litellm_role)
    except ValueError:
        raise _deny(
            403, "role_config_error", "role configuration error",
            client_ip, claims.sub,
        ) from None
    ext_auth_success_total.labels(role=resolved.matched_role).inc()
    return UserAPIKeyAuth(
        api_key=hash_token(token),
        user_id=claims.sub,
        user_email=claims.email,
        user_role=litellm_role,
        team_id=claims.team,
        models=models,
        tpm_limit=resolved.tpm_limit,
        rpm_limit=resolved.rpm_limit,
        max_budget=resolved.max_budget,
        allowed_routes=resolved.allowed_routes,
        expires=datetime.fromtimestamp(claims.exp, tz=UTC),
        metadata={
            "auth_method": "jwt",
            "idp_roles": claims.roles,
            "priority": resolved.priority,  # F12 tier
            **(
                {"allowed_regions": resolved.allowed_regions}
                if resolved.allowed_regions
                else {}
            ),
        },
    )


def _seconds_to_next_month() -> int:
    now = datetime.now(tz=UTC)
    year, month = (now.year + 1, 1) if now.month == 12 else (now.year, now.month + 1)
    return max(0, int((datetime(year, month, 1, tzinfo=UTC) - now).total_seconds()))
