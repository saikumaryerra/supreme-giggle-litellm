"""F5: CIDR allowlist checks (§7B.1), called as step 0 of jwt_auth.

Client IP resolution: use the direct peer IP unless it falls inside
TRUSTED_PROXIES, in which case take the right-most non-trusted hop of
X-Forwarded-For. XFF from an untrusted peer is never honored, so spoofing
cannot bypass the allowlist.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from fastapi import Request

from litellm_ext.settings import get_settings

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=8)
def _compile(cidrs: tuple[str, ...]) -> tuple[Network, ...]:
    return tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)


def _in_any(ip: str, networks: tuple[Network, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def resolve_client_ip(request: Request) -> str:
    """Trusted-proxy-aware client IP resolution."""
    peer = request.client.host if request.client else ""
    settings = get_settings()
    trusted = _compile(tuple(settings.trusted_proxies))
    if not trusted or not _in_any(peer, trusted):
        return peer

    xff = request.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    # Walk right-to-left past trusted proxies; the first untrusted hop is the client.
    for hop in reversed(hops):
        if not _in_any(hop, trusted):
            return hop
    return peer


def check_global_allowlist(client_ip: str) -> bool:
    """True when allowed. An empty allowlist disables the check."""
    settings = get_settings()
    if not settings.ip_allowlist:
        return True
    return _in_any(client_ip, _compile(tuple(settings.ip_allowlist)))


def check_team_cidrs(client_ip: str, allowed_cidrs: list[str]) -> bool:
    """Per-role/team CIDR restriction, enforced after RBAC resolution."""
    if not allowed_cidrs:
        return True
    return _in_any(client_ip, _compile(tuple(allowed_cidrs)))


def privacy_masked(ip: str) -> str:
    """Log the /24 (or /64 for v6), not the full address (§7B.1)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))
