"""F7: entrypoint-time secret resolution (§7B.3).

Scans all env vars; values matching ``vault://<mount>/<path>#<field>``,
``awssm://<secret-name>[#json-key]`` or ``awskms://<base64-ciphertext>`` are
resolved and re-exported. Nothing is written to disk; the child litellm
process inherits the resolved environment via:

    eval "$(python -m litellm_ext.secretsmgr.resolver --export)"

Rules: fail fast on any unresolved ref, naming the REF (never a value);
refuse to start if a vault:// ref exists but VAULT_ADDR is unset; resolved
values register a log-redaction filter so they never appear in log lines.
Break-glass: plain env vars pass through untouched.
"""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import sys

REF_SCHEMES = ("vault://", "awssm://", "awskms://")


class SecretResolutionError(Exception):
    pass


class RedactionFilter(logging.Filter):
    """Scrub resolved secret values from every log record."""

    def __init__(self, values: list[str]) -> None:
        super().__init__()
        self._values = [v for v in values if len(v) >= 4]

    def _scrub(self, text: str) -> str:
        for value in self._values:
            if value in text:
                text = text.replace(value, "***REDACTED***")
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if any(v in message for v in self._values):
            record.msg = self._scrub(message)
            record.args = ()
        # Also scrub exception tracebacks, where a secret can surface via an
        # httpx error repr, KeyError(value), or a formatted stack.
        if record.exc_info:
            import logging as _logging

            record.exc_text = self._scrub(
                _logging.Formatter().formatException(record.exc_info)
            )
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self._scrub(record.exc_text)
        return True


def find_refs(environ: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in environ.items()
        if isinstance(value, str) and value.startswith(REF_SCHEMES)
    }


def resolve_ref(ref: str) -> str:
    if ref.startswith("vault://"):
        from litellm_ext.secretsmgr.providers.vault import VaultResolver

        return VaultResolver().resolve(ref)
    if ref.startswith(("awssm://", "awskms://")):
        from litellm_ext.secretsmgr.providers.aws import AwsResolver

        return AwsResolver().resolve(ref)
    raise SecretResolutionError(f"unsupported secret ref scheme: {ref.split('://')[0]}")


def resolve_all(environ: dict[str, str]) -> dict[str, str]:
    """Resolve every ref; raise naming the failing ref (never a value)."""
    refs = find_refs(environ)
    if any(v.startswith("vault://") for v in refs.values()) and not os.environ.get(
        "LITELLM_EXT_VAULT_ADDR"
    ):
        raise SecretResolutionError(
            "vault:// refs present but LITELLM_EXT_VAULT_ADDR is unset"
        )
    resolved: dict[str, str] = {}
    for name, ref in sorted(refs.items()):
        try:
            resolved[name] = resolve_ref(ref)
        except SecretResolutionError:
            raise
        except Exception as exc:  # noqa: BLE001 — wrap with the ref name only
            raise SecretResolutionError(
                f"failed to resolve {name}={ref.split('#')[0]}: {type(exc).__name__}"
            ) from exc
    return resolved


def install_redaction(values: list[str]) -> None:
    # Filters on a logger do not apply to propagated records, so the scrubber
    # must sit on every handler that could emit a line.
    filt = RedactionFilter(values)
    root = logging.getLogger()
    root.addFilter(filt)
    for handler in root.handlers:
        handler.addFilter(filt)
    for handler in logging.getLogger("litellm_ext.audit").handlers:
        handler.addFilter(filt)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--export",
        action="store_true",
        help="print `export NAME=value` lines for shell eval",
    )
    args = parser.parse_args(argv)
    try:
        resolved = resolve_all(dict(os.environ))
    except SecretResolutionError as exc:
        print(f"secret resolution failed: {exc}", file=sys.stderr)
        return 1
    if args.export:
        for name, value in resolved.items():
            print(f"export {name}={shlex.quote(value)}")
    else:
        os.environ.update(resolved)
        install_redaction(list(resolved.values()))
    print(f"resolved {len(resolved)} secret ref(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
