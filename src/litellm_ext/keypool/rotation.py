"""F4: provider-key lifecycle CLI (§7A.5).

Edits keypool.yaml safely (parse → mutate → atomic rewrite) and prints the
zero-downtime rotation checklist. In GitOps setups the resulting diff is the
audit trail for key changes.

    python -m litellm_ext.keypool.rotation drain   --keypool config/keypool.yaml --key-id openai-team-a
    python -m litellm_ext.keypool.rotation enable  --keypool config/keypool.yaml --key-id openai-team-b
    python -m litellm_ext.keypool.rotation remove  --keypool config/keypool.yaml --key-id openai-old-2025
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from typing import Any

import yaml

CHECKLIST = """\
Zero-downtime rotation checklist (§7A.5):
 1. Add the new key to the K8s Secret and a new enabled entry in keypool.yaml.
 2. Roll the Deployment (rolling update, >=2 replicas → no downtime).
 3. Drain the old key (this command sets enabled: false) → roll again.
 4. Watch keypool_requests_total{{key_id="{key_id}"}} until it stops moving.
 5. Revoke the key at the provider, then `remove` the entry here.
"""


def _load(path: str) -> dict[str, Any]:
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _atomic_write(path: str, data: dict[str, Any]) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            yaml.safe_dump(data, fh, sort_keys=False, default_flow_style=False)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _find_key(data: dict[str, Any], key_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    for pool in data.get("pools", []):
        for key in pool.get("keys", []):
            if key.get("key_id") == key_id:
                return key, pool.get("keys", [])
    raise SystemExit(f"key_id {key_id!r} not found in keypool")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["drain", "enable", "remove"])
    parser.add_argument("--keypool", required=True)
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args(argv)

    data = _load(args.keypool)
    key, siblings = _find_key(data, args.key_id)

    if args.action == "drain":
        key["enabled"] = False
    elif args.action == "enable":
        key["enabled"] = True
    elif args.action == "remove":
        if key.get("enabled"):
            raise SystemExit("refusing to remove an enabled key — drain it first")
        siblings.remove(key)

    _atomic_write(args.keypool, data)
    print(f"{args.action}: {args.key_id} → {args.keypool}")
    print(CHECKLIST.format(key_id=args.key_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
