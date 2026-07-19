#!/usr/bin/env python3
"""Keep the litellm test-extra pin in pyproject.toml equal to the Dockerfile ARG.

The Dockerfile's ``ARG LITELLM_VERSION`` is the single source of truth (§9.1).
``--check`` exits non-zero on drift (CI); without it, pyproject.toml is rewritten.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "docker" / "Dockerfile"
PYPROJECT = ROOT / "pyproject.toml"


def dockerfile_version() -> str:
    m = re.search(r"^ARG LITELLM_VERSION=([\w.]+)", DOCKERFILE.read_text(), re.M)
    if not m:
        sys.exit("ARG LITELLM_VERSION not found in docker/Dockerfile")
    return m.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    version = dockerfile_version()
    text = PYPROJECT.read_text()
    new_text, n = re.subn(
        r'"litellm\[proxy\]==[\w.]+"', f'"litellm[proxy]=={version}"', text
    )
    if n == 0:
        sys.exit("litellm[proxy] pin not found in pyproject.toml")
    if text == new_text:
        print(f"pin in sync: litellm[proxy]=={version}")
        return
    if args.check:
        sys.exit(f"pin drift: Dockerfile has {version}, pyproject.toml differs")
    PYPROJECT.write_text(new_text)
    print(f"updated pyproject.toml to litellm[proxy]=={version}")


if __name__ == "__main__":
    main()
