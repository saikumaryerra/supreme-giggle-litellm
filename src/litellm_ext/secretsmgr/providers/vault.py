"""F7: Vault provider — Kubernetes auth method + KV v2 reads (§7B.3).

Ref format: vault://<mount>/<path>#<field>
The service-account JWT authenticates against LITELLM_EXT_VAULT_ROLE; the
token is used only for the resolve window and never persisted.
"""

from __future__ import annotations

import httpx

from litellm_ext.settings import get_settings

SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class VaultResolver:
    def __init__(self) -> None:
        settings = get_settings()
        self._addr = settings.vault_addr.rstrip("/")
        self._role = settings.vault_role
        self._auth_mount = settings.vault_auth_mount
        self._verify: bool | str = settings.vault_ca_cert or True

    def resolve(self, ref: str) -> str:
        mount_path, _, field = ref.removeprefix("vault://").partition("#")
        mount, _, path = mount_path.partition("/")
        if not (mount and path and field):
            raise ValueError("vault ref must be vault://<mount>/<path>#<field>")
        token = self._login()
        with httpx.Client(timeout=10.0, verify=self._verify) as client:
            resp = client.get(
                f"{self._addr}/v1/{mount}/data/{path}",
                headers={"X-Vault-Token": token},
            )
            resp.raise_for_status()
            data = resp.json()["data"]["data"]
        if field not in data:
            raise KeyError(f"field {field!r} not present at vault path")
        return str(data[field])

    def _login(self) -> str:
        with open(SA_TOKEN_PATH) as fh:
            sa_jwt = fh.read().strip()
        with httpx.Client(timeout=10.0, verify=self._verify) as client:
            resp = client.post(
                f"{self._addr}/v1/auth/{self._auth_mount}/login",
                json={"jwt": sa_jwt, "role": self._role},
            )
            resp.raise_for_status()
            return str(resp.json()["auth"]["client_token"])
