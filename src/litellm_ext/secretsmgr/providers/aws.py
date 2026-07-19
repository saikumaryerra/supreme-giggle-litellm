"""F7: AWS provider — Secrets Manager / KMS via IRSA (§7B.3).

Ref formats: awssm://<secret-name>[#json-key], awskms://<base64-ciphertext>.
Credentials come from the pod's IRSA role (no static AWS keys); required IAM:
secretsmanager:GetSecretValue and/or kms:Decrypt only.

boto3 is imported lazily and is NOT a package dependency — it is present on
AWS-deployed images (add it to the image when F7+AWS is enabled).
"""

from __future__ import annotations

import base64
import json
from typing import Any

from litellm_ext.settings import get_settings


class AwsResolver:
    def __init__(self) -> None:
        self._region = get_settings().aws_region or None

    def _client(self, service: str) -> Any:
        import boto3

        return boto3.client(service, region_name=self._region)

    def resolve(self, ref: str) -> str:
        if ref.startswith("awssm://"):
            return self._resolve_secretsmanager(ref)
        return self._resolve_kms(ref)

    def _resolve_secretsmanager(self, ref: str) -> str:
        name, _, json_key = ref.removeprefix("awssm://").partition("#")
        response = self._client("secretsmanager").get_secret_value(SecretId=name)
        secret = response.get("SecretString")
        if secret is None:
            secret = base64.b64decode(response["SecretBinary"]).decode()
        if json_key:
            parsed = json.loads(secret)
            if json_key not in parsed:
                raise KeyError(f"json key {json_key!r} not present in secret")
            return str(parsed[json_key])
        return str(secret)

    def _resolve_kms(self, ref: str) -> str:
        ciphertext = base64.b64decode(ref.removeprefix("awskms://"))
        response = self._client("kms").decrypt(CiphertextBlob=ciphertext)
        return response["Plaintext"].decode()
