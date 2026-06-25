"""
Non-destructive AWS credential validator.

Uses sts:GetCallerIdentity — a read-only operation that requires no permissions
beyond valid credentials. Safe to call on any AWS key: it never modifies state.

Only activated with --validate-aws flag. Disabled by default.
"""

import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# AWS Access Key ID prefix patterns (AKIA = long-term, ASIA = temporary STS)
_LONG_TERM_PREFIX = "AKIA"
_TEMP_PREFIX = "ASIA"

# Rate limit: avoid hammering the STS endpoint
_MIN_INTERVAL_SECONDS = 1.0


class AWSCredentialValidator:
    """
    Validates AWS credentials by calling sts:GetCallerIdentity.

    This call is:
    - Read-only (no side effects, no data access)
    - Free (not billed per-call)
    - Universally allowed — even zero-permission keys can call it
    - The canonical way security tools verify key validity
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self._last_call_time: float = 0.0
        self._boto3 = None

    def _get_boto3(self):
        if self._boto3 is None:
            try:
                import boto3

                self._boto3 = boto3
            except ImportError:
                raise ImportError(
                    "boto3 is required for --validate-aws. Install with: pip install boto3"
                )
        return self._boto3

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_call_time
        if elapsed < _MIN_INTERVAL_SECONDS:
            time.sleep(_MIN_INTERVAL_SECONDS - elapsed)
        self._last_call_time = time.monotonic()

    def validate(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate an AWS key pair using sts:GetCallerIdentity.

        Returns a dict with keys:
          - valid (bool)
          - account_id (str, if valid)
          - user_arn (str, if valid)
          - user_id (str, if valid)
          - key_type (str): 'long_term' | 'temporary'
          - error (str, if invalid)
        """
        if not access_key_id or not secret_access_key:
            return {"valid": False, "error": "Missing key or secret"}

        key_type = (
            "temporary" if access_key_id.startswith(_TEMP_PREFIX) else "long_term"
        )

        self._rate_limit()

        try:
            boto3 = self._get_boto3()
            session_kwargs: Dict[str, str] = {
                "aws_access_key_id": access_key_id,
                "aws_secret_access_key": secret_access_key,
            }
            if session_token:
                session_kwargs["aws_session_token"] = session_token

            session = boto3.Session(**session_kwargs)
            sts = session.client("sts", region_name="us-east-1")
            identity = sts.get_caller_identity()

            return {
                "valid": True,
                "account_id": identity.get("Account", ""),
                "user_arn": identity.get("Arn", ""),
                "user_id": identity.get("UserId", ""),
                "key_type": key_type,
            }

        except Exception as e:
            err_str = str(e)
            # Distinguish InvalidClientTokenId (bad key) from network errors
            if "InvalidClientTokenId" in err_str or "SignatureDoesNotMatch" in err_str:
                return {
                    "valid": False,
                    "key_type": key_type,
                    "error": "Invalid or expired key",
                }
            if "ExpiredToken" in err_str:
                return {"valid": False, "key_type": key_type, "error": "Token expired"}
            # Network/timeout — don't assume invalid
            logger.warning(
                f"AWS validation network error for key {access_key_id[:8]}...: {e}"
            )
            return {"valid": None, "key_type": key_type, "error": f"Network error: {e}"}

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich findings that contain AWS Access Key IDs with live validation status.

        Pairs AKIA/ASIA keys with nearby secret keys in the same file.
        """
        import re

        # An AWS secret access key is exactly 40 chars of base64 alphabet.
        secret_shape = re.compile(r"^[A-Za-z0-9/+]{40}$")

        # Index findings to pair an access key with a secret in the same file.
        # Prefer findings whose rule name says "secret"; fall back to any
        # secret-shaped 40-char string in the same file (the secret often
        # surfaces only as an entropy/base64 finding, not a named one).
        access_keys: List[Dict[str, Any]] = []
        named_secrets: Dict[str, str] = {}  # file -> explicitly-named secret
        shaped_secrets: Dict[str, str] = {}  # file -> secret-shaped candidate

        for finding in findings:
            value = finding.get("value", "") or ""
            rule = finding.get("rule_name", "")
            path = finding.get("path", "")

            if value.startswith((_LONG_TERM_PREFIX, _TEMP_PREFIX)) and len(value) == 20:
                access_keys.append(finding)
            if "secret" in rule.lower() or "AWS Secret" in rule:
                named_secrets[path] = value
            elif secret_shape.match(value):
                shaped_secrets.setdefault(path, value)

        for finding in access_keys:
            access_key_id = finding.get("value", "")
            path = finding.get("path", "")
            secret = named_secrets.get(path) or shaped_secrets.get(path) or ""

            if not secret:
                finding["aws_validation"] = (
                    "SKIPPED: no matching secret key found in same file"
                )
                continue

            result = self.validate(access_key_id, secret)

            if result["valid"] is True:
                finding["aws_validation"] = (
                    f"ACTIVE: Account {result['account_id']}, "
                    f"ARN {result['user_arn']} [{result['key_type']}]"
                )
                finding["severity"] = "critical"
            elif result["valid"] is False:
                finding["aws_validation"] = f"INVALID: {result.get('error', 'unknown')}"
            else:
                finding["aws_validation"] = (
                    f"UNKNOWN: {result.get('error', 'network error')}"
                )

        return findings
