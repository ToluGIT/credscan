"""
Non-destructive token validators for single-token providers.

Each validator calls a read-only identity endpoint to confirm whether a token is
live. These calls:
  - are READ-ONLY (identity/account lookup only, never state-changing),
  - are opt-in (only run when the user passes --verify),
  - are rate-limited,
  - send the token ONLY to its own provider, never anywhere else.

A verified-live token is close to 100% precision, which is the most persuasive
signal a secrets scanner can produce. An unverifiable token (network error, or a
provider we do not support) is reported as UNVERIFIED, never as a false negative.
"""

import logging
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Conservative shared rate limit across providers.
_MIN_INTERVAL_SECONDS = 1.0
_TIMEOUT_SECONDS = 8


class TokenValidator:
    """Validate single-token credentials against provider identity endpoints."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self._last_call_time = 0.0
        self._requests = None

    def _get_requests(self):
        if self._requests is None:
            try:
                import requests

                self._requests = requests
            except ImportError:
                raise ImportError(
                    "requests is required for --verify. Install with: pip install requests"
                )
        return self._requests

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_call_time
        if elapsed < _MIN_INTERVAL_SECONDS:
            time.sleep(_MIN_INTERVAL_SECONDS - elapsed)
        self._last_call_time = time.monotonic()

    # ── Provider detection ────────────────────────────────────────────────────

    @staticmethod
    def detect_provider(token: str) -> Optional[str]:
        """Identify which provider a token belongs to by its prefix/shape."""
        if not token:
            return None
        if token.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
            return "github"
        if token.startswith(("xoxb-", "xoxp-", "xoxa-", "xoxr-")):
            return "slack"
        if token.startswith(("sk_live_", "rk_live_", "sk_test_", "rk_test_")):
            return "stripe"
        if token.startswith("ya29."):
            return "gcp"
        # Anthropic must be checked before the generic OpenAI sk- prefix.
        if token.startswith("sk-ant-"):
            return "anthropic"
        if token.startswith(("sk-proj-", "sk-")):
            return "openai"
        if token.startswith("npm_"):
            return "npm"
        return None

    # ── Per-provider verification (each is read-only) ──────────────────────────

    def _verify_github(self, requests, token: str) -> Dict[str, Any]:
        # GET /user is read-only and returns the authenticated user.
        resp = requests.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            login = resp.json().get("login", "")
            return {"valid": True, "identity": f"github user: {login}"}
        if resp.status_code in (401, 403):
            return {
                "valid": False,
                "error": f"HTTP {resp.status_code} (invalid/revoked)",
            }
        return {"valid": None, "error": f"HTTP {resp.status_code}"}

    def _verify_slack(self, requests, token: str) -> Dict[str, Any]:
        # auth.test is the canonical read-only token check.
        resp = requests.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                return {
                    "valid": True,
                    "identity": f"slack team: {data.get('team', '')}",
                }
            return {"valid": False, "error": data.get("error", "auth failed")}
        return {"valid": None, "error": f"HTTP {resp.status_code}"}

    def _verify_stripe(self, requests, token: str) -> Dict[str, Any]:
        # GET /v1/account is read-only.
        resp = requests.get(
            "https://api.stripe.com/v1/account",
            auth=(token, ""),
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            acct = resp.json().get("id", "")
            return {"valid": True, "identity": f"stripe account: {acct}"}
        if resp.status_code == 401:
            return {"valid": False, "error": "HTTP 401 (invalid/revoked)"}
        return {"valid": None, "error": f"HTTP {resp.status_code}"}

    def _verify_gcp(self, requests, token: str) -> Dict[str, Any]:
        # OAuth2 tokeninfo is read-only and validates an access token.
        resp = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"access_token": token},
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            scope = resp.json().get("scope", "")
            return {"valid": True, "identity": f"gcp token (scope: {scope[:40]})"}
        # tokeninfo returns 400 with error_description 'invalid_token' for a
        # genuinely bad/expired token, but 400 can also mean a malformed
        # request. Only treat it as INVALID when the body confirms an invalid
        # token; otherwise it is unverifiable.
        if resp.status_code in (400, 401):
            try:
                body = resp.json()
            except Exception:
                body = {}
            desc = (
                f"{body.get('error', '')} {body.get('error_description', '')}".lower()
            )
            if resp.status_code == 401 or "invalid" in desc or "expired" in desc:
                return {
                    "valid": False,
                    "error": f"HTTP {resp.status_code} (invalid/expired)",
                }
            return {"valid": None, "error": f"HTTP {resp.status_code} (indeterminate)"}
        return {"valid": None, "error": f"HTTP {resp.status_code}"}

    def _verify_openai(self, requests, token: str) -> Dict[str, Any]:
        # GET /v1/models is read-only and lists models the key can access.
        resp = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            return {"valid": True, "identity": "openai key (active)"}
        # 401 = bad key; 403 = key cannot authenticate to the endpoint
        # (disabled/region-blocked). Both mean the key does not work here, and
        # this matches the github/anthropic handling.
        if resp.status_code in (401, 403):
            return {
                "valid": False,
                "error": f"HTTP {resp.status_code} (invalid/revoked)",
            }
        return {"valid": None, "error": f"HTTP {resp.status_code}"}

    def _verify_anthropic(self, requests, token: str) -> Dict[str, Any]:
        # GET /v1/models is read-only. Anthropic uses the x-api-key header.
        resp = requests.get(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": token, "anthropic-version": "2023-06-01"},
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            return {"valid": True, "identity": "anthropic key (active)"}
        if resp.status_code in (401, 403):
            return {
                "valid": False,
                "error": f"HTTP {resp.status_code} (invalid/revoked)",
            }
        return {"valid": None, "error": f"HTTP {resp.status_code}"}

    def _verify_npm(self, requests, token: str) -> Dict[str, Any]:
        # /-/whoami is the read-only identity endpoint for an npm token.
        resp = requests.get(
            "https://registry.npmjs.org/-/whoami",
            headers={"Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            try:
                user = resp.json().get("username", "")
            except Exception:
                user = ""
            return {"valid": True, "identity": f"npm user: {user}"}
        if resp.status_code in (401, 403):
            return {
                "valid": False,
                "error": f"HTTP {resp.status_code} (invalid/revoked)",
            }
        return {"valid": None, "error": f"HTTP {resp.status_code}"}

    @property
    def _providers(self) -> Dict[str, Callable]:
        return {
            "github": self._verify_github,
            "slack": self._verify_slack,
            "stripe": self._verify_stripe,
            "gcp": self._verify_gcp,
            "openai": self._verify_openai,
            "anthropic": self._verify_anthropic,
            "npm": self._verify_npm,
        }

    # ── Public API ──────────────────────────────────────────────────────────-

    def validate(self, token: str) -> Dict[str, Any]:
        """Validate a single token. Returns {valid: True|False|None, ...}.

        valid True  = confirmed live, valid False = confirmed invalid/revoked,
        valid None  = unverifiable (network error or unsupported provider).
        """
        provider = self.detect_provider(token)
        if provider is None:
            return {
                "valid": None,
                "provider": None,
                "error": "no supported provider prefix",
            }

        self._rate_limit()
        try:
            requests = self._get_requests()
            result = self._providers[provider](requests, token)
            result["provider"] = provider
            return result
        except Exception as e:  # network / parsing errors are unverifiable, not invalid
            logger.warning(f"{provider} verification error: {e}")
            return {"valid": None, "provider": provider, "error": f"network error: {e}"}

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attach a verification verdict to findings whose value is a known
        single-token provider secret."""
        for finding in findings:
            value = (finding.get("value", "") or "").strip().strip("'\"")
            # The value may be a full line; extract a token-looking substring.
            token = self._extract_token(value)
            if not token:
                continue
            provider = self.detect_provider(token)
            if provider is None:
                continue

            result = self.validate(token)
            if result["valid"] is True:
                finding["verification"] = f"ACTIVE: {result.get('identity', provider)}"
                finding["severity"] = "critical"
            elif result["valid"] is False:
                finding["verification"] = f"INVALID: {result.get('error', 'revoked')}"
            else:
                finding["verification"] = (
                    f"UNVERIFIED: {result.get('error', 'unknown')}"
                )
        return findings

    @staticmethod
    def _extract_token(value: str) -> Optional[str]:
        import re

        m = re.search(
            r"(ghp_[A-Za-z0-9]{30,40}|gh[ousr]_[A-Za-z0-9]{30,40}|"
            r"xox[baprs]-[A-Za-z0-9-]{10,}|"
            r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
            r"ya29\.[A-Za-z0-9_\-]+|"
            r"sk-ant-[A-Za-z0-9_\-]{20,}|"  # Anthropic (before generic sk-)
            r"sk-proj-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{20,}|"  # OpenAI
            r"npm_[A-Za-z0-9]{36})",  # npm automation/publish token
            value,
        )
        return m.group(1) if m else None
