"""
Breach-exposure correlation via the HaveIBeenPwned Pwned Passwords range API.

A finding that is *already public in a known breach* is the strongest urgency
signal a secrets scanner can give: it is not "this might be risky", it is "this
exact secret is already out there, rotate it now."

Privacy by design (k-anonymity):
  - The secret NEVER leaves the machine. We SHA-1 the value locally, then send
    ONLY the first 5 hex characters of the hash to the API. The service returns
    every hash suffix sharing that prefix (hundreds), and the match is checked
    locally. The provider learns a 5-char prefix, never the secret or its full
    hash. This is the same scheme `1Password`, `pwned` CLIs, and browsers use.
  - Opt-in (only runs when the user asks), rate-limited, read-only.

This complements live verification: verification answers "is this key active?",
breach correlation answers "is this secret already leaked?". A password can be
unverifiable yet confirmed-public, which is just as actionable.
"""

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_API = "https://api.pwnedpasswords.com/range/"
_MIN_INTERVAL_SECONDS = 1.5  # be a polite client of a free service
_TIMEOUT_SECONDS = 8

# Unambiguous password hints: a finding naming one of these is a password, so
# it is breach-correlatable even if a provider name also appears (e.g.
# "aws_db_password" is still a password). These always win.
_PASSWORD_HINTS = ("password", "passwd", "passphrase")

# Weaker hints: "secret"/"credential" are correlatable ONLY when the finding is
# not also a structured provider key. This avoids hashing e.g. a "stripe secret
# key" against a PASSWORD corpus, while still catching a bare "client_secret".
_GENERIC_HINTS = ("secret", "credential")

# Findings whose category/name marks them as a structured provider key or
# crypto material — never breach-correlated even if the name contains "secret".
_STRUCTURED_HINTS = (
    "aws",
    "gcp",
    "azure",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "google",
    "private key",
    "rsa",
    "openssh",
    "pem",
    "certificate",
    "access key id",
    "api key",
    "jwt",
    "oauth",
)


class BreachChecker:
    """Correlate finding values against the HIBP Pwned Passwords corpus."""

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
                    "requests is required for breach correlation. "
                    "Install with: pip install requests"
                )
        return self._requests

    def _rate_limit(self):
        elapsed = time.monotonic() - self._last_call_time
        if elapsed < _MIN_INTERVAL_SECONDS:
            time.sleep(_MIN_INTERVAL_SECONDS - elapsed)
        self._last_call_time = time.monotonic()

    def check(self, value: str) -> Dict[str, Any]:
        """Return breach-exposure status for a single secret value.

        Result dict:
          - exposed (bool|None): True = found in a breach, False = not found,
            None = could not check (network/empty).
          - count (int): number of times the secret appears in the corpus.
          - error (str, when exposed is None).
        """
        if not value:
            return {"exposed": None, "count": 0, "error": "empty value"}

        # SHA-1 locally; only the 5-char prefix is ever sent (k-anonymity).
        digest = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]

        self._rate_limit()
        try:
            requests = self._get_requests()
            resp = requests.get(
                _API + prefix,
                timeout=_TIMEOUT_SECONDS,
                headers={"Add-Padding": "true"},  # uniform response size
            )
            if resp.status_code != 200:
                return {
                    "exposed": None,
                    "count": 0,
                    "error": f"breach API HTTP {resp.status_code}",
                }
            # Body is lines of "SUFFIX:COUNT"; match our suffix locally.
            for line in resp.text.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and parts[0].strip() == suffix:
                    count = int(parts[1].strip() or 0)
                    if count > 0:
                        return {"exposed": True, "count": count}
                    return {"exposed": False, "count": 0}
            return {"exposed": False, "count": 0}
        except Exception as e:  # network/timeout — unknown, never a false "safe"
            logger.warning(f"breach check error: {e}")
            return {"exposed": None, "count": 0, "error": "network error"}

    @staticmethod
    def _is_correlatable(finding: Dict[str, Any]) -> bool:
        haystack = " ".join(
            str(finding.get(k, ""))
            for k in ("rule_name", "type", "variable", "pattern_category")
        ).lower()
        # An explicit password is always correlatable, even if a provider name
        # also appears (e.g. "aws_db_password" is a password, not an AWS key).
        if any(h in haystack for h in _PASSWORD_HINTS):
            return True
        # Otherwise a structured provider key / crypto material is out of scope
        # (wrong corpus) even when its name contains "secret"/"key".
        if any(h in haystack for h in _STRUCTURED_HINTS):
            return False
        # A bare "secret"/"credential" with no provider marker is correlatable.
        return any(h in haystack for h in _GENERIC_HINTS)

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attach a breach-exposure verdict to correlatable findings.

        Adds finding["breach_exposure"]:
          - "EXPOSED: seen in N known breaches"   (rotate immediately)
          - "not in known breaches"
          - "breach check skipped/unavailable"
        """
        for finding in findings:
            if not self._is_correlatable(finding):
                continue
            value = finding.get("value", "")
            if not value:
                continue
            result = self.check(value)
            if result["exposed"] is True:
                finding["breach_exposure"] = (
                    f"EXPOSED: seen in {result['count']} known breaches"
                )
                # A publicly-known secret is at least high severity.
                if finding.get("severity") in (None, "low", "medium"):
                    finding["severity"] = "high"
            elif result["exposed"] is False:
                finding["breach_exposure"] = "not in known breaches"
            else:
                finding["breach_exposure"] = "breach check unavailable"
        return findings
