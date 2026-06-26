"""Tests for breach-exposure correlation (HIBP k-anonymity).

All network calls are mocked: tests never contact HIBP. They verify the
k-anonymity contract (only a 5-char hash prefix leaves; the secret never
does), verdict mapping, and that correlatable findings are enriched.
"""

import hashlib
from unittest.mock import Mock, patch

import pytest

from credscan.validators.breach_checker import BreachChecker


@pytest.fixture
def checker():
    c = BreachChecker({})
    c._rate_limit = lambda: None  # no sleeping in tests
    return c


def _range_response(value, count):
    """Build a mocked HIBP range response that contains value's suffix."""
    digest = hashlib.sha1(value.encode()).hexdigest().upper()
    suffix = digest[5:]
    body = f"{suffix}:{count}\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9"
    return Mock(status_code=200, text=body)


class TestKAnonymity:
    def test_only_prefix_is_sent_never_the_secret(self, checker):
        secret = "hunter2-very-secret-value"
        digest = hashlib.sha1(secret.encode()).hexdigest().upper()
        sent_urls = []

        def fake_get(url, **kwargs):
            sent_urls.append(url)
            return Mock(status_code=200, text="ABC:1")

        with patch.object(checker, "_get_requests", return_value=Mock(get=fake_get)):
            checker.check(secret)

        assert len(sent_urls) == 1
        url = sent_urls[0]
        # Only the 5-char prefix is in the URL.
        assert url.endswith(digest[:5])
        # The secret and its full hash never appear in the request.
        assert secret not in url
        assert digest not in url
        assert digest[5:] not in url  # not even the suffix is sent


class TestVerdicts:
    def test_exposed_secret_reports_count(self, checker):
        with patch.object(
            checker,
            "_get_requests",
            return_value=Mock(get=lambda *a, **k: _range_response("password", 4012)),
        ):
            r = checker.check("password")
        assert r["exposed"] is True and r["count"] == 4012

    def test_unseen_secret_not_exposed(self, checker):
        # Response that does not contain our suffix.
        with patch.object(
            checker,
            "_get_requests",
            return_value=Mock(get=lambda *a, **k: Mock(status_code=200, text="DEAD:1")),
        ):
            r = checker.check("a-unique-unbreached-value-9281")
        assert r["exposed"] is False and r["count"] == 0

    def test_network_error_is_unknown_not_safe(self, checker):
        with patch.object(
            checker,
            "_get_requests",
            return_value=Mock(get=lambda *a, **k: Mock(status_code=503, text="")),
        ):
            r = checker.check("x")
        assert r["exposed"] is None  # never a false "not exposed"

    def test_empty_value(self, checker):
        assert checker.check("")["exposed"] is None


class TestEnrichFindings:
    def test_only_correlatable_findings_checked(self, checker):
        findings = [
            {"rule_name": "Db Password", "value": "password", "severity": "medium"},
            {"rule_name": "AWS Access Key ID", "value": "AKIA...", "severity": "high"},
        ]
        calls = []

        def fake_check(value):
            calls.append(value)
            return {"exposed": True, "count": 9}

        with patch.object(checker, "check", side_effect=fake_check):
            out = checker.enrich_findings(findings)

        # Only the password-like finding is correlated, not the AWS key.
        assert calls == ["password"]
        pw = out[0]
        assert pw["breach_exposure"].startswith("EXPOSED")
        # An exposed (publicly-known) secret is escalated to at least high.
        assert pw["severity"] == "high"
        assert "breach_exposure" not in out[1]

    def test_password_named_after_provider_is_still_correlated(self):
        # A real password whose name contains a provider word (aws_db_password)
        # is a password, not an AWS key, so it must still be breach-correlated.
        c = BreachChecker({})
        assert c._is_correlatable(
            {"rule_name": "Aws Db Password", "variable": "aws_db_password"}
        )

    def test_provider_secret_key_not_correlated(self):
        # "stripe secret key" is a provider key, not a password: the weak
        # "secret" hint must not pull it into password-breach correlation.
        c = BreachChecker({})
        assert not c._is_correlatable(
            {"rule_name": "Stripe Secret Key", "pattern_category": "stripe"}
        )

    def test_bare_client_secret_is_correlated(self):
        # A bare client_secret (no provider marker) is in scope.
        c = BreachChecker({})
        assert c._is_correlatable(
            {"rule_name": "Client Secret", "variable": "client_secret"}
        )
