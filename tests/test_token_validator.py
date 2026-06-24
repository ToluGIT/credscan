"""Tests for the multi-provider token validator.

All network calls are mocked: tests never contact a real provider and never
require live credentials. They verify provider detection, verdict mapping
(ACTIVE / INVALID / UNVERIFIED), and the read-only/opt-in ethics constraints.
"""
from unittest.mock import MagicMock, patch

import pytest

from credscan.validators.token_validator import TokenValidator


@pytest.fixture
def validator():
    v = TokenValidator({})
    # Neutralize the rate-limit sleep so tests are fast.
    v._rate_limit = lambda: None
    return v


class TestProviderDetection:
    @pytest.mark.parametrize("token,provider", [
        ("ghp_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy1", "github"),
        ("xoxb-742318965012-742318965012-KpRxMnVzQtWb", "slack"),
        ("sk_live_7mNk3pQr5tVwXzBfCgHjKlMn", "stripe"),
        ("ya29.A0ARrdaM-longtokenvalue", "gcp"),
        ("AKIAZ7Q2MNP4RVTW6XYL", None),       # AWS handled elsewhere
        ("not-a-token", None),
    ])
    def test_detect_provider(self, validator, token, provider):
        assert validator.detect_provider(token) == provider


class TestVerdictMapping:
    def _mock_requests(self, status=200, json_data=None, ok_field=None):
        requests = MagicMock()
        resp = MagicMock()
        resp.status_code = status
        payload = dict(json_data or {})
        if ok_field is not None:
            payload["ok"] = ok_field
        resp.json.return_value = payload
        requests.get.return_value = resp
        requests.post.return_value = resp
        return requests

    def test_github_active(self, validator):
        requests = self._mock_requests(200, {"login": "octocat"})
        with patch.object(validator, "_get_requests", return_value=requests):
            result = validator.validate("ghp_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy1")
        assert result["valid"] is True
        assert "octocat" in result["identity"]

    def test_github_invalid(self, validator):
        requests = self._mock_requests(401)
        with patch.object(validator, "_get_requests", return_value=requests):
            result = validator.validate("ghp_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy1")
        assert result["valid"] is False

    def test_slack_active(self, validator):
        requests = self._mock_requests(200, {"team": "acme"}, ok_field=True)
        with patch.object(validator, "_get_requests", return_value=requests):
            result = validator.validate("xoxb-742318965012-742318965012-KpRxMnVzQtWb")
        assert result["valid"] is True

    def test_slack_revoked(self, validator):
        requests = self._mock_requests(200, {"error": "invalid_auth"}, ok_field=False)
        with patch.object(validator, "_get_requests", return_value=requests):
            result = validator.validate("xoxb-742318965012-742318965012-KpRxMnVzQtWb")
        assert result["valid"] is False

    def test_network_error_is_unverified_not_invalid(self, validator):
        requests = MagicMock()
        requests.get.side_effect = RuntimeError("connection reset")
        with patch.object(validator, "_get_requests", return_value=requests):
            result = validator.validate("ghp_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy1")
        # The dangerous direction: a network failure must NOT read as invalid.
        assert result["valid"] is None

    def test_unsupported_token_is_unverified(self, validator):
        result = validator.validate("AKIAZ7Q2MNP4RVTW6XYL")
        assert result["valid"] is None
        assert result["provider"] is None

    def test_gcp_400_without_invalid_body_is_unverified(self, validator):
        # A bare HTTP 400 (no 'invalid' in the body) must NOT be read as INVALID.
        requests = self._mock_requests(400, {"error": "bad_request"})
        with patch.object(validator, "_get_requests", return_value=requests):
            result = validator.validate("ya29.A0ARrdaM-sometoken")
        assert result["valid"] is None

    def test_gcp_400_with_invalid_token_body_is_invalid(self, validator):
        requests = self._mock_requests(400, {"error_description": "Invalid Value"})
        with patch.object(validator, "_get_requests", return_value=requests):
            result = validator.validate("ya29.A0ARrdaM-sometoken")
        assert result["valid"] is False


class TestEthicsConstraints:
    def test_github_uses_readonly_user_endpoint(self, validator):
        requests = MagicMock()
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"login": "x"}
        requests.get.return_value = resp
        with patch.object(validator, "_get_requests", return_value=requests):
            validator.validate("ghp_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy1")
        url = requests.get.call_args[0][0]
        assert url == "https://api.github.com/user"  # read-only identity endpoint

    def test_stripe_uses_readonly_account_endpoint(self, validator):
        requests = MagicMock()
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"id": "acct_123"}
        requests.get.return_value = resp
        with patch.object(validator, "_get_requests", return_value=requests):
            validator.validate("sk_live_7mNk3pQr5tVwXzBfCgHjKlMn")
        url = requests.get.call_args[0][0]
        assert url == "https://api.stripe.com/v1/account"

    def test_verification_is_opt_in_only(self):
        # The validator never runs on its own; enrich_findings is only called
        # from the CLI when --verify is passed. A finding with no token is
        # left untouched.
        v = TokenValidator({})
        v._rate_limit = lambda: None
        findings = [{"value": "not a token here", "rule_name": "x"}]
        out = v.enrich_findings(findings)
        assert "verification" not in out[0]


class TestEnrichFindings:
    def test_active_token_marked_critical(self, validator):
        requests = MagicMock()
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"login": "octocat"}
        requests.get.return_value = resp
        findings = [{
            "value": 'token = "ghp_R7y2Kx4pQn8vZ3wBfCgHjLmNt6RsUuVwXy1"',
            "rule_name": "GitHub Token", "severity": "high",
        }]
        with patch.object(validator, "_get_requests", return_value=requests):
            out = validator.enrich_findings(findings)
        assert out[0]["verification"].startswith("ACTIVE")
        assert out[0]["severity"] == "critical"
