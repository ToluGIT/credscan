"""Tests for the remediation map: every finding type yields actionable guidance."""
import pytest

from credscan.remediation import remediation_for, remediation_text


class TestRemediationMapping:
    @pytest.mark.parametrize("finding,expect_in_action", [
        ({"pattern_category": "aws", "rule_name": "AWS Access Key"}, "IAM"),
        ({"pattern_category": "github", "rule_name": "GitHub Token"}, "GitHub"),
        ({"pattern_category": "stripe", "rule_name": "Stripe Key"}, "Stripe"),
        ({"rule_name": "Private Key", "pattern_category": "structural_high_value"}, "compromised"),
        ({"rule_name": "Password", "pattern_category": "database_credentials"}, "password"),
    ])
    def test_action_is_provider_specific(self, finding, expect_in_action):
        r = remediation_for(finding)
        assert expect_in_action.lower() in r["action"].lower()

    def test_every_finding_gets_all_fields(self):
        # Even an unknown category gets a complete, generic remediation.
        r = remediation_for({"rule_name": "Mystery", "pattern_category": "unknown"})
        assert r["action"]
        assert r["root_cause"]
        assert r["prevention"]

    def test_aws_has_revoke_link(self):
        r = remediation_for({"pattern_category": "aws"})
        assert r["revoke"].startswith("https://")

    def test_text_is_single_line_pipe_separated(self):
        text = remediation_text({"pattern_category": "github"})
        assert "Action:" in text and "Fix:" in text and "Prevent:" in text
        assert "\n" not in text
