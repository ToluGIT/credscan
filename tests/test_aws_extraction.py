"""Regression tests for AWS credential extraction + validation pairing.

A live test surfaced that enhanced-pattern findings stored the whole
``key = value`` line as the finding value, so AWS validation (which needs the
bare 20-char access key and the 40-char secret) silently skipped every key
written in assignment form. These tests lock in:

  1. The finding ``value`` is the bare credential token, not the line.
  2. The validator pairs an AKIA key with a same-file secret even when the
     secret only surfaces as an entropy/base64 finding (no "secret" in its
     rule name), and maps the STS result to ACTIVE / INVALID.

The STS call is mocked; no live credentials and no network are used.
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from credscan.engine_factory import build_scan_engine
from credscan.enhanced.pattern_structure import CredentialPattern
from credscan.validators.aws_validator import AWSCredentialValidator

# Synthetic, clearly-fake credentials (shape-valid, not live).
FAKE_AKID = "AKIAY2K7MNQ4RST6UVWX"
FAKE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@pytest.fixture
def env_file():
    d = tempfile.mkdtemp(prefix="credscan-awsx-")
    p = os.path.join(d, "creds.env")
    with open(p, "w") as fh:
        fh.write(f"aws_access_key_id = {FAKE_AKID}\n")
        fh.write(f"aws_secret_access_key = {FAKE_SECRET}\n")
    yield d
    import shutil

    shutil.rmtree(d, ignore_errors=True)


class TestTokenExtraction:
    def test_extract_returns_full_match_for_alternation_pattern(self):
        # (AKIA|ASIA)[A-Z0-9]{16}: the group is only the prefix, so the token
        # is the full match, not group 1.
        p = CredentialPattern(name="akid", pattern=r"(AKIA|ASIA)[A-Z0-9]{16}")
        assert p.extract(f"aws_access_key_id = {FAKE_AKID}") == FAKE_AKID

    def test_extract_returns_capture_group_for_assignment_pattern(self):
        # When value_group points at the credential group, return the bare value.
        p = CredentialPattern(
            name="kv",
            pattern=r"(?i)\bsecret\b\s*[:=]\s*['\"]?([A-Za-z0-9/+]{20,})['\"]?",
            value_group=1,
        )
        assert p.extract("secret = " + FAKE_SECRET) == FAKE_SECRET

    def test_extract_none_when_no_match(self):
        p = CredentialPattern(name="akid", pattern=r"AKIA[A-Z0-9]{16}")
        assert p.extract("nothing here") is None


class TestEngineStoresBareToken:
    def test_access_key_value_is_bare_token(self, env_file):
        eng = build_scan_engine(
            {"scan_path": env_file, "min_confidence_threshold": 0.4}
        )
        findings = eng.scan()
        akids = [f for f in findings if str(f.get("value", "")).startswith("AKIA")]
        assert akids, "no AWS access key finding produced"
        for f in akids:
            assert f["value"] == FAKE_AKID, f"value over-captured: {f['value']!r}"

    def test_findings_carry_no_unmasked_line_context(self, env_file):
        # Findings must not carry a raw_line (or any full assignment line) field:
        # such context is unmasked and would leak the secret through JSON export.
        eng = build_scan_engine(
            {"scan_path": env_file, "min_confidence_threshold": 0.4}
        )
        for f in eng.scan():
            assert "raw_line" not in f
            for v in f.values():
                # No stored field should contain the "key = secret" line form.
                assert not (isinstance(v, str) and "aws_access_key_id = " in v)


class TestValidatorPairing:
    def _mock_sts(self, valid):
        # Build a fake validate() result so no network/creds are needed.
        if valid:
            return {
                "valid": True,
                "account_id": "123456789012",
                "user_arn": "arn:aws:iam::123456789012:user/test",
                "user_id": "AIDATEST",
                "key_type": "long_term",
            }
        return {
            "valid": False,
            "key_type": "long_term",
            "error": "Invalid or expired key",
        }

    def test_pairs_and_marks_active(self, env_file):
        eng = build_scan_engine(
            {"scan_path": env_file, "min_confidence_threshold": 0.4}
        )
        findings = eng.scan()
        v = AWSCredentialValidator({})
        with patch.object(v, "validate", return_value=self._mock_sts(True)):
            out = v.enrich_findings(findings)
        verdicts = [f.get("aws_validation") for f in out if f.get("aws_validation")]
        assert any(x.startswith("ACTIVE") for x in verdicts), verdicts
        # A confirmed-live key is escalated to critical.
        assert any(
            f.get("aws_validation", "").startswith("ACTIVE")
            and f.get("severity") == "critical"
            for f in out
        )

    def test_pairs_and_marks_invalid(self, env_file):
        eng = build_scan_engine(
            {"scan_path": env_file, "min_confidence_threshold": 0.4}
        )
        findings = eng.scan()
        v = AWSCredentialValidator({})
        with patch.object(v, "validate", return_value=self._mock_sts(False)):
            out = v.enrich_findings(findings)
        verdicts = [f.get("aws_validation") for f in out if f.get("aws_validation")]
        assert verdicts and all(x.startswith("INVALID") for x in verdicts), verdicts

    def test_validate_never_called_without_a_pair(self):
        # An access key with no same-file secret must be SKIPPED, not validated.
        findings = [
            {"rule_name": "AWS Access Key ID", "value": FAKE_AKID, "path": "/x/a.env"}
        ]
        v = AWSCredentialValidator({})
        with patch.object(v, "validate") as m:
            out = v.enrich_findings(findings)
            m.assert_not_called()
        assert out[0]["aws_validation"].startswith("SKIPPED")
