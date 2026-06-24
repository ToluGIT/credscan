"""SARIF 2.1.0 output correctness tests.

Verifies the structural invariants GitHub code scanning and other SARIF
consumers rely on: version, tool driver, rules, results with regions,
CWE tagging, partialFingerprints for cross-run dedup, and -- critically for a
secrets tool -- that no raw secret value leaks into the SARIF file.
"""
import glob
import json
import os

import pytest

from credscan.output.reporter import Reporter

# A finding shaped like the engine's real output.
AWS_SECRET = "AKIAZ7Q2MNP4RVTW6XYL"
FINDINGS = [
    {
        "rule_id": "enhanced_pattern",
        "rule_name": "Enhanced Pattern: Aws Access Key Id",
        "severity": "high",
        "type": "enhanced_pattern_match",
        "pattern_category": "aws",
        "value": f'AWS_ACCESS_KEY_ID = "{AWS_SECRET}"',
        "line": 8,
        "path": "app/config.py",
        "description": "AWS Access Key ID",
    },
    {
        "rule_id": "enhanced_pattern",
        "rule_name": "Enhanced Pattern: Private Key",
        "severity": "critical",
        "pattern_category": "structural_high_value",
        "value": "-----BEGIN RSA PRIVATE KEY-----",
        "line": 1,
        "path": "keys/id_rsa",
        "description": "Private key in PEM armor",
    },
    {
        "rule_id": "enhanced_pattern",
        "rule_name": "Enhanced Pattern: Password",
        "severity": "high",
        "value": 'password = "Pr0dDb_Pass_X7y2Kp9Q"',
        "line": 13,
        "path": "infra/main.tf",
        "description": "Hardcoded password",
    },
]


@pytest.fixture
def sarif(tmp_path):
    r = Reporter({"output_formats": ["sarif"], "output_directory": str(tmp_path)})
    r.report(FINDINGS, {"files_scanned": 3})
    files = glob.glob(os.path.join(str(tmp_path), "*.sarif"))
    assert files, "no SARIF file produced"
    with open(files[0]) as f:
        return f.read(), json.loads(open(files[0]).read())


class TestSarifStructure:
    def test_version_and_schema(self, sarif):
        _, doc = sarif
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert doc["runs"][0]["tool"]["driver"]["name"] == "CredScan"

    def test_rules_present(self, sarif):
        _, doc = sarif
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        assert all("id" in r for r in rules)

    def test_results_have_regions(self, sarif):
        _, doc = sarif
        for res in doc["runs"][0]["results"]:
            region = res["locations"][0]["physicalLocation"]["region"]
            assert region["startLine"] >= 1
            assert "startColumn" in region


class TestCweTagging:
    def test_rules_carry_cwe_tags(self, sarif):
        _, doc = sarif
        for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
            tags = rule["properties"]["tags"]
            assert any(t.startswith("CWE-") for t in tags)
            assert rule["helpUri"].startswith("https://cwe.mitre.org/")

    def test_private_key_maps_to_cwe_321(self, sarif):
        _, doc = sarif
        cwes = {res["properties"]["cwe"] for res in doc["runs"][0]["results"]}
        assert "CWE-321" in cwes  # private key
        assert "CWE-259" in cwes  # password
        assert "CWE-798" in cwes  # generic hard-coded credential


class TestStableFingerprints:
    def test_results_have_partial_fingerprints(self, sarif):
        _, doc = sarif
        for res in doc["runs"][0]["results"]:
            assert "credscan/v1" in res["partialFingerprints"]

    def test_fingerprints_are_stable(self, tmp_path):
        # Same input twice -> identical fingerprints (cross-run dedup works).
        def run():
            d = tmp_path / os.urandom(4).hex()
            d.mkdir()
            r = Reporter({"output_formats": ["sarif"], "output_directory": str(d)})
            r.report(FINDINGS, {"files_scanned": 3})
            f = glob.glob(os.path.join(str(d), "*.sarif"))[0]
            doc = json.load(open(f))
            return [res["partialFingerprints"]["credscan/v1"]
                    for res in doc["runs"][0]["results"]]
        assert run() == run()


class TestNoSecretLeak:
    def test_raw_secret_not_in_sarif(self, sarif):
        raw, _ = sarif
        # The full AWS key must never appear verbatim in the SARIF file.
        assert AWS_SECRET not in raw
        assert "Pr0dDb_Pass_X7y2Kp9Q" not in raw
