"""Tests for compliance control mapping and the compliance report output."""
import csv
import glob
import os

import pytest

from credscan.compliance import controls_for
from credscan.output.reporter import Reporter


class TestControlMapping:
    def test_generic_finding_maps_to_cwe_798(self):
        controls = controls_for({"rule_name": "Generic Secret", "pattern_category": "generic"})
        assert "CWE-798" in controls
        assert any("NIST" in c for c in controls)
        assert any("PCI-DSS" in c for c in controls)

    def test_private_key_maps_to_cwe_321(self):
        controls = controls_for({"rule_name": "Private Key", "pattern_category": "structural_high_value"})
        assert "CWE-321" in controls

    def test_password_maps_to_cwe_259(self):
        controls = controls_for({"rule_name": "Password", "pattern_category": "database_credentials"})
        assert "CWE-259" in controls

    def test_cloud_finding_adds_secure_development_control(self):
        controls = controls_for({"rule_name": "AWS Access Key", "pattern_category": "aws"})
        assert "PCI-DSS 6.3.1" in controls


class TestComplianceReport:
    def test_report_written_with_controls_column(self, tmp_path):
        findings = [{
            "rule_name": "AWS Access Key", "pattern_category": "aws",
            "severity": "high", "value": 'key = "AKIAZ7Q2MNP4RVTW6XYL"',
            "path": "app/config.py", "line": 8,
        }]
        r = Reporter({"output_formats": ["compliance"], "output_directory": str(tmp_path)})
        r.report(findings, {"files_scanned": 1})

        files = glob.glob(os.path.join(str(tmp_path), "credscan-compliance-*.csv"))
        assert files, "no compliance report produced"
        with open(files[0]) as f:
            rows = list(csv.reader(f))
        header, data = rows[0], rows[1:]
        assert "Controls" in header
        assert len(data) == 1
        controls_col = data[0][header.index("Controls")]
        assert "CWE-798" in controls_col
        # The raw secret must not appear; the value is masked.
        masked_col = data[0][header.index("Masked Value")]
        assert "AKIAZ7Q2MNP4RVTW6XYL" not in masked_col
