"""Tests for compliance control mapping and the compliance report output."""

import csv
import glob
import os

import pytest

from credscan.compliance import control_rows_for, controls_for
from credscan.output.reporter import Reporter


class TestControlMapping:
    def test_generic_finding_maps_to_cwe_798(self):
        controls = controls_for(
            {"rule_name": "Generic Secret", "pattern_category": "generic"}
        )
        assert "CWE-798" in controls
        assert any("NIST" in c for c in controls)
        assert any("PCI-DSS" in c for c in controls)

    def test_private_key_maps_to_cwe_321(self):
        controls = controls_for(
            {"rule_name": "Private Key", "pattern_category": "structural_high_value"}
        )
        assert "CWE-321" in controls

    def test_password_maps_to_cwe_259(self):
        controls = controls_for(
            {"rule_name": "Password", "pattern_category": "database_credentials"}
        )
        assert "CWE-259" in controls

    def test_cloud_finding_adds_secure_development_control(self):
        controls = controls_for(
            {"rule_name": "AWS Access Key", "pattern_category": "aws"}
        )
        assert "PCI-DSS 6.3.1" in controls


class TestControlRows:
    def test_rows_are_framework_segmented(self):
        rows = control_rows_for(
            {"rule_name": "AWS Access Key", "pattern_category": "aws"}
        )
        frameworks = {r["framework"] for r in rows}
        # An auditor pivots by framework, so several must be represented.
        assert {
            "CWE",
            "NIST 800-53",
            "PCI-DSS v4.0",
            "OWASP ASVS",
            "SOC 2",
        } <= frameworks
        # Every row carries id + requirement title (readable without a standard open).
        assert all(r["control"] and r["requirement"] for r in rows)

    def test_private_key_adds_iso_key_management(self):
        rows = control_rows_for(
            {"rule_name": "Private Key", "pattern_category": "structural_high_value"}
        )
        assert any(r["control"] == "ISO 27001 A.8.24" for r in rows)


class TestComplianceReport:
    def test_report_is_framework_segmented_audit_artifact(self, tmp_path):
        findings = [
            {
                "rule_name": "AWS Access Key",
                "pattern_category": "aws",
                "severity": "high",
                "value": 'key = "AKIAZ7Q2MNP4RVTW6XYL"',
                "path": "app/config.py",
                "line": 8,
                "overall_confidence": 0.9,
                "aws_validation": "ACTIVE: Account 123, ARN arn:... [long_term]",
            }
        ]
        r = Reporter(
            {"output_formats": ["compliance"], "output_directory": str(tmp_path)}
        )
        r.report(findings, {"files_scanned": 1})

        files = glob.glob(os.path.join(str(tmp_path), "credscan-compliance-*.csv"))
        assert files, "no compliance report produced"
        with open(files[0]) as f:
            rows = list(csv.reader(f))
        # Skip the commented provenance header + blank line; find the column header.
        header_idx = next(
            i for i, row in enumerate(rows) if row and row[0] == "Finding ID"
        )
        header, data = rows[header_idx], rows[header_idx + 1 :]
        for col in (
            "Framework",
            "Control",
            "Requirement",
            "Verification",
            "Finding ID",
        ):
            assert col in header, f"missing column {col}"
        # One finding expands to multiple control rows, all sharing one Finding ID.
        ids = {row[header.index("Finding ID")] for row in data if row}
        assert len(ids) == 1
        # A verified-live key is surfaced as such.
        assert any(row[header.index("Verification")] == "VERIFIED LIVE" for row in data)
        # The raw secret must not appear anywhere in the report; value is masked.
        assert "AKIAZ7Q2MNP4RVTW6XYL" not in open(files[0]).read()
        # Provenance header present.
        assert any(
            "CredScan compliance report" in (row[0] if row else "") for row in rows
        )
