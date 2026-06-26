"""Tests verifying reporter security properties — masking and XSS prevention."""

import pytest

from credscan.output.reporter import Reporter


@pytest.fixture
def reporter():
    return Reporter({"output_formats": ["console"], "disable_colors": True})


class TestValueMasking:
    def test_short_value_fully_masked(self, reporter):
        assert reporter._mask_value("abc") == "****"

    def test_value_at_boundary_masked(self, reporter):
        assert reporter._mask_value("12345678") == "****"

    def test_long_value_shows_prefix_and_suffix(self, reporter):
        result = reporter._mask_value("AKIAIOSFODNN7EXAMPLE_SECRET")
        assert result.startswith("AKIA")
        assert result.endswith("CRET")
        assert "..." in result

    def test_empty_value_masked(self, reporter):
        assert reporter._mask_value("") == "****"

    def test_nine_char_value_masked(self, reporter):
        # exactly 9 chars — qualifies for show-first-4-last-4
        result = reporter._mask_value("123456789")
        assert result == "1234...6789"


class TestHTMLEscaping:
    def test_xss_payload_escaped_in_html_report(self, tmp_path, reporter):
        reporter.config["output_formats"] = ["html"]
        reporter.output_directory = str(tmp_path)

        findings = [
            {
                "rule_name": "Test Rule",
                "severity": "high",
                "category": "test",
                "variable": "API_KEY",
                "value": '<script>alert("xss")</script>AbCdEfGhIjKl',
                "path": "/tmp/test.py",
                "line": 1,
                "description": "Test finding",
            }
        ]
        reporter.report_html(findings, {"files_scanned": 1})

        html_files = list(tmp_path.glob("*.html"))
        assert html_files, "No HTML report was generated"
        content = html_files[0].read_text()

        assert (
            "<script>" not in content
        ), "Raw <script> tag found in HTML report — XSS vulnerability!"
        assert (
            "&lt;script&gt;" in content or "alert" not in content
        ), "XSS payload was not properly escaped"

    def test_stats_values_escaped_in_html(self, tmp_path, reporter):
        reporter.config["output_formats"] = ["html"]
        reporter.output_directory = str(tmp_path)

        reporter.report_html([], {"<injected>": "<b>bold</b>"})

        html_files = list(tmp_path.glob("*.html"))
        assert html_files
        content = html_files[0].read_text()
        assert "<b>bold</b>" not in content or "&lt;b&gt;" in content
