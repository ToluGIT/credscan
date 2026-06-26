"""
Reporting system for credential detection results.
"""

import datetime
import hashlib
import html
import json
import logging
import os
from typing import Any, Dict, List

from credscan.remediation import remediation_for as _remediation_for
from credscan.remediation import remediation_text as _remediation_text

# Enhanced output format dependencies
try:
    import pandas as pd

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from fpdf import FPDF

    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

logger = logging.getLogger(__name__)


def verification_stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute the verified-secret precision metric from actual verdicts.

    Of findings for providers CredScan can verify, how many were confirmed
    live. This is the most persuasive honest number a secrets scanner can
    report ("4/5 verifiable keys confirmed active"), so it is computed from
    real verdicts attached by the validators, never asserted.

    Returns counts: verifiable (had a verdict attempted), live (confirmed
    active), live_rate (live/verifiable), and breached (secrets found in a
    known breach corpus).
    """
    verifiable = 0
    live = 0
    breached = 0
    for f in findings:
        verdict = f.get("verification") or f.get("aws_validation")
        if verdict:
            # SKIPPED/UNKNOWN means we could not actually verify; don't count it
            # as verifiable, so the rate reflects real confirm-or-deny outcomes.
            if verdict.startswith(("ACTIVE", "INVALID")):
                verifiable += 1
                if verdict.startswith("ACTIVE"):
                    live += 1
        if str(f.get("breach_exposure", "")).startswith("EXPOSED"):
            breached += 1
    return {
        "verifiable": verifiable,
        "live": live,
        "live_rate": (live / verifiable) if verifiable else 0.0,
        "breached": breached,
    }


class Reporter:
    """
    Handles formatting and outputting credential detection results.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the reporter with configuration.

        Args:
            config: Configuration for the reporter
        """
        self.config = config or {}
        self.output_formats = self.config.get("output_formats", ["console"])
        self.output_directory = self.config.get("output_directory", ".")
        self.disable_colors = self.config.get("disable_colors", False)

        # Terminal colors
        if not self.disable_colors:
            self.colors = {
                "red": "\033[31m",
                "green": "\033[32m",
                "yellow": "\033[33m",
                "blue": "\033[34m",
                "magenta": "\033[35m",
                "cyan": "\033[36m",
                "white": "\033[37m",
                "reset": "\033[0m",
                "bold": "\033[1m",
                "dim": "\033[2m",
                "bg_red": "\033[41m",
                "bg_green": "\033[42m",
            }
        else:
            self.colors = {
                k: ""
                for k in (
                    "red",
                    "green",
                    "yellow",
                    "blue",
                    "magenta",
                    "cyan",
                    "white",
                    "reset",
                    "bold",
                    "dim",
                    "bg_red",
                    "bg_green",
                )
            }

    def report(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Generate and output reports in the specified formats.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        # Filter out test/example credentials consistently across ALL formats
        # (not just console). Findings classified as test credentials are
        # suppressed unless the user explicitly asks to see them. This keeps
        # JSON/SARIF/HTML output aligned with the console and with the
        # precision the tool reports.
        if not self.config.get("show_test_credentials", False):
            kept = [f for f in findings if not f.get("is_test_credential", False)]
            statistics = {
                **statistics,
                "test_filtered_count": len(findings) - len(kept),
            }
            findings = kept

        for output_format in self.output_formats:
            if output_format == "console":
                self.report_console(findings, statistics)
            elif output_format == "json":
                self.report_json(findings, statistics)
            elif output_format == "sarif":
                self.report_sarif(findings, statistics)
            elif output_format == "excel":
                self.report_excel(findings, statistics)
            elif output_format == "csv":
                self.report_csv(findings, statistics)
            elif output_format == "html":
                self.report_html(findings, statistics)
            elif output_format == "pdf":
                self.report_pdf(findings, statistics)
            elif output_format == "compliance":
                self.report_compliance(findings, statistics)
            else:
                logger.warning(f"Unsupported output format: {output_format}")

    def report_console(
        self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]
    ):
        """
        Print findings to the console in a readable format.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        c = self.colors

        # Print statistics
        print(f"\n{c['bold']}=== Credential Scan Results ==={c['reset']}\n")
        print(f"Files found: {statistics.get('files_found', 0)}")
        print(f"Files scanned: {statistics.get('files_scanned', 0)}")

        excluded_count = statistics.get("excluded_count", 0)
        if excluded_count > 0:
            print(f"Total credentials found: {c['bold']}{len(findings)}{c['reset']}")
            print(f"  - Excluded by baseline: {c['green']}{excluded_count}{c['reset']}")
            print(
                f"  - Reported: {c['bold']}{len(findings) - excluded_count}{c['reset']}\n"
            )
        else:
            print(f"Credentials found: {c['bold']}{len(findings)}{c['reset']}\n")

        # Findings are pre-filtered for test/example credentials in report();
        # surface how many were suppressed.
        test_filtered = statistics.get("test_filtered_count", 0)
        if test_filtered > 0:
            print(
                f"{c['dim']}Note: {test_filtered} test/example credentials filtered out (use --show-test-credentials to see them){c['reset']}\n"
            )

        # Check if we should group by severity
        group_by_severity = self.config.get("group_by_severity", False)

        if group_by_severity:
            self._print_findings_by_severity(findings, c)
        else:
            # Group findings by file AFTER filtering
            findings_by_file = {}
            for finding in findings:
                path = finding.get("path", "unknown")
                if path not in findings_by_file:
                    findings_by_file[path] = []
                findings_by_file[path].append(finding)

            # Print findings by file
            for filepath, file_findings in findings_by_file.items():
                # Print file header
                print(f"\n{c['bg_red']}{c['bold']} File: {filepath} {c['reset']}\n")

                # Sort findings by line number
                file_findings.sort(key=lambda f: f.get("line", 0))

                self._print_findings_list(file_findings, c)

        # Print summary
        if findings:
            print(
                f"\n{c['bold']}Summary:{c['reset']} {len(findings)} potential credential(s) found."
            )

            # Count by severity
            severity_counts = {"high": 0, "medium": 0, "low": 0}
            for finding in findings:
                severity = finding.get("severity", "medium")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if severity_counts["high"] > 0:
                print(f"{c['red']}High severity: {severity_counts['high']}{c['reset']}")
            if severity_counts["medium"] > 0:
                print(
                    f"{c['yellow']}Medium severity: {severity_counts['medium']}{c['reset']}"
                )
            if severity_counts["low"] > 0:
                print(f"{c['green']}Low severity: {severity_counts['low']}{c['reset']}")

            # Verification summary: the killer honest metric. Only shown when a
            # verify/validate run actually attached verdicts.
            vstats = verification_stats(findings)
            if vstats["live"] > 0:
                print(
                    f"\n{c['bold']}Verification:{c['reset']} "
                    f"{c['red']}{vstats['live']} live{c['reset']} / "
                    f"{vstats['verifiable']} verifiable "
                    f"({vstats['live_rate']:.0%} confirmed active)"
                )
            elif vstats["verifiable"] > 0:
                # We checked and none were live — a useful, non-alarming fact.
                print(
                    f"\n{c['bold']}Verification:{c['reset']} "
                    f"0 live / {vstats['verifiable']} verifiable "
                    f"(none confirmed active)"
                )
            if vstats["breached"] > 0:
                print(
                    f"{c['red']}Breach-exposed: {vstats['breached']} secret(s) "
                    f"found in known breaches{c['reset']}"
                )
        else:
            print(f"\n{c['green']}{c['bold']}No credentials found.{c['reset']}")

    def report_json(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Output findings in JSON format to a file.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        # Attach remediation guidance to each finding for the audit record.
        # By default the CLI JSON is a full-value audit log (documented). When
        # mask_values is set (the web GUI export does this), values are masked
        # so the downloadable artifact can never carry a raw secret even if an
        # upstream caller forgot to mask.
        mask_values = self.config.get("mask_values", False)
        enriched = []
        for finding in findings:
            f = dict(finding)
            if mask_values and f.get("value"):
                f["value"] = self._mask_value(f["value"])
            f.setdefault("remediation", _remediation_for(finding))
            enriched.append(f)

        report = {
            "scan_time": datetime.datetime.now().isoformat(),
            "statistics": statistics,
            "findings": enriched,
        }

        # Ensure output directory exists
        os.makedirs(self.output_directory, exist_ok=True)

        # Create output file
        output_file = os.path.join(
            self.output_directory,
            f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
        )

        try:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)

            logger.info(f"JSON report saved to {output_file}")
            print(f"\nJSON report saved to {output_file}")

        except Exception as e:
            logger.error(f"Error writing JSON report: {e}")

    def report_sarif(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Output findings in SARIF format to a file.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        # SARIF report structure
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CredScan",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/ToluGIT/credscan",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }

        # Collect unique rules, tagged with their CWE.
        rules_by_id = {}
        for finding in findings:
            rule_id = finding.get("rule_id", "unknown")
            if rule_id not in rules_by_id:
                cwe = self._cwe_for_finding(finding)
                cwe_num = cwe.split("-")[1]
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": finding.get("rule_name", "Unknown Rule"),
                    "shortDescription": {
                        "text": finding.get("rule_name", "Unknown Rule")
                    },
                    "fullDescription": {
                        "text": finding.get("description", "")
                        or "Detects potential hard-coded credentials or secrets."
                    },
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                    "help": {"text": _remediation_text(finding)},
                    "properties": {
                        "security-severity": str(
                            self._severity_to_number(finding.get("severity", "medium"))
                        ),
                        "tags": ["security", "secrets", cwe],
                        "cwe": cwe,
                    },
                }

        # Add rules to SARIF report
        sarif_report["runs"][0]["tool"]["driver"]["rules"] = list(rules_by_id.values())

        # Add results with stable partial fingerprints for cross-run dedup.
        for finding in findings:
            rule_id = finding.get("rule_id", "unknown")
            path = finding.get("path", "")
            line = finding.get("line", 0)

            result = {
                "ruleId": rule_id,
                "level": self._severity_to_level(finding.get("severity", "medium")),
                "message": {
                    "text": finding.get("description", "")
                    or "Potential hard-coded credential."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": path},
                            "region": {
                                "startLine": line if line else 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "credscan/v1": self._partial_fingerprint(finding)
                },
                "properties": {
                    "cwe": self._cwe_for_finding(finding),
                },
            }

            sarif_report["runs"][0]["results"].append(result)

        # Ensure output directory exists
        os.makedirs(self.output_directory, exist_ok=True)

        # Create output file
        output_file = os.path.join(
            self.output_directory,
            f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.sarif",
        )

        try:
            with open(output_file, "w") as f:
                json.dump(sarif_report, f, indent=2)

            logger.info(f"SARIF report saved to {output_file}")
            print(f"\nSARIF report saved to {output_file}")

        except Exception as e:
            logger.error(f"Error writing SARIF report: {e}")

    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        if severity == "high":
            return "error"
        elif severity == "medium":
            return "warning"
        else:
            return "note"

    def _severity_to_number(self, severity: str) -> float:
        """Convert severity to a number for SARIF."""
        if severity in ("critical",):
            return 9.5
        if severity == "high":
            return 8.0
        elif severity == "medium":
            return 5.0
        else:
            return 3.0

    @staticmethod
    def _cwe_for_finding(finding: Dict[str, Any]) -> str:
        """Map a finding to its CWE id (hard-coded credentials family).

        CWE-798 is the canonical 'Use of Hard-coded Credentials'. CWE-321
        (hard-coded cryptographic key) and CWE-259 (hard-coded password) are the
        more specific sub-cases used where the finding type makes them apply.
        """
        haystack = " ".join(
            str(finding.get(k, ""))
            for k in ("rule_name", "pattern_category", "type", "description")
        ).lower()
        if any(
            t in haystack
            for t in (
                "private key",
                "private_key",
                "rsa",
                "pem",
                "crypto",
                "certificate",
            )
        ):
            return "CWE-321"
        if "password" in haystack or "passwd" in haystack:
            return "CWE-259"
        return "CWE-798"

    @staticmethod
    def _partial_fingerprint(finding: Dict[str, Any]) -> str:
        """Stable fingerprint for cross-run dedup in SARIF consumers.

        Built from rule + path + a masked value shape rather than the raw
        secret, so the fingerprint file itself never carries a credential.
        """
        value = finding.get("value", "") or ""
        masked = Reporter._mask_value(value)
        basis = f"{finding.get('rule_id','')}|{finding.get('path','')}|{masked}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mask a secret value for display, showing only first/last 4 chars."""
        if not value or len(value) <= 8:
            return "****"
        return f"{value[:4]}...{value[-4:]}"

    def report_excel(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Output findings in Excel format to a file.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        if not PANDAS_AVAILABLE:
            logger.warning("Pandas not available, skipping Excel report")
            return

        try:
            # Prepare data for DataFrame
            data = []
            for finding in findings:
                data.append(
                    {
                        "Category": finding.get("category", "Unknown"),
                        "Severity": finding.get("severity", "medium"),
                        "Rule": finding.get("rule_name", ""),
                        "Variable": finding.get("variable", ""),
                        "Value": self._mask_value(finding.get("value", "")),
                        "File": finding.get("path", ""),
                        "Line": finding.get("line", 0),
                        "Description": finding.get("description", ""),
                    }
                )

            if not data:
                logger.info("No data to export to Excel")
                return

            # Create DataFrame
            df = pd.DataFrame(data)

            # Ensure output directory exists
            os.makedirs(self.output_directory, exist_ok=True)

            # Create output file
            output_file = os.path.join(
                self.output_directory,
                f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.xlsx",
            )

            # Write to Excel with formatting
            with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
                df.to_excel(writer, sheet_name="Findings", index=False)

                # Add statistics sheet
                stats_data = [[k, v] for k, v in statistics.items()]
                stats_df = pd.DataFrame(stats_data, columns=["Metric", "Value"])
                stats_df.to_excel(writer, sheet_name="Statistics", index=False)

            logger.info(f"Excel report saved to {output_file}")
            print(f"\nExcel report saved to {output_file}")

        except Exception as e:
            logger.error(f"Error writing Excel report: {e}")

    def report_csv(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Output findings in CSV format to a file.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        if not PANDAS_AVAILABLE:
            logger.warning("Pandas not available, skipping CSV report")
            return

        try:
            # Prepare data for DataFrame
            data = []
            for finding in findings:
                data.append(
                    {
                        "Category": finding.get("category", "Unknown"),
                        "Severity": finding.get("severity", "medium"),
                        "Rule": finding.get("rule_name", ""),
                        "Variable": finding.get("variable", ""),
                        "Value": self._mask_value(finding.get("value", "")),
                        "File": finding.get("path", ""),
                        "Line": finding.get("line", 0),
                        "Description": finding.get("description", ""),
                    }
                )

            if not data:
                logger.info("No data to export to CSV")
                return

            # Create DataFrame
            df = pd.DataFrame(data)

            # Ensure output directory exists
            os.makedirs(self.output_directory, exist_ok=True)

            # Create output file
            output_file = os.path.join(
                self.output_directory,
                f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.csv",
            )

            # Write to CSV
            df.to_csv(output_file, index=False)

            logger.info(f"CSV report saved to {output_file}")
            print(f"\nCSV report saved to {output_file}")

        except Exception as e:
            logger.error(f"Error writing CSV report: {e}")

    def _verification_status(self, finding: Dict[str, Any]) -> str:
        """Audit-friendly verification verdict for a finding."""
        v = finding.get("verification") or finding.get("aws_validation")
        if not v:
            return "not verified"
        if v.startswith("ACTIVE"):
            return "VERIFIED LIVE"
        if v.startswith("INVALID"):
            return "verified inactive"
        if v.startswith("SKIPPED"):
            return "not verified"
        return "verification inconclusive"

    def report_compliance(
        self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]
    ):
        """Write a control-mapped compliance report (CSV via stdlib csv).

        This is an auditor's artifact, so it is denormalized to one row per
        (finding x implicated control): an auditor can filter/pivot by the
        Framework column (PCI-DSS, NIST, SOC 2, ...). Each row carries a stable
        Finding ID (so it can be referenced across scans), the verification
        status (a confirmed-live key is a materially worse finding than an
        unverified match), the confidence, and the remediation. A provenance
        header records when/what/which tool version produced the report.
        Values are masked; this report is for auditors, not for secrets.
        """
        import csv

        from credscan import __version__
        from credscan.compliance import control_rows_for

        os.makedirs(self.output_directory, exist_ok=True)
        output_file = os.path.join(
            self.output_directory,
            f"credscan-compliance-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.csv",
        )
        try:
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                # Provenance header (commented rows so the CSV still parses).
                writer.writerow(["# CredScan compliance report"])
                writer.writerow(
                    [
                        "# Generated",
                        datetime.datetime.now().isoformat(timespec="seconds"),
                    ]
                )
                writer.writerow(["# Tool version", __version__])
                writer.writerow(
                    ["# Files scanned", statistics.get("files_scanned", "")]
                )
                writer.writerow(["# Findings", len(findings)])
                writer.writerow([])

                writer.writerow(
                    [
                        "Finding ID",
                        "Framework",
                        "Control",
                        "Requirement",
                        "Severity",
                        "Verification",
                        "Confidence",
                        "Finding",
                        "File",
                        "Line",
                        "Masked Value",
                        "Remediation",
                    ]
                )
                for finding in findings:
                    fid = self._partial_fingerprint(finding)[:12]
                    sev = finding.get("severity", "medium")
                    verification = self._verification_status(finding)
                    conf = finding.get(
                        "overall_confidence", finding.get("confidence", "")
                    )
                    conf_str = f"{float(conf):.2f}" if conf != "" else ""
                    masked = self._mask_value(finding.get("value", ""))
                    remediation = _remediation_text(finding)
                    rule = finding.get("rule_name", "")
                    path = finding.get("path", "")
                    line = finding.get("line", "")
                    for ctrl in control_rows_for(finding):
                        writer.writerow(
                            [
                                fid,
                                ctrl["framework"],
                                ctrl["control"],
                                ctrl["requirement"],
                                sev,
                                verification,
                                conf_str,
                                rule,
                                path,
                                line,
                                masked,
                                remediation,
                            ]
                        )
            logger.info(f"Compliance report saved to {output_file}")
            print(f"\nCompliance report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error writing compliance report: {e}")

    def report_html(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Output findings in HTML format to a file.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        try:
            # Prepare data for HTML
            data = []
            for finding in findings:
                severity_color = {
                    "high": "#ff4444",
                    "medium": "#ffaa00",
                    "low": "#44aa44",
                }.get(finding.get("severity", "medium"), "#888888")
                severity_label = html.escape(finding.get("severity", "medium").upper())

                data.append(
                    {
                        "Category": html.escape(finding.get("category", "Unknown")),
                        "Severity": f'<span style="color: {severity_color}; font-weight: bold">{severity_label}</span>',
                        "Rule": html.escape(finding.get("rule_name", "")),
                        "Variable": html.escape(finding.get("variable", "")),
                        "Value": html.escape(
                            self._mask_value(finding.get("value", ""))
                        ),
                        "File": html.escape(finding.get("path", "")),
                        "Line": finding.get("line", 0),
                        "Description": html.escape(finding.get("description", "")),
                    }
                )

            # Create HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>CredScan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    .stats {{ background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <h1>CredScan Security Report</h1>
                <div class="stats">
                    <h3>Scan Statistics</h3>
            """

            for key, value in statistics.items():
                html_content += f"<p><strong>{html.escape(key.replace('_', ' ').title())}:</strong> {html.escape(str(value))}</p>"

            html_content += f"""
                    <p><strong>Report Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <h3>Findings ({len(findings)} total)</h3>
            """

            if data:
                if PANDAS_AVAILABLE:
                    df = pd.DataFrame(data)
                    html_content += df.to_html(escape=False, index=False)
                else:
                    # Manual HTML table creation
                    html_content += "<table><tr>"
                    for key in data[0].keys():
                        html_content += f"<th>{key}</th>"
                    html_content += "</tr>"

                    for row in data:
                        html_content += "<tr>"
                        for cell_value in row.values():
                            # Values are already escaped above; int Line passes through safely
                            html_content += f"<td>{cell_value}</td>"
                        html_content += "</tr>"
                    html_content += "</table>"
            else:
                html_content += "<p>No credentials found.</p>"

            html_content += """
            </body>
            </html>
            """

            # Ensure output directory exists
            os.makedirs(self.output_directory, exist_ok=True)

            # Create output file
            output_file = os.path.join(
                self.output_directory,
                f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.html",
            )

            # Write HTML file
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"HTML report saved to {output_file}")
            print(f"\nHTML report saved to {output_file}")

        except Exception as e:
            logger.error(f"Error writing HTML report: {e}")

    def report_pdf(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Output findings in PDF format to a file.

        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        if not PDF_AVAILABLE:
            logger.warning("FPDF not available, skipping PDF report")
            return

        try:
            # Create PDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=16)

            # Title
            pdf.cell(0, 10, "CredScan Security Report", ln=True, align="C")
            pdf.ln(10)

            # Statistics
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, "Scan Statistics:", ln=True)
            pdf.set_font("Arial", size=10)

            for key, value in statistics.items():
                pdf.cell(0, 8, f"{key.replace('_', ' ').title()}: {value}", ln=True)

            pdf.ln(5)
            pdf.cell(
                0,
                8,
                f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                ln=True,
            )
            pdf.ln(10)

            # Findings
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, f"Findings ({len(findings)} total):", ln=True)
            pdf.ln(5)

            if findings:
                pdf.set_font("Arial", size=9)
                for i, finding in enumerate(findings, 1):
                    if pdf.get_y() > 250:  # Check if we need a new page
                        pdf.add_page()

                    severity = finding.get("severity", "medium").upper()
                    category = finding.get("category", "Unknown")
                    variable = finding.get("variable", "")
                    file_path = finding.get("path", "")
                    line_num = finding.get("line", 0)

                    pdf.cell(0, 6, f"{i}. [{severity}] {category}", ln=True)
                    if variable:
                        pdf.cell(0, 6, f"   Variable: {variable}", ln=True)
                    if file_path:
                        pdf.cell(
                            0, 6, f"   File: {file_path} (Line {line_num})", ln=True
                        )
                    pdf.ln(2)
            else:
                pdf.cell(0, 10, "No credentials found.", ln=True)

            # Ensure output directory exists
            os.makedirs(self.output_directory, exist_ok=True)

            # Create output file
            output_file = os.path.join(
                self.output_directory,
                f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf",
            )

            # Save PDF
            pdf.output(output_file)

            logger.info(f"PDF report saved to {output_file}")
            print(f"\nPDF report saved to {output_file}")

        except Exception as e:
            logger.error(f"Error writing PDF report: {e}")

    def _get_confidence_color(self, confidence: float) -> str:
        """Get appropriate color for confidence score."""
        if self.disable_colors:
            return ""

        if confidence >= 0.8:
            return self.colors["green"]  # High confidence - green
        elif confidence >= 0.6:
            return self.colors["yellow"]  # Medium confidence - yellow
        elif confidence >= 0.4:
            return self.colors["magenta"]  # Low-medium confidence - magenta
        else:
            return self.colors["red"]  # Low confidence - red

    def _print_findings_by_severity(
        self, findings: List[Dict[str, Any]], c: Dict[str, str]
    ):
        """Print findings grouped by severity level."""
        # Group findings by severity
        severity_groups = {"high": [], "medium": [], "low": [], "info": []}

        for finding in findings:
            severity = finding.get("severity", "medium")
            if severity in severity_groups:
                severity_groups[severity].append(finding)
            else:
                severity_groups["medium"].append(finding)  # Default to medium

        # Print each severity group
        severity_order = ["high", "medium", "low", "info"]
        for severity in severity_order:
            if not severity_groups[severity]:
                continue

            # Print severity header
            severity_color = (
                c["red"]
                if severity == "high"
                else c["yellow"] if severity == "medium" else c["green"]
            )
            print(
                f"\n{c['bg_red'] if severity == 'high' else c['dim']}{c['bold']} {severity.upper()} SEVERITY FINDINGS ({len(severity_groups[severity])}) {c['reset']}\n"
            )

            # Group by file within this severity
            files_in_severity = {}
            for finding in severity_groups[severity]:
                path = finding.get("path", "unknown")
                if path not in files_in_severity:
                    files_in_severity[path] = []
                files_in_severity[path].append(finding)

            # Print findings for each file in this severity
            for filepath, file_findings in files_in_severity.items():
                print(f"\n{c['bold']}File: {filepath}{c['reset']}")
                file_findings.sort(key=lambda f: f.get("line", 0))
                self._print_findings_list(file_findings, c)

    def _print_findings_list(self, findings: List[Dict[str, Any]], c: Dict[str, str]):
        """Print a list of findings with detailed information."""
        for finding in findings:
            rule_name = finding.get("rule_name", "Unknown Rule")
            severity = finding.get("severity", "medium")
            line = finding.get("line", 0)
            variable = finding.get("variable", "")
            value = finding.get("value", "")
            description = finding.get("description", "")

            # Handle excluded findings
            is_excluded = finding.get("excluded", False)

            # Color-code severity
            if is_excluded:
                severity_str = f"{c['green']}EXCLUDED{c['reset']}"
            elif severity == "high":
                severity_str = f"{c['red']}{severity.upper()}{c['reset']}"
            elif severity == "medium":
                severity_str = f"{c['yellow']}{severity.upper()}{c['reset']}"
            else:
                severity_str = f"{c['green']}{severity.upper()}{c['reset']}"

            # Print finding details
            if is_excluded:
                print(
                    f"{c['bold']}[{severity_str}] {rule_name}{c['reset']} (Baseline: {finding.get('exclusion_reason', 'Unknown reason')})"
                )
            else:
                # Check if this is a grouped finding
                if finding.get("is_duplicate_group"):
                    detection_count = finding.get("detection_count", 1)
                    print(
                        f"{c['bold']}[{severity_str}] {rule_name}{c['reset']} ({c['cyan']}{detection_count} detections grouped{c['reset']})"
                    )

                    # Show detection methods if available
                    detection_methods = finding.get("detection_methods", [])
                    if detection_methods and len(detection_methods) > 1:
                        methods = [
                            m.get("rule", "Unknown") for m in detection_methods[:3]
                        ]
                        print(f"  Detection methods: {', '.join(methods)}")
                else:
                    print(f"{c['bold']}[{severity_str}] {rule_name}{c['reset']}")

                # Mark test credentials
                if finding.get("is_test_credential"):
                    test_indicators = finding.get("test_indicators", [])
                    print(
                        f"  {c['yellow']}⚠ Likely test/example credential{c['reset']} ({', '.join(test_indicators[:2])})"
                    )

            if line:
                print(f"  Line: {line}")

            if variable:
                print(f"  Variable: {variable}")

            if value:
                print(f"  Value: {c['yellow']}{self._mask_value(value)}{c['reset']}")

            print(f"  {description}")

            # Show confidence information if available
            overall_confidence = finding.get("overall_confidence")
            context_confidence = finding.get(
                "confidence"
            )  # Context confidence from existing analyzer

            if overall_confidence is not None:
                confidence_color = self._get_confidence_color(overall_confidence)
                print(
                    f"  Overall Confidence: {confidence_color}{overall_confidence:.3f}{c['reset']}"
                )
            elif context_confidence is not None:
                confidence_color = self._get_confidence_color(context_confidence)
                print(
                    f"  Confidence: {confidence_color}{context_confidence:.3f}{c['reset']}"
                )

            # Show detailed confidence breakdown if requested
            if finding.get("confidence_explanation") and not is_excluded:
                explanation_lines = finding["confidence_explanation"].split("\n")
                print(f"  {c['dim']}{explanation_lines[0]}{c['reset']}")
                if len(explanation_lines) > 1:
                    for line in explanation_lines[1:4]:  # Show top 3 factors
                        if line.strip():
                            print(f"  {c['dim']}{line}{c['reset']}")

            # Show context information if available
            context_type = finding.get("context_type")
            risk_level = finding.get("risk_level")
            if context_type and not is_excluded:
                risk_color = (
                    c["red"]
                    if risk_level == "high"
                    else c["yellow"] if risk_level == "medium" else c["green"]
                )
                print(
                    f"  Context: {context_type} ({risk_color}{risk_level} risk{c['reset']})"
                )

            # Show verification verdict if a validator ran
            verification = finding.get("verification") or finding.get("aws_validation")
            if verification and not is_excluded:
                vcolor = c["red"] if verification.startswith("ACTIVE") else c["dim"]
                print(f"  Verification: {vcolor}{verification}{c['reset']}")

            # Show breach-exposure correlation if it ran (--check-breaches)
            breach = finding.get("breach_exposure")
            if breach and not is_excluded:
                bcolor = c["red"] if breach.startswith("EXPOSED") else c["dim"]
                print(f"  Breach exposure: {bcolor}{breach}{c['reset']}")

            # Show the git-history exposure window if present (history scans)
            window = finding.get("exposure_window")
            if window and not is_excluded:
                print(f"  Exposure: {c['dim']}{window}{c['reset']}")

            # Show remediation guidance (skip for clearly-excluded findings)
            if not is_excluded:
                r = _remediation_for(finding)
                print(f"  {c['cyan']}Remediation:{c['reset']} {r['action']}")
                if r.get("revoke"):
                    print(f"    Revoke: {r['revoke']}")
                print(f"    Fix: {r['root_cause']}")

            # Show exclusion ID if excluded
            if is_excluded and finding.get("exclusion_id"):
                print(f"  Exclusion ID: {finding.get('exclusion_id')}")

            print()
