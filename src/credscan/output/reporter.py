"""
Reporting system for credential detection results.
"""
import json
import os
import datetime
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

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
        self.output_formats = self.config.get('output_formats', ['console'])
        self.output_directory = self.config.get('output_directory', '.')
        self.disable_colors = self.config.get('disable_colors', False)
        
        # Terminal colors
        if not self.disable_colors:
            self.colors = {
                'red': '\033[31m',
                'green': '\033[32m',
                'yellow': '\033[33m',
                'blue': '\033[34m',
                'magenta': '\033[35m',
                'cyan': '\033[36m',
                'white': '\033[37m',
                'reset': '\033[0m',
                'bold': '\033[1m',
                'bg_red': '\033[41m',
                'bg_green': '\033[42m'
            }
        else:
            self.colors = {k: '' for k in ('red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', 'reset', 'bold', 'bg_red', 'bg_green')}
    
    def report(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Generate and output reports in the specified formats.
        
        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        for output_format in self.output_formats:
            if output_format == 'console':
                self.report_console(findings, statistics)
            elif output_format == 'json':
                self.report_json(findings, statistics)
            elif output_format == 'sarif':
                self.report_sarif(findings, statistics)
            else:
                logger.warning(f"Unsupported output format: {output_format}")
    
    def report_console(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
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
        
        excluded_count = statistics.get('excluded_count', 0)
        if excluded_count > 0:
            print(f"Total credentials found: {c['bold']}{len(findings)}{c['reset']}")
            print(f"  - Excluded by baseline: {c['green']}{excluded_count}{c['reset']}")
            print(f"  - Reported: {c['bold']}{len(findings) - excluded_count}{c['reset']}\n")
        else:
            print(f"Credentials found: {c['bold']}{len(findings)}{c['reset']}\n")

        
        # Group findings by file
        findings_by_file = {}
        for finding in findings:
            path = finding.get('path', 'unknown')
            if path not in findings_by_file:
                findings_by_file[path] = []
            findings_by_file[path].append(finding)
        
        # Print findings by file
        for filepath, file_findings in findings_by_file.items():
            # Print file header
            print(f"\n{c['bg_red']}{c['bold']} File: {filepath} {c['reset']}\n")
            
            # Sort findings by line number
            file_findings.sort(key=lambda f: f.get('line', 0))
            
            for finding in file_findings:
                rule_name = finding.get('rule_name', 'Unknown Rule')
                severity = finding.get('severity', 'medium')
                line = finding.get('line', 0)
                variable = finding.get('variable', '')
                value = finding.get('value', '')
                description = finding.get('description', '')
                
                # Handle excluded findings
                is_excluded = finding.get('excluded', False)
                
                # Color-code severity
                if is_excluded:
                    severity_str = f"{c['green']}EXCLUDED{c['reset']}"
                elif severity == 'high':
                    severity_str = f"{c['red']}{severity.upper()}{c['reset']}"
                elif severity == 'medium':
                    severity_str = f"{c['yellow']}{severity.upper()}{c['reset']}"
                else:
                    severity_str = f"{c['green']}{severity.upper()}{c['reset']}"
                
                # Print finding details
                if is_excluded:
                    print(f"{c['bold']}[{severity_str}] {rule_name}{c['reset']} (Baseline: {finding.get('exclusion_reason', 'Unknown reason')})")
                else:
                    print(f"{c['bold']}[{severity_str}] {rule_name}{c['reset']}")
                
                if line:
                    print(f"  Line: {line}")
                    
                if variable:
                    print(f"  Variable: {variable}")
                    
                if value:
                    # Truncate long values
                    if len(value) > 100:
                        display_value = value[:97] + "..."
                    else:
                        display_value = value
                    print(f"  Value: {c['yellow']}{display_value}{c['reset']}")
                    
                print(f"  {description}")
                
                # Show exclusion ID if excluded
                if is_excluded and finding.get('exclusion_id'):
                    print(f"  Exclusion ID: {finding.get('exclusion_id')}")
                    
                print()
                
        # Print summary
        if findings:
            print(f"\n{c['bold']}Summary:{c['reset']} {len(findings)} potential credential(s) found.")
            
            # Count by severity
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            for finding in findings:
                severity = finding.get('severity', 'medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
            if severity_counts['high'] > 0:
                print(f"{c['red']}High severity: {severity_counts['high']}{c['reset']}")
            if severity_counts['medium'] > 0:
                print(f"{c['yellow']}Medium severity: {severity_counts['medium']}{c['reset']}")
            if severity_counts['low'] > 0:
                print(f"{c['green']}Low severity: {severity_counts['low']}{c['reset']}")
        else:
            print(f"\n{c['green']}{c['bold']}No credentials found.{c['reset']}")
    
    def report_json(self, findings: List[Dict[str, Any]], statistics: Dict[str, Any]):
        """
        Output findings in JSON format to a file.
        
        Args:
            findings: List of detection findings
            statistics: Dictionary of scan statistics
        """
        report = {
            "scan_time": datetime.datetime.now().isoformat(),
            "statistics": statistics,
            "findings": findings
        }
        
        # Ensure output directory exists
        os.makedirs(self.output_directory, exist_ok=True)
        
        # Create output file
        output_file = os.path.join(self.output_directory, f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
        
        try:
            with open(output_file, 'w') as f:
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
                            "informationUri": "https://github.com/yourusername/credscan",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        # Collect unique rules
        rules_by_id = {}
        for finding in findings:
            rule_id = finding.get('rule_id', 'unknown')
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": finding.get('rule_name', 'Unknown Rule')
                    },
                    "fullDescription": {
                        "text": finding.get('description', '')
                    },
                    "help": {
                        "text": "This rule detects potential credentials or secrets in code."
                    },
                    "properties": {
                        "security-severity": self._severity_to_number(finding.get('severity', 'medium'))
                    }
                }
        
        # Add rules to SARIF report
        sarif_report["runs"][0]["tool"]["driver"]["rules"] = list(rules_by_id.values())
        
        # Add results
        for finding in findings:
            rule_id = finding.get('rule_id', 'unknown')
            path = finding.get('path', '')
            line = finding.get('line', 0)
            
            result = {
                "ruleId": rule_id,
                "level": self._severity_to_level(finding.get('severity', 'medium')),
                "message": {
                    "text": finding.get('description', '')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": path
                            },
                            "region": {
                                "startLine": line,
                                "startColumn": 1
                            }
                        }
                    }
                ]
            }
            
            sarif_report["runs"][0]["results"].append(result)
        
        # Ensure output directory exists
        os.makedirs(self.output_directory, exist_ok=True)
        
        # Create output file
        output_file = os.path.join(self.output_directory, f"credscan-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.sarif")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(sarif_report, f, indent=2)
                
            logger.info(f"SARIF report saved to {output_file}")
            print(f"\nSARIF report saved to {output_file}")
            
        except Exception as e:
            logger.error(f"Error writing SARIF report: {e}")
    
    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        if severity == 'high':
            return 'error'
        elif severity == 'medium':
            return 'warning'
        else:
            return 'note'
    
    def _severity_to_number(self, severity: str) -> float:
        """Convert severity to a number for SARIF."""
        if severity == 'high':
            return 9.0
        elif severity == 'medium':
            return 5.0
        else:
            return 3.0
