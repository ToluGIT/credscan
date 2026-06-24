"""
IaC (Infrastructure as Code) parser for detecting credentials in Terraform,
CloudFormation, and AWS CDK files.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List

from credscan.core.parser_base import BaseParser

logger = logging.getLogger(__name__)

# Extensions and filenames this parser handles
_EXTENSIONS = {".tf", ".tfvars", ".hcl"}
_CF_EXTENSIONS = {".yaml", ".yml", ".json", ".template"}
_CDK_EXTENSIONS = {".ts", ".py", ".js"}

# CloudFormation filename indicators
_CF_FILENAMES = {"template", "stack", "cloudformation", "cfn", "cf-", "cf_"}

# Patterns that strongly suggest a CloudFormation template
_CF_MARKERS = re.compile(
    r'(?:"AWSTemplateFormatVersion"|AWSTemplateFormatVersion\s*:)', re.IGNORECASE
)

# Terraform hardcoded credential patterns
_TF_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "Terraform Hardcoded Access Key",
        "pattern": re.compile(
            r'(?i)(?:access_key|aws_access_key_id)\s*=\s*"([^"${}]{16,})"'
        ),
        "severity": "critical",
        "category": "terraform",
    },
    {
        "name": "Terraform Hardcoded Secret Key",
        "pattern": re.compile(
            r'(?i)(?:secret_key|aws_secret_access_key)\s*=\s*"([^"${}]{20,})"'
        ),
        "severity": "critical",
        "category": "terraform",
    },
    {
        "name": "Terraform Hardcoded Token",
        "pattern": re.compile(
            r'(?i)(?:token|api_key|api_token|password|passwd|secret)\s*=\s*"([^"${}]{8,})"'
        ),
        "severity": "high",
        "category": "terraform",
    },
    {
        "name": "Terraform Variable Default Secret",
        "pattern": re.compile(
            r'(?i)variable\s+"[^"]*(?:secret|key|token|password|passwd)[^"]*"\s*\{[^}]*default\s*=\s*"([^"${}]{8,})"',
            re.DOTALL,
        ),
        "severity": "high",
        "category": "terraform",
    },
    {
        "name": "Terraform AWS Account ID",
        "pattern": re.compile(r"\b(\d{12})\b"),
        "severity": "medium",
        "category": "terraform",
    },
]

# CloudFormation hardcoded credential patterns
_CF_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "CloudFormation Hardcoded Secret",
        "pattern": re.compile(
            r'(?i)(?:password|passwd|secret|api_?key|access_?key|token)\s*:\s*["\']?([^"\'${}{\n]{8,})["\']?'
        ),
        "severity": "critical",
        "category": "cloudformation",
    },
    {
        "name": "CloudFormation NoEcho Missing",
        "pattern": re.compile(
            r"(?i)(?:Password|Secret|Key|Token)\s*:\s*\n\s*Type\s*:\s*String"
            r"(?![\s\S]{0,200}NoEcho\s*:\s*true)",
            re.DOTALL,
        ),
        "severity": "medium",
        "category": "cloudformation",
    },
]

# Patterns to skip — template variable references are not real credentials
_SKIP_PATTERNS = re.compile(
    r"^\$\{|^\!Ref|^\!Sub|^var\.|^\$\(|^data\.|^aws_|^module\.",
    re.IGNORECASE,
)


def _is_template_variable(value: str) -> bool:
    """Return True if the value looks like a template reference, not a literal."""
    stripped = value.strip()
    return bool(_SKIP_PATTERNS.match(stripped)) or stripped.startswith("${")


class IaCParser(BaseParser):
    """Parser for Infrastructure as Code files (Terraform, CloudFormation, CDK)."""

    def can_parse(self, filepath: str) -> bool:
        ext = os.path.splitext(filepath)[1].lower()
        basename = os.path.basename(filepath).lower()

        if ext in _EXTENSIONS:
            return True

        # CloudFormation: YAML/JSON files whose name hints at CF
        if ext in _CF_EXTENSIONS:
            if any(hint in basename for hint in _CF_FILENAMES):
                return True

        return False

    def parse(self, filepath: str) -> Dict[str, Any]:
        content = self.read_file(filepath)
        if not content:
            return {}

        ext = os.path.splitext(filepath)[1].lower()
        basename = os.path.basename(filepath).lower()

        entries = []
        is_cf = ext in _CF_EXTENSIONS and (
            _CF_MARKERS.search(content) or any(h in basename for h in _CF_FILENAMES)
        )

        if ext in _EXTENSIONS:
            entries = self._parse_terraform(content, filepath)
        elif is_cf:
            entries = self._parse_cloudformation(content, filepath)

        return {
            "filepath": filepath,
            "file_type": "terraform" if ext in _EXTENSIONS else "cloudformation",
            "entries": entries,
        }

    def _parse_terraform(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        entries = []
        lines = content.splitlines()

        for pattern_def in _TF_PATTERNS:
            for match in pattern_def["pattern"].finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                if _is_template_variable(value):
                    continue

                # Derive line number from match position
                line_num = content[: match.start()].count("\n") + 1

                entries.append(
                    {
                        "key": pattern_def["name"],
                        "value": value,
                        "line": line_num,
                        "rule_name": pattern_def["name"],
                        "severity": pattern_def["severity"],
                        "category": pattern_def["category"],
                        "path": filepath,
                        "description": f"Hardcoded credential in Terraform: {pattern_def['name']}",
                    }
                )

        return entries

    def _parse_cloudformation(
        self, content: str, filepath: str
    ) -> List[Dict[str, Any]]:
        entries = []

        for pattern_def in _CF_PATTERNS:
            for match in pattern_def["pattern"].finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                if _is_template_variable(value):
                    continue

                line_num = content[: match.start()].count("\n") + 1

                entries.append(
                    {
                        "key": pattern_def["name"],
                        "value": value,
                        "line": line_num,
                        "rule_name": pattern_def["name"],
                        "severity": pattern_def["severity"],
                        "category": pattern_def["category"],
                        "path": filepath,
                        "description": f"Hardcoded credential in CloudFormation: {pattern_def['name']}",
                    }
                )

        return entries
