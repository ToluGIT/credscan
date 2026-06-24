"""
Integration of the enhanced pattern library with the existing rule engine.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from credscan.baseline.manager import BaselineManager
from credscan.core.engine import ScanEngine

# Import from the cred-scan codebase
from credscan.detection.rules import Rule

from .pattern_library import load_default_patterns, load_patterns_from_file

# Import our new pattern library
from .pattern_structure import CredentialPattern, PatternCategory, PatternLibrary


class EnhancedRule(Rule):
    """
    Extended rule class that integrates with the enhanced pattern library.
    """

    def __init__(
        self,
        rule_config: Dict[str, Any],
        pattern_library: Optional[PatternLibrary] = None,
    ):
        """
        Initialize an enhanced rule with the pattern library integration.

        Args:
            rule_config: Rule definition dictionary
            pattern_library: Optional pattern library to use with this rule
        """
        super().__init__(rule_config)
        self.pattern_library = pattern_library or load_default_patterns()
        self.enabled_categories: Set[str] = set(
            rule_config.get("enabled_categories", [])
        )

        # If no categories are explicitly enabled, enable all by default
        if not self.enabled_categories:
            self.enabled_categories = set(self.pattern_library.categories.keys())

        # Configure categories based on the rule config
        for category_name in self.pattern_library.categories:
            if category_name in self.enabled_categories:
                self.pattern_library.enable_category(category_name)
            else:
                self.pattern_library.disable_category(category_name)

    def apply(
        self, parsed_content: Dict[str, Any], filepath: str
    ) -> List[Dict[str, Any]]:
        """
        Apply the rule to parsed content.

        Args:
            parsed_content: Parsed file content
            filepath: Path to the file

        Returns:
            List of findings
        """
        # First, apply the standard Rule logic
        findings = super().apply(parsed_content, filepath)

        # Then, apply the enhanced pattern library checks
        items = parsed_content.get("items", [])

        for item in items:
            key = item.get("key")
            value = item.get("value")
            item_type = item.get("type")
            line = item.get("line", 0)

            if value:
                # Check value against all enabled pattern categories
                matched_patterns = self.pattern_library.check_value(value)

                for category_name, patterns in matched_patterns.items():
                    for pattern in patterns:
                        # Create a finding for each matched pattern
                        findings.append(
                            {
                                "rule_id": self.id,
                                "rule_name": f"{self.name} ({pattern.name})",
                                "severity": pattern.severity,
                                "type": "enhanced_pattern_match",
                                "pattern": pattern.name,
                                "pattern_category": category_name,
                                "confidence": pattern.confidence,
                                "variable": key,
                                "value": value,
                                "line": line,
                                "path": filepath,
                                "description": pattern.description
                                or f"Detected {pattern.name} in {category_name} category",
                            }
                        )

        return findings


class EnhancedScanEngine(ScanEngine):
    """
    Extended scan engine that integrates with the enhanced pattern library.
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize with configuration."""
        super().__init__(config)
        self.pattern_library = None
        self.enabled_categories = set()

    def initialize_patterns(self, pattern_library=None):
        """Initialize pattern library."""
        # Use provided pattern library or load default
        if pattern_library:
            self.pattern_library = pattern_library
        else:
            self.pattern_library = load_default_patterns()

        # Configure enabled categories
        self.enabled_categories = set(self.config.get("enabled_pattern_categories", []))
        if not self.enabled_categories and self.pattern_library:
            self.enabled_categories = set(self.pattern_library.categories.keys())

        # Enable/disable categories based on configuration
        for category_name in self.pattern_library.categories:
            if category_name in self.enabled_categories:
                self.pattern_library.enable_category(category_name)
            else:
                self.pattern_library.disable_category(category_name)

    def register_enhanced_rules(self, pattern_library_path: Optional[str] = None):
        """Register enhanced detection rules with the engine."""
        # Load pattern library (from file if provided)
        if pattern_library_path:
            try:
                pattern_library = load_patterns_from_file(pattern_library_path)
            except Exception as e:
                self.logger.error(
                    f"Error loading pattern library from {pattern_library_path}: {e}"
                )
                pattern_library = load_default_patterns()
        else:
            pattern_library = load_default_patterns()

        # Register enhanced rules
        enhanced_rules = EnhancedRuleLoader.load_default_rules(pattern_library)
        self.register_rules(enhanced_rules)

        self.logger.info(
            f"Registered {len(enhanced_rules)} enhanced detection rules with {len(pattern_library.get_all_patterns())} patterns"
        )

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Enhanced scan for a single file with improved deduplication."""
        # First, use the standard scanning mechanism
        findings = super().scan_file(filepath)

        # Skip if no pattern library is configured
        if not self.pattern_library:
            return findings

        # Use set to track duplicates - key is the extracted credential value
        found_credentials = set()
        enhanced_findings = []

        try:
            from credscan.file_cache import read_text

            content = read_text(filepath)
            if content is None:
                return findings

            # Extract individual lines for better context
            lines = content.split("\n")

            # Check lines for patterns
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue  # Skip empty lines

                # Check against all enabled patterns
                for category_name, category in self.pattern_library.categories.items():
                    if category_name not in self.enabled_categories:
                        continue

                    for pattern in category.patterns:
                        if pattern.matches(line):
                            # Extract the actual credential value
                            # This is a simplified approach - in real implementation,
                            # you'd want to use the pattern to extract the exact credential

                            # Create a fingerprint based on the actual content
                            # This will deduplicate findings with the same actual credential
                            fingerprint = f"{category_name}:{line}"

                            if fingerprint in found_credentials:
                                continue

                            found_credentials.add(fingerprint)

                            enhanced_findings.append(
                                {
                                    "rule_id": "enhanced_pattern",
                                    "rule_name": f"Enhanced Pattern: {pattern.name}",
                                    "severity": pattern.severity,
                                    "type": "enhanced_pattern_match",
                                    "pattern": pattern.name,
                                    "pattern_category": category_name,
                                    "confidence": pattern.confidence,
                                    "variable": None,
                                    "value": line,  # Use the specific line content
                                    "line": line_num,
                                    "path": filepath,
                                    "description": pattern.description
                                    or f"Detected {pattern.name} in {category_name} category",
                                }
                            )

            # Add the enhanced findings to the results
            findings.extend(enhanced_findings)

        except Exception as e:
            self.logger.error(f"Error applying enhanced patterns to {filepath}: {e}")
            if getattr(self, "verbose", False):
                self.logger.exception(e)

        return findings


class EnhancedRuleLoader:
    """
    Loads and initializes enhanced detection rules with pattern library integration.
    """

    @staticmethod
    def load_default_rules(
        pattern_library: Optional[PatternLibrary] = None,
    ) -> List[EnhancedRule]:
        """
        Load a set of default detection rules with pattern library integration.

        Args:
            pattern_library: Optional pattern library to use

        Returns:
            List of initialized EnhancedRule objects
        """
        # Use the provided pattern library or load the default one
        if not pattern_library:
            pattern_library = load_default_patterns()

        # Define default rule configs
        default_rule_configs = [
            {
                "id": "enhanced_credentials",
                "name": "Enhanced Credential Detection",
                "description": "Detects credentials using the enhanced pattern library",
                "severity": "high",
                "enabled_categories": list(pattern_library.categories.keys()),
                "variable_patterns": [
                    r"(?i)passwd|password|pass",
                    r"(?i)secret",
                    r"(?i)token",
                    r"(?i)apiKey|api[_-]key",
                    r"(?i)accessKey|access[_-]key",
                    r"(?i)bearer",
                    r"(?i)credentials",
                    r"(?i)db[_-]?password",
                    r"salt|SALT|Salt",
                    r"(?i)signature",
                ],
                "variable_exclusion_pattern": r"(?i)format|tokenizer|secretName|Error$|passwordPolicy|tokens$|tokenPolicy|[,\s#+*^|}{'\"[\]]|regex",
                "value_exclusion_patterns": [
                    r"(?i)^test$|^password$|^postgres$|^root$|^foobar$|^example$|^changeme$|^default$|^master$",
                    r"(?i)^string$|^integer$|^number$|^boolean$|^xsd:.+|^literal$",
                    r"(?i)^true$|^false$",
                    r"(?i)^bearer$|^Authorization$",
                    r"bootstrapper",
                    r"\${.+\}",
                    r"(?i){{.*}}",
                ],
                "min_length": 6,
            },
            {
                "id": "aws_credentials",
                "name": "AWS Credential Detection",
                "description": "Detects AWS credentials specifically",
                "severity": "critical",
                "enabled_categories": ["aws"],
                "variable_patterns": [
                    r"(?i)aws[_.-]?key",
                    r"(?i)aws[_.-]?secret",
                    r"(?i)aws[_.-]?token",
                    r"(?i)aws[_.-]?id",
                ],
                "min_length": 8,
            },
            {
                "id": "payment_credentials",
                "name": "Payment Credential Detection",
                "description": "Detects payment processing credentials",
                "severity": "critical",
                "enabled_categories": ["payment"],
                "min_length": 8,
            },
        ]

        # Create and return rule objects
        rules = []
        for rule_config in default_rule_configs:
            rules.append(EnhancedRule(rule_config, pattern_library))

        return rules


class SimpleTextParser:
    """A simple parser for text files."""

    def __init__(self, config=None):
        self.config = config or {}

    def can_parse(self, filepath: str) -> bool:
        """Check if this parser can handle the file."""
        return filepath.endswith(".txt")

    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse the file content."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Create a simple structure with the content
            return {
                "type": "text",
                "path": filepath,
                "content": content,
                "items": [
                    {"key": None, "value": content, "line": 1, "type": "text_content"}
                ],
                "error": None,
            }
        except Exception as e:
            return {
                "type": "text",
                "path": filepath,
                "content": None,
                "error": f"Parse error: {str(e)}",
            }
