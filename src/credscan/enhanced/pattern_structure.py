"""
Enhanced pattern categorization for credential detection.
This module defines the structure for organizing detection patterns by credential type.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Set, Union


@dataclass
class CredentialPattern:
    """Represents a pattern for detecting a specific type of credential."""

    name: str
    pattern: str
    description: Optional[str] = None
    severity: str = "medium"  # Values: low, medium, high, critical
    compiled_pattern: Optional[Pattern] = None
    confidence: float = 0.8  # 0.0 to 1.0 confidence level
    # Which regex group holds the credential token. 0 = whole match (default,
    # for patterns that match the token directly). Set to 1+ on assignment-style
    # patterns like `key = (<secret>)` where a group isolates the bare secret.
    value_group: int = 0
    examples: List[str] = field(default_factory=list)  # Example matches for testing
    false_positives: List[str] = field(
        default_factory=list
    )  # Known false positive examples

    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        if self.pattern:
            try:
                self.compiled_pattern = re.compile(self.pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{self.pattern}': {str(e)}")

    def matches(self, value: str) -> bool:
        """Check if the given value matches this pattern."""
        if not self.compiled_pattern or not value:
            return False
        return bool(self.compiled_pattern.search(value))

    def extract(self, value: str) -> Optional[str]:
        """Return the matched credential substring, not the whole input.

        When a pattern matches inside a larger string (e.g. the line
        ``aws_access_key_id = AKIA...``), downstream consumers — masking and
        especially live validation, which pairs an ``AKIA`` key with its
        secret — need the bare token, not the surrounding assignment.

        By default the full match (``group(0)``) is the token. Patterns whose
        regex isolates the secret in a capture group (assignment-style, e.g.
        ``key = (<secret>)``) set ``value_group`` to that group's index, so the
        bare secret is returned instead of the ``key = `` prefix. Alternation
        groups like ``(AKIA|ASIA)[A-Z0-9]{16}`` keep ``value_group = 0`` because
        their group is only a fragment of the token.
        """
        if not self.compiled_pattern or not value:
            return None
        m = self.compiled_pattern.search(value)
        if not m:
            return None
        if self.value_group and m.groups():
            # From value_group onward, return the first group that captured —
            # handles patterns with alternative groups (quoted | unquoted value).
            for g in m.groups()[self.value_group - 1 :]:
                if g:
                    return g
        return m.group(0)


@dataclass
class PatternCategory:
    """A category of credential patterns for a specific service or technology."""

    name: str
    description: str
    patterns: List[CredentialPattern] = field(default_factory=list)
    enabled: bool = True

    def add_pattern(self, pattern: CredentialPattern):
        """Add a pattern to this category."""
        self.patterns.append(pattern)

    def check_value(self, value: str) -> List[CredentialPattern]:
        """Check a value against all patterns in this category."""
        if not self.enabled or not value:
            return []

        matches = []
        for pattern in self.patterns:
            if pattern.matches(value):
                matches.append(pattern)

        return matches

    def extract_matches(self, value: str) -> List[tuple]:
        """Like check_value, but also return the matched credential substring.

        Returns a list of (pattern, extracted_token) tuples.
        """
        if not self.enabled or not value:
            return []

        results = []
        for pattern in self.patterns:
            token = pattern.extract(value)
            if token is not None:
                results.append((pattern, token))
        return results


class PatternLibrary:
    """A library of credential pattern categories."""

    def __init__(self):
        self.categories: Dict[str, PatternCategory] = {}
        self.enabled_categories: Set[str] = set()

    def add_category(self, category: PatternCategory):
        """Add a pattern category to the library."""
        self.categories[category.name] = category
        if category.enabled:
            self.enabled_categories.add(category.name)

    def enable_category(self, category_name: str):
        """Enable a pattern category."""
        if category_name in self.categories:
            self.categories[category_name].enabled = True
            self.enabled_categories.add(category_name)

    def disable_category(self, category_name: str):
        """Disable a pattern category."""
        if category_name in self.categories:
            self.categories[category_name].enabled = False
            self.enabled_categories.discard(category_name)

    def check_value(self, value: str) -> Dict[str, List[CredentialPattern]]:
        """Check a value against all enabled pattern categories."""
        if not value:
            return {}

        results = {}
        for category_name in self.enabled_categories:
            category = self.categories.get(category_name)
            if category:
                matches = category.check_value(value)
                if matches:
                    results[category_name] = matches

        return results

    def extract_matches(self, value: str) -> Dict[str, List[tuple]]:
        """Like check_value, but each match carries the extracted token.

        Returns {category_name: [(pattern, extracted_token), ...]}.
        """
        if not value:
            return {}

        results = {}
        for category_name in self.enabled_categories:
            category = self.categories.get(category_name)
            if category:
                matches = category.extract_matches(value)
                if matches:
                    results[category_name] = matches

        return results

    def get_all_patterns(self) -> List[CredentialPattern]:
        """Get all patterns from all categories."""
        all_patterns = []
        for category in self.categories.values():
            all_patterns.extend(category.patterns)
        return all_patterns

    @classmethod
    def from_dict(cls, data: Dict) -> "PatternLibrary":
        """Create a PatternLibrary from a dictionary representation."""
        library = cls()

        for category_data in data.get("categories", []):
            category = PatternCategory(
                name=category_data["name"],
                description=category_data.get("description", ""),
                enabled=category_data.get("enabled", True),
            )

            for pattern_data in category_data.get("patterns", []):
                pattern = CredentialPattern(
                    name=pattern_data["name"],
                    pattern=pattern_data["pattern"],
                    description=pattern_data.get("description", ""),
                    severity=pattern_data.get("severity", "medium"),
                    confidence=pattern_data.get("confidence", 0.8),
                    examples=pattern_data.get("examples", []),
                    false_positives=pattern_data.get("false_positives", []),
                )
                category.add_pattern(pattern)

            library.add_category(category)

        return library

    def to_dict(self) -> Dict:
        """Convert the PatternLibrary to a dictionary representation."""
        return {
            "categories": [
                {
                    "name": category.name,
                    "description": category.description,
                    "enabled": category.enabled,
                    "patterns": [
                        {
                            "name": pattern.name,
                            "pattern": pattern.pattern,
                            "description": pattern.description,
                            "severity": pattern.severity,
                            "confidence": pattern.confidence,
                            "examples": pattern.examples,
                            "false_positives": pattern.false_positives,
                        }
                        for pattern in category.patterns
                    ],
                }
                for category in self.categories.values()
            ]
        }
