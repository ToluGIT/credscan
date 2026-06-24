"""
Configuration integration for the enhanced pattern library.
"""

import json
import os
from typing import Any, Dict, List, Optional

import yaml

# Import from cred-scan
from credscan.core.engine import ScanEngine
from credscan.detection.rules import Rule, RuleLoader

from .context_aware_engine import ContextAwareConfig, ContextAwareEngine
from .entropy_analyzer import EnhancedEntropyAnalyzer, EnhancedEntropyEngine
from .pattern_library import (
    load_default_patterns,
    load_patterns_from_file,
    merge_pattern_libraries,
    save_patterns_to_file,
)

# Import our new modules
from .pattern_structure import CredentialPattern, PatternCategory, PatternLibrary
from .rule_engine_integration import (
    EnhancedRule,
    EnhancedRuleLoader,
    EnhancedScanEngine,
)
from .technology_detector import TechnologyAwareEngine, TechnologyDetector


class EnhancedConfig:
    """
    Enhanced configuration for the credential detection system.
    """

    def __init__(self, config_data: Dict[str, Any]):
        """Initialize with config data."""
        self.config_data = config_data

        # Extract pattern configuration
        self.pattern_library_path = config_data.get("pattern_library_path")
        self.enabled_categories = set(config_data.get("enabled_pattern_categories", []))
        self.disabled_categories = set(
            config_data.get("disabled_pattern_categories", [])
        )

        # Extract rule configuration
        self.custom_rules = config_data.get("custom_rules", [])

        # Extract other settings
        self.min_threshold = config_data.get(
            "min_threshold", 0.7
        )  # Confidence threshold
        self.severity_threshold = config_data.get("severity_threshold", "medium")

        # Technology detection settings
        self.enable_technology_detection = config_data.get(
            "enable_technology_detection", True
        )
        self.technology_categories = config_data.get("technology_categories", [])

        # Enhanced entropy settings
        self.enable_enhanced_entropy = config_data.get("enable_enhanced_entropy", True)
        self.entropy_thresholds = config_data.get("entropy_thresholds", {})

        # Context-aware detection settings
        self.enable_context_aware = config_data.get("enable_context_aware", True)
        self.context_config = config_data.get("context_config", {})

    def load_pattern_library(self) -> PatternLibrary:
        """
        Load the pattern library based on configuration.

        Returns:
            PatternLibrary: The loaded pattern library
        """
        # Start with default patterns
        library = load_default_patterns()

        # Load additional patterns if specified
        if self.pattern_library_path and os.path.exists(self.pattern_library_path):
            try:
                additional_library = load_patterns_from_file(self.pattern_library_path)
                library = merge_pattern_libraries(library, additional_library)
            except Exception as e:
                print(f"Error loading additional patterns: {e}")

        # Apply category enable/disable settings
        for category_name in self.enabled_categories:
            if category_name in library.categories:
                library.enable_category(category_name)

        for category_name in self.disabled_categories:
            if category_name in library.categories:
                library.disable_category(category_name)

        return library

    def create_enhanced_engine(self) -> EnhancedScanEngine:
        """
        Create an enhanced scan engine based on this configuration.

        Returns:
            EnhancedScanEngine: The configured scan engine
        """
        # Create the base engine with existing config
        base_engine = EnhancedScanEngine(self.config_data)

        # Load pattern library
        pattern_library = self.load_pattern_library()

        # Create enhanced rules
        enhanced_rules = EnhancedRuleLoader.load_default_rules(pattern_library)

        # Add custom rules if specified
        for rule_config in self.custom_rules:
            enhanced_rules.append(EnhancedRule(rule_config, pattern_library))

        # Register rules with the base engine
        base_engine.register_rules(enhanced_rules)
        base_engine.initialize_patterns(pattern_library)

        # Start with the base engine
        final_engine = base_engine

        # Wrap with technology-aware engine if enabled
        if self.enable_technology_detection:
            final_engine = TechnologyAwareEngine(final_engine, self.config_data)

        # Wrap with enhanced entropy engine if enabled
        if self.enable_enhanced_entropy:
            entropy_config = self.config_data.copy()
            if self.entropy_thresholds:
                entropy_config.update(self.entropy_thresholds)
            final_engine = EnhancedEntropyEngine(final_engine, entropy_config)

        return final_engine

    @classmethod
    def from_yaml_file(cls, filepath: str) -> "EnhancedConfig":
        """
        Load configuration from a YAML file.

        Args:
            filepath: Path to the YAML file

        Returns:
            EnhancedConfig: The loaded configuration
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        with open(filepath, "r") as f:
            config_data = yaml.safe_load(f)

        return cls(config_data)

    @classmethod
    def from_json_file(cls, filepath: str) -> "EnhancedConfig":
        """
        Load configuration from a JSON file.

        Args:
            filepath: Path to the JSON file

        Returns:
            EnhancedConfig: The loaded configuration
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        with open(filepath, "r") as f:
            config_data = json.load(f)

        return cls(config_data)

    def to_yaml_file(self, filepath: str):
        """
        Save configuration to a YAML file.

        Args:
            filepath: Path to save the YAML file
        """
        with open(filepath, "w") as f:
            yaml.dump(self.config_data, f, default_flow_style=False)

    def to_json_file(self, filepath: str):
        """
        Save configuration to a JSON file.

        Args:
            filepath: Path to save the JSON file
        """
        with open(filepath, "w") as f:
            json.dump(self.config_data, f, indent=2)


def get_example_config() -> Dict[str, Any]:
    """
    Generate an example configuration.

    Returns:
        Dict: Example configuration dictionary
    """
    return {
        "pattern_library_path": "path/to/custom/patterns.yaml",
        "enabled_pattern_categories": [
            "aws",
            "gcp",
            "database",
            "payment",
            "messaging",
            "private_keys",
            "jwt",
        ],
        "disabled_pattern_categories": ["social"],  # Example of a category to disable
        "custom_rules": [
            {
                "id": "custom_internal_tokens",
                "name": "Internal Token Detection",
                "description": "Detects internal tokens specific to your organization",
                "severity": "high",
                "variable_patterns": [
                    r"(?i)internal[_-]token",
                    r"(?i)company[_-]secret",
                ],
                "enabled_categories": ["api"],
            }
        ],
        "min_threshold": 0.7,
        "severity_threshold": "medium",
        # Technology detection settings
        "enable_technology_detection": True,
        "technology_categories": [
            "Docker/Containers",
            "Kubernetes",
            "CI/CD Platforms",
            "Extended Cloud Platforms",
            "Infrastructure as Code",
            "Package Managers",
        ],
        # Enhanced entropy settings
        "enable_enhanced_entropy": True,
        "entropy_thresholds": {
            "base64": 4.5,
            "hex": 3.8,
            "jwt": 4.0,
            "api_key": 4.2,
            "generic": 4.0,
        },
        # Include the standard cred-scan configuration
        "baseline_file": ".cred-scan-baseline.json",
        "exclude_patterns": ["vendor/", "node_modules/", ".git/"],
        "output_formats": ["console", "json", "sarif"],
        "output_directory": "./reports",
        "disable_colors": False,
        "max_workers": 4,
        "verbose": False,
    }


def create_example_config_file(filepath: str, format_type: str = "yaml"):
    """
    Create an example configuration file.

    Args:
        filepath: Path to save the file
        format_type: 'yaml' or 'json'
    """
    config_data = get_example_config()

    if format_type.lower() == "yaml":
        with open(filepath, "w") as f:
            yaml.dump(config_data, f, default_flow_style=False)
    elif format_type.lower() == "json":
        with open(filepath, "w") as f:
            json.dump(config_data, f, indent=2)
    else:
        raise ValueError(
            f"Unsupported format type: {format_type}. Use 'yaml' or 'json'."
        )
