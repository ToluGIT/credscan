"""
Configuration integration for the enhanced pattern library.
"""

import os
import yaml
import json
from typing import Dict, Any, List, Optional

# Import from cred-scan
from credscan.core.engine import ScanEngine
from credscan.detection.rules import Rule, RuleLoader

# Import our new modules
from .pattern_structure import PatternLibrary, PatternCategory, CredentialPattern
from .pattern_library import load_default_patterns, load_patterns_from_file, save_patterns_to_file, merge_pattern_libraries
from .rule_engine_integration import EnhancedRule, EnhancedRuleLoader, EnhancedScanEngine




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
        self.disabled_categories = set(config_data.get("disabled_pattern_categories", []))
        
        # Extract rule configuration
        self.custom_rules = config_data.get("custom_rules", [])
        
        # Extract other settings
        self.min_threshold = config_data.get("min_threshold", 0.7)  # Confidence threshold
        self.severity_threshold = config_data.get("severity_threshold", "medium")
    
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
        # Create the engine with existing config
        engine = EnhancedScanEngine(self.config_data)
        
        # Load pattern library
        pattern_library = self.load_pattern_library()
        
        # Create enhanced rules
        enhanced_rules = EnhancedRuleLoader.load_default_rules(pattern_library)
        
        # Add custom rules if specified
        for rule_config in self.custom_rules:
            enhanced_rules.append(EnhancedRule(rule_config, pattern_library))
        
        # Register rules with the engine
        engine.register_rules(enhanced_rules)

        engine.initialize_patterns(pattern_library)
        
        return engine
    
    @classmethod
    def from_yaml_file(cls, filepath: str) -> 'EnhancedConfig':
        """
        Load configuration from a YAML file.
        
        Args:
            filepath: Path to the YAML file
            
        Returns:
            EnhancedConfig: The loaded configuration
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")
        
        with open(filepath, 'r') as f:
            config_data = yaml.safe_load(f)
        
        return cls(config_data)
    
    @classmethod
    def from_json_file(cls, filepath: str) -> 'EnhancedConfig':
        """
        Load configuration from a JSON file.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            EnhancedConfig: The loaded configuration
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Configuration file not found: {filepath}")
        
        with open(filepath, 'r') as f:
            config_data = json.load(f)
        
        return cls(config_data)
    
    def to_yaml_file(self, filepath: str):
        """
        Save configuration to a YAML file.
        
        Args:
            filepath: Path to save the YAML file
        """
        with open(filepath, 'w') as f:
            yaml.dump(self.config_data, f, default_flow_style=False)
    
    def to_json_file(self, filepath: str):
        """
        Save configuration to a JSON file.
        
        Args:
            filepath: Path to save the JSON file
        """
        with open(filepath, 'w') as f:
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
            "jwt"
        ],
        "disabled_pattern_categories": [
            "social"  # Example of a category to disable
        ],
        "custom_rules": [
            {
                "id": "custom_internal_tokens",
                "name": "Internal Token Detection",
                "description": "Detects internal tokens specific to your organization",
                "severity": "high",
                "variable_patterns": [
                    r"(?i)internal[_-]token",
                    r"(?i)company[_-]secret"
                ],
                "enabled_categories": ["api"]
            }
        ],
        "min_threshold": 0.7,
        "severity_threshold": "medium",
        
        # Include the standard cred-scan configuration
        "baseline_file": ".cred-scan-baseline.json",
        "exclude_patterns": [
            "vendor/",
            "node_modules/",
            ".git/"
        ],
        "output_formats": [
            "console",
            "json",
            "sarif"
        ],
        "output_directory": "./reports",
        "disable_colors": False,
        "max_workers": 4,
        "verbose": False
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
        with open(filepath, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False)
    elif format_type.lower() == "json":
        with open(filepath, 'w') as f:
            json.dump(config_data, f, indent=2)
    else:
        raise ValueError(f"Unsupported format type: {format_type}. Use 'yaml' or 'json'.")