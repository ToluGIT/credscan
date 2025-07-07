"""
Unit tests for the enhanced pattern library and rule integration.
"""

import os
import unittest
import tempfile
import json
import yaml
from unittest.mock import patch, MagicMock

# Import the modules to test
from credscan.enhanced.pattern_structure import PatternLibrary, PatternCategory, CredentialPattern
from credscan.enhanced.pattern_library import load_default_patterns, save_patterns_to_file, load_patterns_from_file
from credscan.enhanced.rule_engine_integration import EnhancedRule, EnhancedRuleLoader
from credscan.enhanced.config_integration import EnhancedConfig, get_example_config


class TestPatternStructure(unittest.TestCase):
    """Tests for the pattern structure module."""
    
    def test_credential_pattern_initialization(self):
        """Test that a CredentialPattern can be properly initialized."""
        pattern = CredentialPattern(
            name="Test Pattern",
            pattern=r"test-[0-9]+",
            description="Test description",
            severity="medium"
        )
        
        self.assertEqual(pattern.name, "Test Pattern")
        self.assertEqual(pattern.pattern, r"test-[0-9]+")
        self.assertEqual(pattern.description, "Test description")
        self.assertEqual(pattern.severity, "medium")
        self.assertIsNotNone(pattern.compiled_pattern)
    
    def test_credential_pattern_matching(self):
        """Test that a CredentialPattern correctly matches values."""
        pattern = CredentialPattern(
            name="JWT Token",
            pattern=r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        )
        
        # Should match
        self.assertTrue(pattern.matches("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"))
        
        # Should not match
        self.assertFalse(pattern.matches("not-a-jwt-token"))
        self.assertFalse(pattern.matches(""))
        self.assertFalse(pattern.matches(None))
    
    def test_pattern_category(self):
        """Test that a PatternCategory can be properly created and used."""
        category = PatternCategory(
            name="test_category",
            description="Test category"
        )
        
        pattern1 = CredentialPattern(name="Pattern 1", pattern=r"test1-[0-9]+")
        pattern2 = CredentialPattern(name="Pattern 2", pattern=r"test2-[0-9]+")
        
        category.add_pattern(pattern1)
        category.add_pattern(pattern2)
        
        self.assertEqual(len(category.patterns), 2)
        
        # Test matching
        matches = category.check_value("test1-123")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].name, "Pattern 1")
        
        matches = category.check_value("test2-456")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].name, "Pattern 2")
        
        matches = category.check_value("no-match")
        self.assertEqual(len(matches), 0)
        
        # Test with disabled category
        category.enabled = False
        matches = category.check_value("test1-123")
        self.assertEqual(len(matches), 0)
    
    def test_pattern_library(self):
        """Test that a PatternLibrary can be properly created and used."""
        library = PatternLibrary()
        
        # Create categories
        category1 = PatternCategory(name="category1", description="Category 1")
        category1.add_pattern(CredentialPattern(name="Pattern 1", pattern=r"cat1-[0-9]+"))
        
        category2 = PatternCategory(name="category2", description="Category 2")
        category2.add_pattern(CredentialPattern(name="Pattern 2", pattern=r"cat2-[0-9]+"))
        
        # Add to library
        library.add_category(category1)
        library.add_category(category2)
        
        self.assertEqual(len(library.categories), 2)
        self.assertEqual(len(library.enabled_categories), 2)
        
        # Test matching
        matches = library.check_value("cat1-123")
        self.assertEqual(len(matches), 1)
        self.assertEqual(list(matches.keys())[0], "category1")
        
        # Test disable category
        library.disable_category("category1")
        matches = library.check_value("cat1-123")
        self.assertEqual(len(matches), 0)
        
        matches = library.check_value("cat2-456")
        self.assertEqual(len(matches), 1)
        
        # Test get all patterns
        all_patterns = library.get_all_patterns()
        self.assertEqual(len(all_patterns), 2)


class TestPatternLibrary(unittest.TestCase):
    """Tests for the pattern library module."""
    
    def test_load_default_patterns(self):
        """Test that default patterns can be loaded."""
        library = load_default_patterns()
        
        self.assertIsInstance(library, PatternLibrary)
        self.assertGreater(len(library.categories), 0)
        self.assertGreater(len(library.get_all_patterns()), 0)
    
    def test_save_and_load_patterns(self):
        """Test that patterns can be saved to a file and loaded back."""
        library = PatternLibrary()
        
        # Create a test category
        category = PatternCategory(name="test", description="Test Category")
        category.add_pattern(CredentialPattern(name="Test Pattern", pattern=r"test-[0-9]+"))
        library.add_category(category)
        
        # Save to temporary files
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as json_file:
            json_path = json_file.name
        
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as yaml_file:
            yaml_path = yaml_file.name
        
        try:
            # Test JSON save/load
            save_patterns_to_file(library, json_path)
            loaded_library = load_patterns_from_file(json_path)
            
            self.assertEqual(len(loaded_library.categories), 1)
            self.assertEqual(loaded_library.categories["test"].name, "test")
            self.assertEqual(len(loaded_library.categories["test"].patterns), 1)
            
            # Test YAML save/load
            save_patterns_to_file(library, yaml_path)
            loaded_library = load_patterns_from_file(yaml_path)
            
            self.assertEqual(len(loaded_library.categories), 1)
            self.assertEqual(loaded_library.categories["test"].name, "test")
            self.assertEqual(len(loaded_library.categories["test"].patterns), 1)
            
        finally:
            # Clean up temporary files
            os.unlink(json_path)
            os.unlink(yaml_path)


class TestRuleEngineIntegration(unittest.TestCase):
    """Tests for the rule engine integration."""
    
    def test_enhanced_rule(self):
        """Test that an EnhancedRule can be properly created and used."""
        # Create a simple pattern library
        library = PatternLibrary()
        category = PatternCategory(name="test", description="Test Category")
        category.add_pattern(CredentialPattern(name="Test Pattern", pattern=r"secret-[0-9]+"))
        library.add_category(category)
        
        # Create a rule using this library
        rule_config = {
            "id": "test_rule",
            "name": "Test Rule",
            "description": "A test rule",
            "severity": "medium",
            "enabled_categories": ["test"]
        }
        
        rule = EnhancedRule(rule_config, library)
        
        # Mock parsed content
        parsed_content = {
            "items": [
                {
                    "key": "api_key",
                    "value": "secret-12345",
                    "line": 10
                }
            ]
        }
        
        # Apply the rule
        findings = rule.apply(parsed_content, "test_file.py")
        
        # There should be a finding
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "test_rule")
        self.assertEqual(findings[0]["pattern"], "Test Pattern")
        self.assertEqual(findings[0]["line"], 10)
        self.assertEqual(findings[0]["path"], "test_file.py")
    
    def test_enhanced_rule_loader(self):
        """Test that the EnhancedRuleLoader can load default rules."""
        # Create a simple pattern library
        library = PatternLibrary()
        category = PatternCategory(name="aws", description="AWS")
        category.add_pattern(CredentialPattern(name="AWS Key", pattern=r"AKIA[0-9A-Z]{16}"))
        library.add_category(category)
        
        # Load rules
        rules = EnhancedRuleLoader.load_default_rules(library)
        
        # There should be rules
        self.assertGreater(len(rules), 0)
        
        # At least one rule should have the aws category enabled
        found_aws_rule = False
        for rule in rules:
            if "aws" in rule.enabled_categories:
                found_aws_rule = True
                break
        
        self.assertTrue(found_aws_rule)


class TestConfigIntegration(unittest.TestCase):
    """Tests for the configuration integration."""
    
    def test_enhanced_config(self):
        """Test that an EnhancedConfig can be properly created and used."""
        config_data = {
            "pattern_library_path": None,
            "enabled_pattern_categories": ["aws", "database"],
            "disabled_pattern_categories": ["social"],
            "custom_rules": [],
            "min_threshold": 0.8,
            "severity_threshold": "high"
        }
        
        config = EnhancedConfig(config_data)
        
        self.assertEqual(config.min_threshold, 0.8)
        self.assertEqual(config.severity_threshold, "high")
        self.assertEqual(config.enabled_categories, {"aws", "database"})
        self.assertEqual(config.disabled_categories, {"social"})
    
    def test_config_save_load(self):
        """Test that configuration can be saved and loaded."""
        config_data = get_example_config()
        config = EnhancedConfig(config_data)
        
        # Save to temporary files
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as json_file:
            json_path = json_file.name
        
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as yaml_file:
            yaml_path = yaml_file.name
        
        try:
            # Test JSON save/load
            config.to_json_file(json_path)
            loaded_config = EnhancedConfig.from_json_file(json_path)
            
            self.assertEqual(loaded_config.min_threshold, config.min_threshold)
            self.assertEqual(loaded_config.enabled_categories, config.enabled_categories)
            
            # Test YAML save/load
            config.to_yaml_file(yaml_path)
            loaded_config = EnhancedConfig.from_yaml_file(yaml_path)
            
            self.assertEqual(loaded_config.min_threshold, config.min_threshold)
            self.assertEqual(loaded_config.enabled_categories, config.enabled_categories)
            
        finally:
            # Clean up temporary files
            os.unlink(json_path)
            os.unlink(yaml_path)
    
    @patch('credscan.enhanced.rule_engine_integration.EnhancedScanEngine')
    def test_create_enhanced_engine(self, mock_engine_class):
        """Test that an enhanced engine can be created from config."""
        mock_engine = MagicMock()
        mock_engine_class.return_value = mock_engine
        
        config_data = get_example_config()
        config = EnhancedConfig(config_data)
        
        engine = config.create_enhanced_engine()
        
        # The engine should have been created
        mock_engine_class.assert_called_once_with(config_data)
        
        # Rules should have been registered
        self.assertTrue(mock_engine.register_rules.called)


if __name__ == '__main__':
    unittest.main()
