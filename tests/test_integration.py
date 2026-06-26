# tests/test_integration.py
import os
import unittest

from credscan.enhanced.config_integration import EnhancedConfig
from credscan.enhanced.pattern_library import load_default_patterns
from credscan.enhanced.rule_engine_integration import SimpleTextParser


class TestEnhancedIntegration(unittest.TestCase):
    def test_enhanced_detection(self):
        # Load enhanced patterns
        pattern_library = load_default_patterns()

        # Debug: Check the AWS category
        print(
            f"AWS patterns loaded: {len(pattern_library.categories.get('aws', {}).patterns)}"
        )

        # Create config with AWS category enabled
        config_data = {
            "enabled_pattern_categories": ["aws"],
            "scan_path": "tests/testdata/enhanced",
            "verbose": True,  # Enable verbose logging
        }
        config = EnhancedConfig(config_data)

        # Create engine
        engine = config.create_enhanced_engine()

        engine.register_parser(SimpleTextParser(config_data))

        # Debug engine information
        print(f"Engine type: {type(engine).__name__}")
        print(f"Scan path exists: {os.path.exists('tests/testdata/enhanced')}")
        print(
            f"Test file exists: {os.path.exists('tests/testdata/enhanced/aws_credentials.txt')}"
        )

        # Run scan
        findings = engine.scan()

        # Debug output
        print(f"Found {len(findings)} findings")
        for i, finding in enumerate(findings):
            print(
                f"Finding {i+1}: {finding.get('pattern_category', 'NO CATEGORY')} - {finding.get('value', 'NO VALUE')}"
            )

        # Check if engine scanned any files
        print(f"Files found: {getattr(engine, 'files_found', 'unknown')}")
        print(f"Files scanned: {getattr(engine, 'files_scanned', 'unknown')}")

        # Verify AWS credentials were detected
        self.assertTrue(
            any(finding.get("pattern_category") == "aws" for finding in findings)
        )
