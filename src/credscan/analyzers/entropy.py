"""
Entropy-based analyzer for credential detection.
"""
import math
from typing import Dict, Any, List
import logging
import string

logger = logging.getLogger(__name__)

class EntropyAnalyzer:
    """
    Analyzer that uses Shannon entropy to detect potential credentials.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the analyzer with configuration.
        
        Args:
            config: Configuration for the analyzer
        """
        self.config = config or {}
        self.entropy_threshold = self.config.get('entropy_threshold', 4.0)
        self.min_string_length = self.config.get('min_string_length', 8)
        self.max_string_length = self.config.get('max_string_length', 120)
        self.analyze_variable_names = self.config.get('analyze_variable_names', True)
        
        # Characters that commonly appear in random strings/credentials
        self.high_entropy_chars = set(string.ascii_letters + string.digits + string.punctuation)
        
    def calculate_entropy(self, value: str) -> float:
        """
        Calculate the Shannon entropy of a string.
        
        Args:
            value: String to calculate entropy for
            
        Returns:
            float: Shannon entropy value
        """
        if not value:
            return 0.0
            
        # Filter out characters that don't contribute to high entropy
        filtered_value = ''.join(c for c in value if c in self.high_entropy_chars)
        if not filtered_value:
            return 0.0
            
        # Count character frequencies
        char_count = {}
        for char in filtered_value:
            char_count[char] = char_count.get(char, 0) + 1
            
        # Calculate entropy
        entropy = 0.0
        for count in char_count.values():
            freq = count / len(filtered_value)
            entropy -= freq * math.log2(freq)
            
        return entropy
    
    def is_potential_credential(self, value: str) -> bool:
        """
        Determine if a string is a potential credential based on entropy.
        
        Args:
            value: String to analyze
            
        Returns:
            bool: True if the string is a potential credential, False otherwise
        """
        if not value:
            return False
            
        # Check length constraints
        if len(value) < self.min_string_length or len(value) > self.max_string_length:
            return False
            
        # Some quick heuristics to exclude obvious non-credentials
        if value.lower() in ('true', 'false', 'null', 'none', 'undefined'):
            return False
            
        # Check for common URL patterns without credentials
        if value.startswith(('http://', 'https://')) and ':' not in value.split('//')[1]:
            return False
            
        # Calculate entropy
        entropy = self.calculate_entropy(value)
        
        # Higher threshold for shorter strings to reduce false positives
        adjusted_threshold = self.entropy_threshold
        if len(value) < 12:
            adjusted_threshold += 0.5
            
        return entropy >= adjusted_threshold
    
    def analyze(self, parsed_content: Dict[str, Any], filepath: str, existing_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze parsed content for high-entropy strings that might be credentials.
        
        Args:
            parsed_content: Parsed file content
            filepath: Path to the file
            existing_findings: List of findings from other analyzers or rules
            
        Returns:
            List of entropy-based findings
        """
        findings = []
        
        # Skip files with errors
        if parsed_content.get('error'):
            return findings
        
        # Get all items that might contain values
        items = parsed_content.get('items', [])
        
        # Skip values that have already been flagged by other rules
        existing_values = set()
        for finding in existing_findings:
            if 'value' in finding:
                existing_values.add(finding['value'])
        
        for item in items:
            value = item.get('value')
            key = item.get('key')
            item_type = item.get('type')
            line = item.get('line', 0)
            
            # Skip if this value has already been flagged
            if value in existing_values:
                continue
                
            # Check if the value is a potential credential based on entropy
            if value and self.is_potential_credential(value):
                context = ""
                if key:
                    context = f"in variable '{key}'"
                elif item_type:
                    context = f"in {item_type}"
                
                findings.append({
                    "rule_id": "entropy_analysis",
                    "rule_name": "High Entropy String",
                    "severity": "medium",
                    "type": "entropy_match",
                    "variable": key,
                    "value": value,
                    "entropy": round(self.calculate_entropy(value), 2),
                    "line": line,
                    "path": filepath,
                    "description": f"High entropy string detected {context} - possible credential"
                })
                
                # Add to existing_values to prevent duplicate findings
                existing_values.add(value)
        
        return findings
