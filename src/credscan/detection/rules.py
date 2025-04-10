"""
Rule system for credential detection.
"""
import re
from typing import Dict, Any, List, Pattern
import logging

logger = logging.getLogger(__name__)

class Rule:
    """
    Represents a detection rule for finding credentials.
    """
    
    def __init__(self, rule_config: Dict[str, Any]):
        """
        Initialize a rule from configuration.
        
        Args:
            rule_config: Rule definition dictionary
        """
        self.id = rule_config.get('id', 'unknown')
        self.name = rule_config.get('name', 'Unnamed Rule')
        self.description = rule_config.get('description', '')
        self.severity = rule_config.get('severity', 'medium')
        
        # Variable name patterns (for matching variable names that might contain credentials)
        self.variable_patterns = []
        for pattern in rule_config.get('variable_patterns', []):
            try:
                self.variable_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.error(f"Invalid regex in rule {self.id}: {pattern} - {e}")
        
        # Variable exclusion patterns (to exclude certain variable names)
        self.variable_exclusion_pattern = None
        if 'variable_exclusion_pattern' in rule_config and rule_config['variable_exclusion_pattern']:
            try:
                self.variable_exclusion_pattern = re.compile(
                    rule_config['variable_exclusion_pattern'], re.IGNORECASE
                )
            except re.error as e:
                logger.error(f"Invalid regex in rule {self.id} exclusion pattern: {e}")
        
        # Value patterns (for directly matching credential values)
        self.value_patterns = {}
        for pattern_def in rule_config.get('value_patterns', []):
            try:
                pattern_name = pattern_def.get('name', 'Unnamed Pattern')
                pattern_regex = pattern_def.get('pattern', '')
                if pattern_regex:
                    self.value_patterns[pattern_name] = re.compile(pattern_regex)
            except re.error as e:
                logger.error(f"Invalid regex in rule {self.id} value pattern: {pattern_def.get('pattern')} - {e}")
        
        # Value exclusion patterns (to exclude common test/default values)
        self.value_exclusion_patterns = []
        for pattern in rule_config.get('value_exclusion_patterns', []):
            try:
                self.value_exclusion_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.error(f"Invalid regex in rule {self.id} value exclusion: {pattern} - {e}")
        
        # Minimum password length to consider
        self.min_length = rule_config.get('min_length', 6)
        
        logger.debug(f"Initialized rule: {self.id} - {self.name}")
    
    def is_variable_name_match(self, var_name: str) -> bool:
        """
        Check if the variable name matches any of the suspicious patterns.
        
        Args:
            var_name: Variable name to check
            
        Returns:
            bool: True if the name matches any suspicious pattern, False otherwise
        """
        if not var_name:
            return False
            
        # Check exclusion patterns first
        if self.variable_exclusion_pattern and self.variable_exclusion_pattern.search(var_name):
            return False
            
        # Check inclusion patterns
        for pattern in self.variable_patterns:
            if pattern.search(var_name):
                return True
                
        return False
    
    def is_excluded_value(self, value: str) -> bool:
        """
        Check if the value should be excluded (test values, defaults, etc.).
        
        Args:
            value: Value to check
            
        Returns:
            bool: True if the value should be excluded, False otherwise
        """
        if not value or len(value) < self.min_length:
            return True
            
        for pattern in self.value_exclusion_patterns:
            if pattern.search(value):
                return True
                
        return False
    
    def get_value_pattern_match(self, value: str) -> Dict[str, Any]:
        """
        Check if the value directly matches any credential pattern.
        
        Args:
            value: Value to check
            
        Returns:
            Dict with match details or None if no match
        """
        if not value or len(value) < self.min_length:
            return None
            
        for pattern_name, pattern in self.value_patterns.items():
            if pattern.search(value):
                return {
                    "pattern_name": pattern_name,
                    "matched_pattern": pattern.pattern
                }
                
        return None
    
    def apply(self, parsed_content: Dict[str, Any], filepath: str) -> List[Dict[str, Any]]:
        """
        Apply the rule to parsed content.
        
        Args:
            parsed_content: Parsed file content
            filepath: Path to the file
            
        Returns:
            List of findings
        """
        findings = []
        
        # Extract items for rule processing
        items = parsed_content.get("items", [])
        
        for item in items:
            key = item.get("key")
            value = item.get("value")
            item_type = item.get("type")
            line = item.get("line", 0)
            
            # Skip items without values
            if not value:
                continue
                
            # For variable assignments, check the variable name
            if key and self.is_variable_name_match(key) and not self.is_excluded_value(value):
                findings.append({
                    "rule_id": self.id,
                    "rule_name": self.name,
                    "severity": self.severity,
                    "type": "variable_name_match",
                    "variable": key,
                    "value": value,
                    "line": line,
                    "path": filepath,
                    "description": f"Potential credential in variable '{key}'"
                })
                continue
                
            # For all values, check for direct pattern matches
            value_match = self.get_value_pattern_match(value)
            if value_match:
                findings.append({
                    "rule_id": self.id,
                    "rule_name": self.name,
                    "severity": self.severity,
                    "type": "value_pattern_match",
                    "pattern": value_match["pattern_name"],
                    "variable": key,
                    "value": value,
                    "line": line,
                    "path": filepath,
                    "description": f"Potential {value_match['pattern_name']} found"
                })
                
        return findings

class RuleLoader:
    """
    Loads and initializes detection rules from configuration.
    """
    
    @staticmethod
    def load_default_rules() -> List[Rule]:
        """
        Load a set of default detection rules.
        
        Returns:
            List of initialized Rule objects
        """
        # Define default rules
        default_rule_configs = [
            {
                "id": "sensitive_variable_names",
                "name": "Sensitive Variable Names",
                "description": "Detects variables with names suggesting they contain credentials",
                "severity": "medium",
                "variable_patterns": [
                    r"(?i)passwd|password|pass",  # Added "pass" to catch more variations
                    r"(?i)secret",
                    r"(?i)token",
                    r"(?i)apiKey|api[_-]key",
                    r"(?i)accessKey|access[_-]key",
                    r"(?i)bearer",
                    r"(?i)credentials",
                    r"(?i)db[_-]?password",  # Explicitly add database passwords
                    r"salt|SALT|Salt",
                    r"(?i)signature"
                ],
                "variable_exclusion_pattern": r"(?i)format|tokenizer|secretName|Error$|passwordPolicy|tokens$|tokenPolicy|[,\s#+*^|}{'\"[\]]|regex",
                "value_exclusion_patterns": [
                    # Fixed pattern - only exclude exact matches, not substrings
                    r"(?i)^test$|^password$|^postgres$|^root$|^foobar$|^example$|^changeme$|^default$|^master$",
                    r"(?i)^string$|^integer$|^number$|^boolean$|^xsd:.+|^literal$",
                    r"(?i)^true$|^false$",
                    r"(?i)^bearer$|^Authorization$",
                    r"bootstrapper",
                    r"\${.+\}",
                    r"(?i){{.*}}"
                ],
                "min_length": 6
            },
            {
                "id": "credential_patterns",
                "name": "Common Credential Patterns",
                "description": "Detects values matching common credential patterns",
                "severity": "high",
                "value_patterns": [
                    {
                        "name": "Postgres URI",
                        "pattern": r"postgres(?:ql)?:\/\/.+:.+@.+:.+\/.+"
                    },
                    {
                        "name": "URL With Basic Auth",
                        "pattern": r"(ftp|sftp|http|https):\/\/[a-zA-Z0-9%-]+:[a-zA-Z0-9%-]+@([a-z0-9-]{0,61}\.[a-z]{2,})"
                    },
                    {
                        "name": "JWT Token",
                        "pattern": r"eyJhbGciOiJIUzI1NiIsInR5cCI[a-zA-Z0-9_.]+"
                    },
                    {
                        "name": "Bcrypt Hash",
                        "pattern": r"^\$2[ayb]\$.{56,57}$"
                    },
                    {
                        "name": "AWS Client ID",
                        "pattern": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
                    },
                    {
                        "name": "SendGrid API Key",
                        "pattern": r"SG\.[\w_-]{16,32}\.[\w_-]{16,64}"
                    },
                    {
                        "name": "Private Key",
                        "pattern": r"-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----"
                    },
                    {
                        "name": "Google API Key",
                        "pattern": r"AIza[0-9A-Za-z\\-_]{35}"
                    }
                ],
                "value_exclusion_patterns": [
                    r"postgres(?:ql)?:\/\/.+:.+@localhost:.+\/.+",
                    r"postgres(?:ql)?:\/\/.+:.+@127.0.0.1:.+\/.+",
                    r"postgres(?:ql)?:\/\/postgres:postgres@postgres:.+\/.+"
                ],
                "min_length": 16
            }
        ]
        
        # Create and return rule objects
        rules = []
        for rule_config in default_rule_configs:
            rules.append(Rule(rule_config))
            
        return rules
    
    @staticmethod
    def load_rules_from_file(filepath: str) -> List[Rule]:
        """
        Load rules from a YAML file.
        
        Args:
            filepath: Path to the rules file
            
        Returns:
            List of initialized Rule objects
        """
        import yaml
        
        try:
            with open(filepath, 'r') as f:
                rule_configs = yaml.safe_load(f)
                
            rules = []
            for rule_config in rule_configs:
                rules.append(Rule(rule_config))
                
            return rules
                
        except Exception as e:
            logger.error(f"Error loading rules from {filepath}: {e}")
            return []
