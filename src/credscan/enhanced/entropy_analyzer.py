"""
Enhanced entropy-based analyzer with advanced secret detection capabilities.
"""

import math
import re
import base64
import binascii
from typing import Dict, Any, List, Tuple, Set, Optional
import logging
import string
from collections import Counter

logger = logging.getLogger(__name__)


class EnhancedEntropyAnalyzer:
    """
    Advanced entropy analyzer with pattern recognition and context awareness.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the enhanced entropy analyzer."""
        self.config = config or {}
        
        # Entropy thresholds for different contexts
        self.entropy_thresholds = {
            'base64': 4.5,      # Base64 encoded strings
            'hex': 3.8,         # Hexadecimal strings
            'jwt': 4.0,         # JWT tokens
            'uuid': 3.5,        # UUIDs
            'api_key': 4.2,     # API keys
            'generic': 4.0      # Generic high entropy
        }
        
        # Length constraints
        self.min_lengths = {
            'base64': 16,
            'hex': 16,
            'jwt': 36,
            'uuid': 32,
            'api_key': 20,
            'generic': 12
        }
        
        self.max_length = self.config.get('max_string_length', 200)
        
        # Compiled regex patterns for different encoding types
        self.patterns = {
            'base64': re.compile(r'^[A-Za-z0-9+/]*={0,2}$'),
            'hex': re.compile(r'^[0-9a-fA-F]+$'),
            'jwt': re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'),
            'uuid': re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
            'alphanum_mixed': re.compile(r'^[A-Za-z0-9]+$'),
        }
        
        # Known false positive patterns
        self.false_positive_patterns = {
            'common_words': {'password', 'username', 'token', 'secret', 'key', 'localhost', 'example', 'test', 'demo'},
            'file_extensions': {'.jpg', '.png', '.gif', '.pdf', '.doc', '.zip', '.tar', '.gz'},
            'urls': re.compile(r'^https?://'),
            'template_vars': re.compile(r'^\${?\w+}?$'),
            'placeholder_patterns': re.compile(r'^(xxx+|###|...|todo|fixme|changeme)$', re.IGNORECASE)
        }
        
        # Credential type indicators for context-aware analysis
        self.credential_indicators = {
            'api_key': ['api', 'key', 'apikey', 'token'],
            'password': ['pass', 'pwd', 'password', 'passwd'],
            'secret': ['secret', 'private', 'confidential'],
            'auth': ['auth', 'authorization', 'bearer'],
            'database': ['db', 'database', 'sql', 'mongo', 'redis'],
            'cloud': ['aws', 'gcp', 'azure', 'cloud']
        }
    
    def calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        
        # Count character frequencies
        counter = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def calculate_character_diversity(self, data: str) -> float:
        """Calculate character diversity score (0-1)."""
        if not data:
            return 0.0
        
        unique_chars = len(set(data))
        total_chars = len(data)
        
        return unique_chars / total_chars
    
    def detect_encoding_type(self, value: str) -> str:
        """Detect the likely encoding type of a string."""
        value = value.strip()
        
        # Check for JWT format
        if self.patterns['jwt'].match(value) and value.count('.') == 2:
            return 'jwt'
        
        # Check for UUID format
        if self.patterns['uuid'].match(value):
            return 'uuid'
        
        # Check for base64 (must be valid base64 and have reasonable length)
        if len(value) >= 16 and self.patterns['base64'].match(value):
            try:
                # Verify it's valid base64 by attempting to decode
                base64.b64decode(value, validate=True)
                return 'base64'
            except:
                pass
        
        # Check for hexadecimal
        if len(value) >= 16 and self.patterns['hex'].match(value):
            return 'hex'
        
        # Check for mixed alphanumeric (common in API keys)
        if self.patterns['alphanum_mixed'].match(value):
            return 'api_key'
        
        return 'generic'
    
    def is_false_positive(self, value: str, context: str = '') -> bool:
        """Check if a value is likely a false positive."""
        value_lower = value.lower()

        # Known non-secret high-entropy formats. These are the classic entropy
        # false positives: UUIDs, content hashes, and integrity digests are
        # random-looking but carry no credential value.
        stripped = value.strip().strip('\'"')
        # UUID (any version)
        if re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', stripped):
            return True
        # Named-algorithm integrity hash, e.g. sha256-..., sha384-..., md5-...
        if re.match(r'(?i)^(sha(1|224|256|384|512)|md5)[-:]', stripped):
            return True
        # A bare hex digest of a standard hash width (md5/sha1/sha256) with no
        # credential keyword context is far more likely a checksum than a secret.
        if re.fullmatch(r'[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', stripped):
            return True
        # Base64 that decodes to readable JSON/text config (e.g.
        # eyJ0aGVtZSI6...) is an encoded config blob, not a secret. A 2-segment
        # "eyJ" string is base64 JSON, not a 3-segment JWT.
        if stripped.startswith('eyJ') and stripped.count('.') < 2:
            try:
                decoded = base64.b64decode(stripped + '===', validate=False)
                text = decoded.decode('utf-8', errors='strict')
                if text.lstrip().startswith(('{', '[')):
                    return True
            except Exception:
                pass

        # Check common false positive words
        if value_lower in self.false_positive_patterns['common_words']:
            return True
        
        # Check for file extensions
        if any(value_lower.endswith(ext) for ext in self.false_positive_patterns['file_extensions']):
            return True
        
        # Check for URLs without credentials
        if self.false_positive_patterns['urls'].match(value) and '@' not in value:
            return True
        
        # Check for template variables
        if self.false_positive_patterns['template_vars'].match(value):
            return True
        
        # Check for placeholder patterns
        if self.false_positive_patterns['placeholder_patterns'].match(value):
            return True
        
        # Check for repeated characters (likely test data)
        if len(set(value)) <= 3 and len(value) > 8:
            return True
        
        # Check for obvious non-secret patterns
        if value.isdigit() or value.isalpha():
            return True
        
        return False
    
    def get_context_type(self, variable_name: str = '', file_path: str = '') -> str:
        """Determine the credential context type based on variable name and file path."""
        if not variable_name:
            return 'unknown'
        
        var_lower = variable_name.lower()
        path_lower = file_path.lower()
        
        # Check against credential indicators
        for cred_type, indicators in self.credential_indicators.items():
            if any(indicator in var_lower for indicator in indicators):
                return cred_type
        
        # Check file path context
        if any(term in path_lower for term in ['docker', 'k8s', 'kubernetes']):
            return 'container'
        
        if any(term in path_lower for term in ['.env', 'config', 'settings']):
            return 'config'
        
        return 'generic'
    
    def calculate_confidence_score(self, value: str, encoding_type: str, context_type: str, 
                                  entropy: float, diversity: float) -> float:
        """Calculate confidence score for a potential credential."""
        confidence = 0.0
        
        # Base confidence from entropy
        threshold = self.entropy_thresholds.get(encoding_type, self.entropy_thresholds['generic'])
        if entropy >= threshold:
            confidence += 0.4
        
        # Bonus for character diversity
        if diversity >= 0.7:
            confidence += 0.2
        
        # Bonus for appropriate length
        min_len = self.min_lengths.get(encoding_type, self.min_lengths['generic'])
        if min_len <= len(value) <= self.max_length:
            confidence += 0.1
        
        # Bonus for encoding type recognition
        if encoding_type in ['base64', 'jwt', 'hex']:
            confidence += 0.2
        
        # Bonus for context awareness
        if context_type in ['api_key', 'secret', 'auth']:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def analyze_string(self, value: str, variable_name: str = '', file_path: str = '') -> Optional[Dict[str, Any]]:
        """Analyze a single string for credential characteristics."""
        if not value or self.is_false_positive(value):
            return None
        
        # Detect encoding and context
        encoding_type = self.detect_encoding_type(value)
        context_type = self.get_context_type(variable_name, file_path)
        
        # Calculate metrics
        entropy = self.calculate_shannon_entropy(value)
        diversity = self.calculate_character_diversity(value)
        confidence = self.calculate_confidence_score(value, encoding_type, context_type, entropy, diversity)
        
        # Check if it meets the threshold for the detected encoding type
        threshold = self.entropy_thresholds.get(encoding_type, self.entropy_thresholds['generic'])
        min_len = self.min_lengths.get(encoding_type, self.min_lengths['generic'])
        
        if entropy >= threshold and len(value) >= min_len and confidence >= 0.5:
            return {
                'value': value,
                'encoding_type': encoding_type,
                'context_type': context_type,
                'entropy': round(entropy, 2),
                'diversity': round(diversity, 2),
                'confidence': round(confidence, 2),
                'length': len(value),
                'variable_name': variable_name
            }
        
        return None
    
    def analyze_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze content for high-entropy credentials."""
        findings = []
        
        # Split content into lines for analysis
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith(('#', '//', '/*')):
                continue
                
            # Extract potential credential patterns from the line
            potential_creds = self._extract_credential_candidates(line)
            
            for variable_name, value in potential_creds:
                analysis = self.analyze_string(value, variable_name, file_path)
                
                if analysis:
                    severity = self._calculate_severity(analysis['encoding_type'], analysis['confidence'])
                    
                    finding = {
                        "rule_id": f"enhanced_entropy_{analysis['encoding_type']}",
                        "rule_name": f"Enhanced Entropy Analysis ({analysis['encoding_type'].upper()})",
                        "severity": severity,
                        "type": "enhanced_entropy_match",
                        "encoding_type": analysis['encoding_type'],
                        "context_type": analysis['context_type'],
                        "variable": variable_name,
                        "value": value,
                        "entropy": analysis['entropy'],
                        "diversity": analysis['diversity'],
                        "confidence": analysis['confidence'],
                        "line": line_num,
                        "path": file_path,
                        "description": f"High entropy {analysis['encoding_type']} string detected in {analysis['context_type']} context"
                    }
                    findings.append(finding)
        
        return findings
    
    def _extract_credential_candidates(self, line: str) -> List[Tuple[str, str]]:
        """Extract potential credential key-value pairs from a line."""
        candidates = []
        
        # Common patterns for credential assignment
        patterns = [
            r'(\w+)\s*[:=]\s*["\']([^"\']+)["\']',  # key="value" or key: "value"
            r'(\w+)\s*[:=]\s*([^\s,;]+)',           # key=value or key: value
            r'export\s+(\w+)=["\']?([^"\']+)["\']?', # export KEY=value
            r'set\s+(\w+)=["\']?([^"\']+)["\']?',    # set KEY=value
            r'env\s+(\w+)\s*[:=]\s*["\']?([^"\']+)["\']?', # env KEY=value
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                variable_name, value = match.groups()
                if len(value) >= 8:  # Minimum length for potential credentials
                    candidates.append((variable_name, value))
        
        # Also look for standalone high-entropy strings
        standalone_pattern = r'["\']([A-Za-z0-9+/=_-]{16,})["\']'
        standalone_matches = re.finditer(standalone_pattern, line)
        for match in standalone_matches:
            value = match.group(1)
            candidates.append(('', value))  # No variable name for standalone strings
        
        return candidates
    
    def _calculate_severity(self, encoding_type: str, confidence: float) -> str:
        """Calculate severity based on encoding type and confidence."""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"


class EnhancedEntropyEngine:
    """Engine that integrates enhanced entropy analysis with existing scanning."""
    
    def __init__(self, base_engine, config: Dict[str, Any] = None):
        """Initialize with base engine and enhanced entropy analyzer."""
        self.base_engine = base_engine
        self.config = config or {}
        self.entropy_analyzer = EnhancedEntropyAnalyzer(config)
        
    def scan(self) -> List[Dict[str, Any]]:
        """Perform enhanced entropy-aware credential scanning."""
        # First run the base engine scan
        base_findings = self.base_engine.scan()
        
        # Then enhance with entropy analysis
        entropy_findings = []
        files_to_scan = self.base_engine.find_files()
        
        from credscan.file_cache import read_text
        for file_path in files_to_scan:
            try:
                content = read_text(file_path)
                if content is None:
                    continue

                file_findings = self.entropy_analyzer.analyze_content(content, file_path)
                entropy_findings.extend(file_findings)

            except Exception as e:
                logger.debug(f"Error scanning {file_path} with entropy analyzer: {e}")
                continue
        
        # Combine and deduplicate findings
        all_findings = base_findings + entropy_findings
        return self._deduplicate_findings(all_findings)
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings while preserving the highest confidence ones."""
        seen = set()
        deduplicated = []
        
        # Sort by confidence (highest first)
        findings.sort(key=lambda x: x.get('confidence', 0.5), reverse=True)
        
        for finding in findings:
            # Create a unique key for deduplication
            key = (finding.get('path'), finding.get('line'), finding.get('value'))
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        return deduplicated
    
    def __getattr__(self, name):
        """Delegate missing attributes to the base engine."""
        return getattr(self.base_engine, name)
    
    @property
    def parsers(self):
        """Delegate parsers property to base engine."""
        # Use the original base engine if available, otherwise use direct base
        if hasattr(self, '_base_engine'):
            return self._base_engine.parsers
        return self.base_engine.parsers
    
    def get_parser_for_file(self, filepath: str):
        """Delegate parser selection to base engine."""
        # Use the original base engine if available, otherwise use direct base
        if hasattr(self, '_base_engine'):
            return self._base_engine.get_parser_for_file(filepath)
        return self.base_engine.get_parser_for_file(filepath)
    
    def scan_file(self, filepath: str):
        """Delegate file scanning to base engine but add entropy analysis."""
        # Get base findings first
        base_findings = self.base_engine.scan_file(filepath)
        
        # Add entropy analysis
        try:
            from credscan.file_cache import read_text
            content = read_text(filepath)
            if content is None:
                return base_findings

            entropy_findings = self.entropy_analyzer.analyze_content(content, filepath)

            # Combine and deduplicate
            all_findings = base_findings + entropy_findings
            return self._deduplicate_findings(all_findings)
        except Exception as e:
            logger.debug(f"Error in enhanced entropy scan for {filepath}: {e}")
            return base_findings