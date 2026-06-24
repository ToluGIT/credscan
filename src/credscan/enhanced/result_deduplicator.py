"""
Result deduplication and grouping system for credential detection.
"""

import hashlib
import json
import os
import re
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class ResultDeduplicator:
    """Handles deduplication and grouping of credential detection results."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the deduplicator."""
        self.config = config or {}

        # Known test/example credentials are loaded from a data file rather than
        # hard-coded here, so that CredScan does not flag its own fixtures when
        # scanning its own source.
        self.known_test_credentials = self._load_known_test_credentials()
        
        # Test patterns to identify likely test credentials. These are matched
        # with re.search against the finding value (often a full line), so they
        # are deliberately not ^-anchored unless position matters.
        self.test_patterns = [
            r'(?i)(test|dummy|example|sample|fake|mock)',
            r'(?i)(placeholder|changeme|change[_\-]?me)',
            r'(?i)replace[_\-\s]?with',           # REPLACE_WITH_YOUR_SECRET_KEY
            r'(?i)your[_\-](api|secret|access|key|token|password)',  # your_api_key
            r'(?i)<[^>]+>',                       # <placeholder>
            r'(?i)os\.environ',                   # os.environ["KEY"] — not a value
            r'123+$',  # Ends with repeated numbers
            r'^(admin|root|user)123*$',
            r'(?i)^.*test.*$',
            r'(?i)^.*example.*$',
            r'(?i)^.*dummy.*$'
        ]
        
        # Compile patterns for efficiency
        self.compiled_test_patterns = [re.compile(pattern) for pattern in self.test_patterns]

    # Fallback set used if the data file is missing; kept minimal on purpose.
    _FALLBACK_TEST_CREDENTIALS = {
        'dummy', 'example', 'sample', 'placeholder',
        'changeme', 'default', 'password', 'admin',
    }

    def _load_known_test_credentials(self) -> Set[str]:
        """Load well-known test/example credentials from the data file."""
        from credscan.config_paths import config_file
        path = config_file('known_test_credentials.json')
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return set(data.get('values', [])) or set(self._FALLBACK_TEST_CREDENTIALS)
        except Exception as e:
            logger.debug(f"Could not load known_test_credentials.json: {e}")
            return set(self._FALLBACK_TEST_CREDENTIALS)

    def deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate findings by grouping similar detections.
        
        Args:
            findings: List of credential findings
            
        Returns:
            Deduplicated list with grouped detections
        """
        if not findings:
            return findings
        
        # Group findings by credential value and location
        grouped_findings = defaultdict(list)
        
        for finding in findings:
            # Create a unique key for grouping
            key = self._create_grouping_key(finding)
            grouped_findings[key].append(finding)
        
        # Process each group
        deduplicated = []
        for group_key, group_findings in grouped_findings.items():
            if len(group_findings) == 1:
                # Single finding, just enhance it
                enhanced_finding = self._enhance_single_finding(group_findings[0])
                deduplicated.append(enhanced_finding)
            else:
                # Multiple findings, merge them
                merged_finding = self._merge_findings(group_findings)
                deduplicated.append(merged_finding)
        
        # Sort by severity and confidence
        deduplicated.sort(key=lambda f: (
            self._severity_priority(f.get('severity', 'low')),
            f.get('overall_confidence', f.get('confidence', 0.5))
        ), reverse=True)
        
        return deduplicated
    
    def _create_grouping_key(self, finding: Dict[str, Any]) -> str:
        """Create a unique key for grouping similar findings."""
        # Use value and approximate location for grouping
        value = finding.get('value', '')
        path = finding.get('path', '')
        line = finding.get('line', 0)
        
        # Normalize value for grouping (remove quotes, whitespace)
        normalized_value = re.sub(r'["\s=:]', '', value.lower())
        
        # Create hash for consistent grouping
        key_data = f"{normalized_value}:{path}:{line//5*5}"  # Group nearby lines
        return hashlib.md5(key_data.encode()).hexdigest()[:16]
    
    def _enhance_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance a single finding with test credential detection."""
        enhanced = finding.copy()
        
        # Check if this is a test credential
        test_info = self._analyze_test_credential(finding)
        if test_info['is_test']:
            enhanced.update({
                'is_test_credential': True,
                'test_indicators': test_info['indicators'],
                'severity': self._adjust_severity_for_test(enhanced.get('severity', 'medium')),
                'test_confidence': test_info['confidence']
            })
        
        return enhanced
    
    def _merge_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple similar findings into one comprehensive result."""
        # Use the finding with highest confidence as base
        base_finding = max(findings, key=lambda f: f.get('overall_confidence', f.get('confidence', 0)))
        
        merged = base_finding.copy()
        
        # Collect all detection methods
        detection_methods = []
        rule_names = set()
        patterns = set()
        
        for finding in findings:
            rule_name = finding.get('rule_name', 'Unknown')
            pattern_name = finding.get('pattern_name', '')
            
            rule_names.add(rule_name)
            if pattern_name:
                patterns.add(pattern_name)
            
            detection_methods.append({
                'rule': rule_name,
                'pattern': pattern_name,
                'confidence': finding.get('confidence', 0.5),
                'severity': finding.get('severity', 'medium')
            })
        
        # Calculate consensus severity
        severities = [f.get('severity', 'medium') for f in findings]
        consensus_severity = self._calculate_consensus_severity(severities)
        
        # Check if this is a test credential
        test_info = self._analyze_test_credential(merged)
        
        # Update merged finding
        merged.update({
            'detection_count': len(findings),
            'detection_methods': detection_methods,
            'rule_names': list(rule_names),
            'pattern_names': list(patterns),
            'consensus_severity': consensus_severity,
            'severity': consensus_severity,
            'is_duplicate_group': True
        })
        
        if test_info['is_test']:
            merged.update({
                'is_test_credential': True,
                'test_indicators': test_info['indicators'],
                'severity': self._adjust_severity_for_test(consensus_severity),
                'test_confidence': test_info['confidence']
            })
        
        return merged
    
    def _analyze_test_credential(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze if a credential is likely a test/example credential."""
        value = finding.get('value', '')
        variable = finding.get('variable', '')
        path = finding.get('path', '').lower()

        indicators = []
        confidence = 0.0

        # A reference to a secret (env var, template var, or a bare constant
        # reference) is not itself a secret. These are the dominant false
        # positive class for keyword-based patterns, so classify them out with
        # high confidence.
        if self._is_secret_reference(value):
            indicators.append('secret_reference_not_literal')
            confidence += 0.9

        # Check against known test credentials
        clean_value = re.sub(r'["\s=:]+', '', value)
        if clean_value in self.known_test_credentials:
            indicators.append('known_test_credential')
            confidence += 0.9
        
        # Unambiguous placeholders ("replace with", "your_api_key",
        # "changeme", "<placeholder>") are definitively not secrets -- weight
        # them strongly so a single match is decisive.
        placeholder_patterns = [
            r'(?i)replace[_\-\s]?with',
            r'(?i)your[_\-](api|secret|access|key|token|password)',
            r'(?i)change[_\-]?me',
            r'(?i)placeholder',
            r'(?i)<[^>]+>',
        ]
        for pat in placeholder_patterns:
            if re.search(pat, value):
                indicators.append('placeholder_value')
                confidence += 0.9
                break

        # Check value patterns
        for pattern in self.compiled_test_patterns:
            if pattern.search(value):
                indicators.append(f'test_pattern_in_value: {pattern.pattern[:30]}...')
                confidence += 0.3
                break
        
        # Check variable name patterns
        if variable:
            for pattern in self.compiled_test_patterns:
                if pattern.search(variable):
                    indicators.append(f'test_pattern_in_variable: {pattern.pattern[:30]}...')
                    confidence += 0.2
                    break
        
        # Check file path
        test_path_indicators = ['test', 'example', 'sample', 'mock']
        for indicator in test_path_indicators:
            if indicator in path:
                indicators.append(f'test_path: {indicator}')
                confidence += 0.3
                break
        
        # Check for documentation/comment context
        description = finding.get('description', '').lower()
        if any(word in description for word in ['example', 'test', 'sample', 'demo']):
            indicators.append('test_context_in_description')
            confidence += 0.2
        
        # Check entropy (low entropy often indicates test data)
        if self._is_low_entropy(value):
            indicators.append('low_entropy_suggests_test')
            confidence += 0.1
        
        return {
            'is_test': confidence > 0.3,
            'confidence': min(confidence, 1.0),
            'indicators': indicators
        }
    
    def _is_secret_reference(self, value: str) -> bool:
        """Return True if the value is a reference to a secret, not a literal.

        Covers the dominant false-positive classes for keyword-based patterns:
        environment-variable reads, shell/CI template variables, and assignments
        whose right-hand side is another identifier (a constant reference) rather
        than a quoted literal credential.
        """
        if not value:
            return False

        # Isolate the right-hand side of a key: value or key = value pair.
        rhs = value
        m = re.search(r'[:=]\s*(.+)$', value)
        if m:
            rhs = m.group(1).strip()
        # Drop trailing inline comments.
        rhs = re.split(r'\s+#', rhs)[0].strip()

        # An env/template reference is a non-literal whether or not it is quoted
        # (e.g. password: "${DB_PASS}" or key = os.environ["X"]).
        reference_patterns = [
            r'\$\{[^}]+\}',                          # ${VAR}, ${{ secrets.X }}
            r'\$[A-Z_][A-Z0-9_]*$',                  # $VAR
            r'os\.environ',                          # os.environ[...] / .get(...)
            r'os\.getenv',                           # os.getenv(...)
            r'process\.env\.',                       # Node process.env.X
            r'System\.getenv',                       # Java
            r'ENV\[',                                # Ruby ENV['X']
            r'config\.get\(',                        # config.get('x')
            r'secrets\.',                            # GitHub Actions secrets.X
            r'vars\.',                               # CI vars.X
        ]
        for pat in reference_patterns:
            if re.search(pat, rhs, re.IGNORECASE):
                return True

        bare = rhs.rstrip(',)')

        # A value carrying a known provider prefix is a real secret, never a
        # reference -- check this FIRST so e.g. a JWT (eyJ...) with dots is not
        # mistaken for attribute access below.
        if re.match(r'(?i)(AKIA|ASIA|hf_|sk-|sk_|rk_|ghp_|gho_|ghu_|ghs_|ghr_|xox[baprs]-|AIza|glpat-|eyJ)', bare):
            return False

        # A QUOTED right-hand side is a literal value, not a reference -- do not
        # classify it here (its content is judged elsewhere).
        if re.match(r'''^["']''', rhs):
            return False

        # A code expression (function call or attribute access) is not a literal
        # secret, e.g. `match.group('key')`, `cfg.get('token')`. Require an
        # actual call `(` or index `[`, or a method chain `.name(`, so a bare
        # dotted token is not misread as code.
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*[(\[]', bare) or \
           re.match(r'^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\s*\(', bare):
            return True

        # An UNQUOTED all-caps/underscore identifier (e.g.
        # aws_access_key_id=AWS_ACCESS_KEY_ID, or =MY_CONSTANT) is a variable
        # reference, not a hardcoded literal. Require it to look like an
        # identifier WITHOUT the digit/mixed-case entropy of a real token.
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', bare) and not re.search(r'[0-9]', bare):
            return True

        return False

    def _is_low_entropy(self, value: str) -> bool:
        """Check if a value has low entropy (suggesting test data)."""
        if len(value) < 8:
            return True
        
        # Count unique characters
        unique_chars = len(set(value.lower()))
        entropy_ratio = unique_chars / len(value)
        
        # Low entropy patterns
        if entropy_ratio < 0.4:  # Less than 40% unique characters
            return True
        
        # Check for repetitive patterns
        if re.search(r'(.)\1{3,}', value):  # 4+ repeated characters
            return True
        
        if re.search(r'(12|23|34|45|56|67|78|89|90|01)+', value):  # Sequential numbers
            return True
        
        if re.search(r'(abc|def|test|example)', value.lower()):  # Common test strings
            return True
        
        return False
    
    def _adjust_severity_for_test(self, original_severity: str) -> str:
        """Adjust severity downward for test credentials."""
        severity_map = {
            'high': 'medium',
            'medium': 'low', 
            'low': 'info'
        }
        return severity_map.get(original_severity, 'info')
    
    def _calculate_consensus_severity(self, severities: List[str]) -> str:
        """Calculate consensus severity from multiple detections."""
        severity_weights = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        
        # Calculate weighted average
        total_weight = sum(severity_weights.get(s, 1) for s in severities)
        avg_weight = total_weight / len(severities)
        
        # Map back to severity
        if avg_weight >= 2.5:
            return 'high'
        elif avg_weight >= 1.5:
            return 'medium'
        elif avg_weight >= 0.5:
            return 'low'
        else:
            return 'info'
    
    def _severity_priority(self, severity: str) -> int:
        """Get numeric priority for severity (higher = more important)."""
        priorities = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        return priorities.get(severity, 1)
    
    def generate_summary(self, deduplicated_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of the deduplicated findings."""
        total_findings = len(deduplicated_findings)
        
        # Count by severity
        severity_counts = defaultdict(int)
        test_credential_count = 0
        duplicate_groups = 0
        unique_credentials = set()
        
        for finding in deduplicated_findings:
            severity = finding.get('severity', 'medium')
            severity_counts[severity] += 1
            
            if finding.get('is_test_credential'):
                test_credential_count += 1
            
            if finding.get('is_duplicate_group'):
                duplicate_groups += 1
            
            # Track unique credential values
            value = finding.get('value', '')
            clean_value = re.sub(r'["\s=:]+', '', value)
            unique_credentials.add(clean_value[:50])  # Truncate for grouping
        
        return {
            'total_findings': total_findings,
            'unique_credentials': len(unique_credentials),
            'duplicate_groups_merged': duplicate_groups,
            'test_credentials': test_credential_count,
            'severity_breakdown': dict(severity_counts),
            'production_credentials': total_findings - test_credential_count
        }