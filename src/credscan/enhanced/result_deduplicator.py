"""
Result deduplication and grouping system for credential detection.
"""

import hashlib
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
        
        # Known test/example credentials that should be marked as such
        self.known_test_credentials = {
            # AWS Examples (from AWS documentation)
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'ASIAIREXAMPLE',
            
            # Common test patterns
            'test123', 'password123', 'admin123', 'secret123',
            'dummy', 'example', 'sample', 'placeholder',
            'changeme', 'default', 'password', 'admin',
            
            # GitHub test tokens
            'ghp_1234567890abcdefghijklmnopqrstuvwxyz123456',
            
            # Slack test tokens  
            'xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx',
            
            # Common JWT test
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        }
        
        # Test patterns to identify likely test credentials
        self.test_patterns = [
            r'(?i)(test|dummy|example|sample|fake|mock|demo)',
            r'(?i)(placeholder|changeme|default)',
            r'123+$',  # Ends with repeated numbers
            r'^(admin|root|user)123*$',
            r'(?i)^.*test.*$',
            r'(?i)^.*example.*$',
            r'(?i)^.*dummy.*$'
        ]
        
        # Compile patterns for efficiency
        self.compiled_test_patterns = [re.compile(pattern) for pattern in self.test_patterns]
    
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
        
        # Check against known test credentials
        clean_value = re.sub(r'["\s=:]+', '', value)
        if clean_value in self.known_test_credentials:
            indicators.append('known_test_credential')
            confidence += 0.9
        
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
        test_path_indicators = ['test', 'example', 'sample', 'demo', 'mock']
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