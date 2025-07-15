"""
Technology-aware credential detection system.
Provides enhanced detection capabilities based on file context and technology stack.
"""

import json
import os
import re
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class TechnologyDetector:
    """Detects technology context and applies appropriate credential patterns."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the technology detector."""
        self.config = config or {}
        self.technology_patterns = self._load_technology_patterns()
        self.technology_files = self._load_technology_files()
        self.compiled_patterns = self._compile_patterns()
        
    def _load_technology_patterns(self) -> Dict[str, List[str]]:
        """Load technology-specific credential patterns."""
        try:
            config_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'config')
            patterns_file = os.path.join(config_dir, 'technology_patterns.json')
            
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load technology patterns: {e}")
        
        return {}
    
    def _load_technology_files(self) -> Dict[str, List[str]]:
        """Load technology-specific file patterns."""
        try:
            config_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'config')
            files_file = os.path.join(config_dir, 'technology_files.json')
            
            if os.path.exists(files_file):
                with open(files_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load technology files: {e}")
        
        return {}
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for each technology category."""
        compiled = {}
        
        for tech_category, patterns in self.technology_patterns.items():
            compiled[tech_category] = []
            for pattern in patterns:
                try:
                    # Create flexible regex pattern for the credential type
                    regex_pattern = rf"(?i){re.escape(pattern)}\s*[:=]\s*['\"]?([^'\"\s{{}}]+)['\"]?"
                    compiled[tech_category].append(re.compile(regex_pattern))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern for {pattern}: {e}")
        
        return compiled
    
    def detect_technology_context(self, file_path: str) -> Set[str]:
        """
        Detect which technologies are relevant for a given file.
        
        Args:
            file_path: Path to the file being scanned
            
        Returns:
            Set of technology categories that apply to this file
        """
        file_path = os.path.normpath(file_path)
        filename = os.path.basename(file_path)
        detected_technologies = set()
        
        # Check against technology-specific file patterns
        for tech_category, file_patterns in self.technology_files.items():
            for pattern in file_patterns:
                if self._matches_file_pattern(file_path, filename, pattern):
                    # Map file categories to pattern categories
                    tech_name = self._map_file_category_to_tech(tech_category)
                    if tech_name:
                        detected_technologies.add(tech_name)
        
        # Add general detection based on file extension and content
        detected_technologies.update(self._detect_from_file_extension(file_path))
        
        return detected_technologies
    
    def _matches_file_pattern(self, file_path: str, filename: str, pattern: str) -> bool:
        """Check if a file matches a specific pattern."""
        # Handle glob patterns
        if '*' in pattern:
            import fnmatch
            return fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(file_path, pattern)
        
        # Handle exact matches
        if filename == pattern:
            return True
        
        # Handle path-based matches
        if pattern in file_path:
            return True
        
        return False
    
    def _map_file_category_to_tech(self, file_category: str) -> Optional[str]:
        """Map file categories to technology pattern categories."""
        mapping = {
            'docker_files': 'Docker/Containers',
            'kubernetes_files': 'Kubernetes',
            'ci_cd_files': 'CI/CD Platforms',
            'cloud_config_files': 'Extended Cloud Platforms',
            'infrastructure_files': 'Infrastructure as Code',
            'package_manager_files': 'Package Managers',
            'framework_config_files': 'Framework Specific',
            'security_files': 'Extended SSH/Certificate',
            'monitoring_files': 'Monitoring/Observability'
        }
        return mapping.get(file_category)
    
    def _detect_from_file_extension(self, file_path: str) -> Set[str]:
        """Detect technologies based on file extension."""
        extension = Path(file_path).suffix.lower()
        detected = set()
        
        # Docker files
        if 'dockerfile' in file_path.lower() or 'docker-compose' in file_path.lower():
            detected.add('Docker/Containers')
        
        # Kubernetes files
        if extension in ['.yaml', '.yml'] and any(k8s in file_path.lower() for k8s in ['k8s', 'kubernetes', 'helm', 'kustomize']):
            detected.add('Kubernetes')
        
        # Infrastructure as Code
        if extension in ['.tf', '.tfvars', '.hcl']:
            detected.add('Infrastructure as Code')
        
        # Framework configs
        if 'config' in file_path.lower() or 'settings' in file_path.lower():
            detected.add('Framework Specific')
        
        return detected
    
    def get_relevant_patterns(self, file_path: str) -> Dict[str, List[re.Pattern]]:
        """
        Get credential patterns relevant to a specific file.
        
        Args:
            file_path: Path to the file being scanned
            
        Returns:
            Dictionary of relevant patterns organized by technology category
        """
        detected_technologies = self.detect_technology_context(file_path)
        relevant_patterns = {}
        
        # Always include general patterns as baseline
        if 'General Credentials' in self.compiled_patterns:
            relevant_patterns['General Credentials'] = self.compiled_patterns['General Credentials']
        
        # Add technology-specific patterns
        for tech in detected_technologies:
            if tech in self.compiled_patterns:
                relevant_patterns[tech] = self.compiled_patterns[tech]
        
        return relevant_patterns
    
    def scan_with_technology_context(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """
        Scan content with technology-aware patterns.
        
        Args:
            file_path: Path to the file being scanned
            content: File content to scan
            
        Returns:
            List of findings with technology context
        """
        findings = []
        relevant_patterns = self.get_relevant_patterns(file_path)
        detected_technologies = self.detect_technology_context(file_path)
        
        logger.debug(f"Scanning {file_path} with technologies: {detected_technologies}")
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Apply patterns from each relevant technology category
            for tech_category, patterns in relevant_patterns.items():
                for pattern in patterns:
                    for match in pattern.finditer(line):
                        variable_name = self._extract_variable_name(pattern.pattern)
                        value = match.group(1)
                        
                        # Skip obvious false positives
                        if self._is_false_positive(variable_name, value, line):
                            continue
                        
                        finding = {
                            "rule_id": f"tech_{tech_category.lower().replace('/', '_').replace(' ', '_')}",
                            "rule_name": f"{tech_category} Credential Detection",
                            "severity": self._calculate_severity(tech_category, variable_name, value),
                            "type": "technology_specific_credential",
                            "category": tech_category,
                            "technology_context": list(detected_technologies),
                            "variable": variable_name,
                            "value": value,
                            "line": line_num,
                            "path": file_path,
                            "description": f"Potential {tech_category.lower()} credential '{variable_name}' found",
                            "confidence": self._calculate_confidence(tech_category, variable_name, value, file_path)
                        }
                        findings.append(finding)
        
        return findings
    
    def _extract_variable_name(self, pattern: str) -> str:
        """Extract the variable name from a regex pattern."""
        # Extract the variable name from the escaped pattern
        if 'escape(' in pattern and ')' in pattern:
            start = pattern.find('escape(') + 7
            end = pattern.find(')', start)
            if start < end:
                escaped_part = pattern[start:end]
                # Remove quotes if present
                return escaped_part.strip("'\"")
        return "unknown"
    
    def _is_false_positive(self, variable_name: str, value: str, line: str) -> bool:
        """Check if a detection is likely a false positive."""
        false_positive_values = {
            'true', 'false', 'null', 'none', 'undefined', 'todo', 'fixme',
            'example', 'sample', 'test', 'demo', 'placeholder', 'changeme',
            '${', '$', '${env:', '${ENV_', '${var:', '${VAR_'
        }
        
        value_lower = value.lower()
        
        # Skip template variables and obvious placeholders
        if any(fp in value_lower for fp in false_positive_values):
            return True
        
        # Skip very short values (likely not real credentials)
        if len(value) < 8:
            return True
        
        # Skip comments
        if line.strip().startswith('#') or line.strip().startswith('//'):
            return True
        
        return False
    
    def _calculate_severity(self, tech_category: str, variable_name: str, value: str) -> str:
        """Calculate severity based on technology context and credential type."""
        # Critical severity for private keys and high-value secrets
        critical_patterns = ['private_key', 'secret_key', 'password', 'token']
        if any(pattern in variable_name.lower() for pattern in critical_patterns):
            return "critical"
        
        # High severity for CI/CD and cloud credentials
        high_severity_categories = ['CI/CD Platforms', 'Extended Cloud Platforms', 'Infrastructure as Code']
        if tech_category in high_severity_categories:
            return "high"
        
        # Medium severity for framework and database credentials
        medium_severity_categories = ['Framework Specific', 'Extended Database', 'Package Managers']
        if tech_category in medium_severity_categories:
            return "medium"
        
        return "high"  # Default to high for technology-specific findings
    
    def _calculate_confidence(self, tech_category: str, variable_name: str, value: str, file_path: str) -> float:
        """Calculate confidence score for the detection."""
        confidence = 0.7  # Base confidence
        
        # Higher confidence for technology-specific file contexts
        if tech_category != 'General Credentials':
            confidence += 0.1
        
        # Higher confidence for longer, more complex values
        if len(value) >= 32:
            confidence += 0.1
        
        # Higher confidence for specific patterns
        high_confidence_patterns = ['api_key', 'secret_key', 'private_key', 'token']
        if any(pattern in variable_name.lower() for pattern in high_confidence_patterns):
            confidence += 0.1
        
        return min(confidence, 1.0)


class TechnologyAwareEngine:
    """Engine that integrates technology detection with credential scanning."""
    
    def __init__(self, base_engine, config: Dict[str, Any] = None):
        """Initialize with a base scanning engine."""
        self.base_engine = base_engine
        self.config = config or {}
        self.tech_detector = TechnologyDetector(config)
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform technology-aware credential scanning."""
        # First run the base engine scan
        base_findings = self.base_engine.scan()
        
        # Then enhance with technology-specific patterns
        tech_findings = []
        files_to_scan = self.base_engine.find_files()
        
        for file_path in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                file_findings = self.tech_detector.scan_with_technology_context(file_path, content)
                tech_findings.extend(file_findings)
                
            except Exception as e:
                logger.debug(f"Error scanning {file_path} with technology detector: {e}")
                continue
        
        # Combine and deduplicate findings
        all_findings = base_findings + tech_findings
        return self._deduplicate_findings(all_findings)
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings while preserving the highest confidence ones."""
        seen = set()
        deduplicated = []
        
        # Sort by confidence (highest first)
        findings.sort(key=lambda x: x.get('confidence', 0.5), reverse=True)
        
        for finding in findings:
            # Create a unique key for deduplication
            key = (finding.get('path'), finding.get('line'), finding.get('variable'), finding.get('value'))
            
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
        """Delegate file scanning to base engine but add technology-aware analysis."""
        # Get base findings first
        base_findings = self.base_engine.scan_file(filepath)
        
        # Add technology-specific analysis
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            tech_findings = self.tech_detector.scan_with_technology_context(filepath, content)
            
            # Combine and deduplicate
            all_findings = base_findings + tech_findings
            return self._deduplicate_findings(all_findings)
        except Exception as e:
            logger.debug(f"Error in technology-aware scan for {filepath}: {e}")
            return base_findings