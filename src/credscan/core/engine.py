"""
Core scanning engine for credential detection.
"""
import os
import concurrent.futures
from typing import List, Dict, Any, Set, Optional
from credscan.baseline.manager import BaselineManager
import logging

logger = logging.getLogger(__name__)

class ScanEngine:
    """
    Main engine that coordinates the credential scanning process.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the scanning engine with configuration.
        
        Args:
            config: Configuration dictionary for the scanner
        """
        self.config = config
        self.parsers = []
        self.analyzers = []
        self.rules = []
        self.results = []
        self.files_found = 0
        self.files_scanned = 0
        
        # Set up configuration
        self.max_workers = config.get('max_workers', os.cpu_count() or 4)
        self.exclude_patterns = config.get('exclude_patterns', [])
        self.include_patterns = config.get('include_patterns', [])
        self.scan_path = config.get('scan_path', '.')
        self.verbose = config.get('verbose', False)
        # Initialize baseline manager if baseline file is provided
        self.baseline_file = config.get('baseline_file')
        self.baseline_manager = None
        if self.baseline_file:
            self.baseline_manager = BaselineManager(self.baseline_file)
        
        # Track excluded findings
        self.excluded_findings = []
        
        logger.info(f"Initialized scanner with {self.max_workers} workers")
    
    def register_parser(self, parser):
        """Register a file parser with the engine."""
        self.parsers.append(parser)
        logger.debug(f"Registered parser: {parser.__class__.__name__}")
    
    def register_analyzer(self, analyzer):
        """Register an analyzer with the engine."""
        self.analyzers.append(analyzer)
        logger.debug(f"Registered analyzer: {analyzer.__class__.__name__}")
    
    def register_rules(self, rules):
        """Register detection rules with the engine."""
        self.rules.extend(rules)
        logger.debug(f"Registered {len(rules)} rules")
    
    def should_scan_file(self, filepath: str) -> bool:
        """
        Determine if a file should be scanned based on include/exclude patterns.
        
        Args:
            filepath: Path to the file
            
        Returns:
            bool: True if the file should be scanned, False otherwise
        """
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if pattern in filepath:
                logger.debug(f"Excluding file: {filepath} (matched {pattern})")
                return False
        
        # If include patterns are specified, the file must match one
        if self.include_patterns:
            for pattern in self.include_patterns:
                if pattern in filepath:
                    return True
            logger.debug(f"Excluding file: {filepath} (no include pattern match)")
            return False
        
        return True
    
    def find_files(self) -> List[str]:
        """
        Find all files to scan in the specified path.
        
        Returns:
            List[str]: List of file paths to scan
        """
        files_to_scan = []
        
        for root, dirs, files in os.walk(self.scan_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if self.should_scan_file(os.path.join(root, d))]
            
            for file in files:
                filepath = os.path.join(root, file)
                if self.should_scan_file(filepath):
                    files_to_scan.append(filepath)
        
        self.files_found = len(files_to_scan)
        logger.info(f"Found {self.files_found} files to scan")
        return files_to_scan
    
    def get_parser_for_file(self, filepath: str):
        """
        Find an appropriate parser for the given file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            Parser or None if no suitable parser is found
        """
        for parser in self.parsers:
            if parser.can_parse(filepath):
                return parser
        return None
    
    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Scan a single file for credentials.
        
        Args:
            filepath: Path to the file to scan
            
        Returns:
            List of findings
        """
        try:
            # Get appropriate parser
            parser = self.get_parser_for_file(filepath)
            if not parser:
                logger.debug(f"No parser available for {filepath}")
                return []
            
            # Parse the file
            parsed_content = parser.parse(filepath)
            if not parsed_content:
                return []
            
            findings = []
            
            # Apply rules to parsed content
            for rule in self.rules:
                rule_findings = rule.apply(parsed_content, filepath)
                findings.extend(rule_findings)
            
            # Apply analyzers for additional detection
            for analyzer in self.analyzers:
                analyzer_findings = analyzer.analyze(parsed_content, filepath, findings)
                findings.extend(analyzer_findings)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error scanning {filepath}: {e}")
            if self.verbose:
                logger.exception(e)
            return []
    
    # Modify the scan method to filter out false positives
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan all files in the specified path for credentials.
        
        Returns:
            List of findings
        """
        files_to_scan = self.find_files()
        all_findings = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(self.scan_file, f): f for f in files_to_scan}
            
            for future in concurrent.futures.as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    findings = future.result()
                    
                    # Filter out baseline exclusions if baseline manager is available
                    if findings and self.baseline_manager:
                        filtered_findings = []
                        for finding in findings:
                            exclusion = self.baseline_manager.is_excluded(finding)
                            if exclusion.get("excluded"):
                                # Add to excluded findings for reporting
                                finding["excluded"] = True
                                finding["exclusion_reason"] = exclusion.get("reason", "Unknown")
                                finding["exclusion_id"] = exclusion.get("id", "")
                                self.excluded_findings.append(finding)
                            else:
                                filtered_findings.append(finding)
                        
                        # Only add non-excluded findings to the main results
                        all_findings.extend(filtered_findings)
                    else:
                        # No baseline manager, add all findings
                        all_findings.extend(findings or [])
                    
                    self.files_scanned += 1
                    
                    # Log progress periodically
                    if self.files_scanned % 100 == 0 or self.files_scanned == self.files_found:
                        logger.info(f"Scanned {self.files_scanned}/{self.files_found} files")
                        
                except Exception as e:
                    logger.error(f"Error processing {filepath}: {e}")
        
        self.results = all_findings
        excluded_count = len(self.excluded_findings)
        total_count = len(all_findings) + excluded_count
        
        logger.info(f"Scan complete. Found {total_count} potential credentials.")
        if excluded_count > 0:
            logger.info(f"  - {excluded_count} excluded by baseline")
            logger.info(f"  - {len(all_findings)} reported")
        return all_findings

    # Add method to create a baseline from findings
    def create_baseline(self, output_file: str) -> bool:
        """
        Create a baseline file from the current scan results.
        
        Args:
            output_file: Path to save the baseline file
            
        Returns:
            bool: True if baseline was created successfully
        """
        if not self.results:
            logger.warning("No findings to create baseline from")
            return False
        
        manager = BaselineManager(output_file)
        
        # Add all current findings to the baseline
        for finding in self.results:
            manager.add_finding_exclusion(
                finding, 
                f"Auto-generated baseline for {finding.get('rule_name', 'unknown rule')}"
            )
        
        # Save the baseline file
        metadata = {
            "created_by": "credscan",
            "scan_path": self.scan_path
        }
        return manager.save_baseline(metadata)

    # Add method to update existing baseline with new findings
    def update_baseline(self, findings_to_exclude: List[Dict[str, Any]], reason: str = "User marked as false positive") -> bool:
        """
        Update the baseline with additional findings.
        
        Args:
            findings_to_exclude: List of findings to exclude
            reason: Reason for exclusion
            
        Returns:
            bool: True if baseline was updated successfully
        """
        if not self.baseline_manager:
            logger.error("No baseline file configured")
            return False
        
        for finding in findings_to_exclude:
            self.baseline_manager.add_finding_exclusion(finding, reason)
        
        return self.baseline_manager.save_baseline()
