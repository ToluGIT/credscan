# src/credscan/history/diff_processor.py - Improved new file handling

import os
import subprocess
import tempfile
import logging
from typing import List, Dict, Any, Set, Optional, Tuple

from credscan.core.engine import ScanEngine
from credscan.parsers.json_parser import JSONParser
from credscan.parsers.yaml_parser import YAMLParser
from credscan.parsers.code_parser import CodeParser
from credscan.detection.rules import RuleLoader

logger = logging.getLogger(__name__)

class DiffProcessor:
    """
    Processes git diffs to extract and scan added content.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the diff processor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.repo_root = config.get('repo_path', os.getcwd())
        
        # Initialize parsers and rules
        self.parsers = [
            JSONParser(config),
            YAMLParser(config),
            CodeParser(config)
        ]
        
        self.rules = RuleLoader.load_default_rules()
        
        # Apply baseline if configured
        self.baseline_manager = None
        if config.get('baseline_file'):
            from credscan.baseline.manager import BaselineManager
            self.baseline_manager = BaselineManager(config.get('baseline_file'))
    
    def process_file_diff(self, commit_hash: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Process a single file diff to extract added content and scan for credentials.
        """
        # Save current directory
        original_dir = os.getcwd()
        
        try:
            # Change to repository directory
            os.chdir(self.repo_root)
            
            # Check if this is a newly added file or a modified file
            change_type = self._get_change_type(commit_hash, file_path)
            logger.info(f"Processing {file_path} with change type: {change_type}")
            
            if change_type == 'A':  # Added file
                # For new files, process the entire file
                added_content = self._get_file_content(commit_hash, file_path)
                if not added_content:
                    logger.warning(f"No content found for new file {file_path} in commit {commit_hash}")
                    return []
                    
                logger.debug(f"New file content first 100 chars: {added_content[:100]}")
                logger.debug(f"File content length: {len(added_content)}")
                
                # Create a temporary file with the full content
                with tempfile.NamedTemporaryFile(mode='w', suffix=os.path.splitext(file_path)[1], delete=False) as tmp_file:
                    tmp_file.write(added_content)
                    temp_path = tmp_file.name
                    logger.debug(f"Created temp file at {temp_path}")
                    
                # Create line mapping for entire file
                line_mapping = [(i+1, line) for i, line in enumerate(added_content.split('\n'))]
                logger.debug(f"Created line mapping with {len(line_mapping)} lines")
            else:
                # For modified files, get just the added lines
                added_lines = self.get_added_lines(commit_hash, file_path)
                if not added_lines:
                    logger.warning(f"No added lines found for {file_path} in commit {commit_hash}")
                    return []
                    
                logger.debug(f"Found {len(added_lines)} added lines")
                
                # Create a temporary file with the added content
                with tempfile.NamedTemporaryFile(mode='w', suffix=os.path.splitext(file_path)[1], delete=False) as tmp_file:
                    for line_num, content in added_lines:
                        tmp_file.write(f"{content}\n")
                    temp_path = tmp_file.name
                    logger.debug(f"Created temp file at {temp_path}")
                    
                line_mapping = added_lines
            
            try:
                # Find appropriate parser
                parser = self.get_parser_for_file(temp_path)
                if not parser:
                    logger.warning(f"No suitable parser found for {temp_path}")
                    os.unlink(temp_path)  # Clean up temp file
                    return []
                    
                logger.debug(f"Using parser: {parser.__class__.__name__}")
                
                # Parse the file
                parsed_content = parser.parse(temp_path)
                if not parsed_content or parsed_content.get('error'):
                    logger.warning(f"Error parsing content: {parsed_content.get('error')}")
                    os.unlink(temp_path)  # Clean up temp file
                    return []
                
                # Apply rules to find credentials
                findings = []
                for rule in self.rules:
                    rule_findings = rule.apply(parsed_content, file_path)
                    if rule_findings:
                        logger.debug(f"Rule '{rule.name}' found {len(rule_findings)} findings")
                    findings.extend(rule_findings)
                    
                # Log the findings before exclusions
                logger.debug(f"Total findings before baseline: {len(findings)}")
                for i, finding in enumerate(findings):
                    logger.debug(f"Finding {i+1}: {finding.get('variable', 'N/A')} = {finding.get('value', 'N/A')}")
                
                # Apply baseline if available
                if self.baseline_manager:
                    filtered_findings = []
                    for finding in findings:
                        exclusion = self.baseline_manager.is_excluded(finding)
                        if not exclusion.get("excluded", False):
                            filtered_findings.append(finding)
                        else:
                            logger.debug(f"Excluded finding: {finding.get('variable', 'N/A')} = {finding.get('value', 'N/A')}")
                    findings = filtered_findings
                    
                # Add original line numbers and commit info to findings
                for finding in findings:
                    # Map back from temp file to original line numbers
                    temp_line = finding.get('line', 0)
                    if temp_line > 0 and temp_line <= len(line_mapping):
                        finding['line'] = line_mapping[temp_line - 1][0]
                        
                    finding['original_file'] = file_path
                
                return findings
                
            finally:
                # Clean up temp file
                try:
                    os.unlink(temp_path)
                except:
                    pass
                    
        finally:
            # Change back to original directory
            os.chdir(original_dir)
    
    def _get_change_type(self, commit_hash: str, file_path: str) -> str:
        """
        Get the change type for a file in a commit (A=Added, M=Modified, D=Deleted).
        
        Args:
            commit_hash: Commit hash
            file_path: Path to the file
            
        Returns:
            Change type character
        """
        try:
            result = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--name-status", "-r", commit_hash, "--", file_path],
                capture_output=True,
                text=True,
                check=True
            )
            
            output = result.stdout.strip()
            if output:
                return output.split('\t')[0]  # First character is the change type
            return 'M'  # Default to modified
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting change type for {file_path} at {commit_hash}: {e}")
            return 'M'  # Default to modified
    
    def _get_file_content(self, commit_hash: str, file_path: str) -> str:
        """
        Get the entire content of a file at a specific commit.
        
        Args:
            commit_hash: Commit hash
            file_path: Path to the file
            
        Returns:
            File content as string
        """
        try:
            result = subprocess.run(
                ["git", "show", f"{commit_hash}:{file_path}"],
                capture_output=True,
                text=True,
                check=True
            )
            
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting content for {file_path} at {commit_hash}: {e}")
            return ""
    
    def get_added_lines(self, commit_hash: str, file_path: str) -> List[Tuple[int, str]]:
        """
        Extract lines added in a specific commit for a file.
        
        Args:
            commit_hash: Commit hash
            file_path: Path to the file
            
        Returns:
            List of (line_number, content) tuples for added lines
        """
        try:
            # Get the file diff
            result = subprocess.run(
                ["git", "show", "--format=", "--unified=0", f"{commit_hash}", "--", file_path],
                capture_output=True,
                text=True,
                check=True
            )
            
            diff_lines = result.stdout.split('\n')
            added_lines = []
            current_line_num = None
            
            # Process the diff output
            for line in diff_lines:
                # Look for the @@ marker which indicates line numbers
                if line.startswith('@@'):
                    # Extract line numbers using regex or simple parsing
                    parts = line.split(' ')
                    if len(parts) >= 3:
                        line_info = parts[2].lstrip('+')
                        line_parts = line_info.split(',')
                        current_line_num = int(line_parts[0])
                    continue
                    
                # Track added lines
                if line.startswith('+') and not line.startswith('+++'):
                    if current_line_num is not None:
                        # Store the line number and content (without the '+' prefix)
                        added_lines.append((current_line_num, line[1:]))
                        current_line_num += 1
                elif not line.startswith('-'):
                    # This is a context line or other non-removal line
                    if current_line_num is not None:
                        current_line_num += 1
            
            return added_lines
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting diff for {file_path} at {commit_hash}: {e}")
            return []
    
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