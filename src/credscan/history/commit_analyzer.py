# src/credscan/history/commit_analyzer.py - Updated analyzer

import os
import subprocess
import tempfile
import logging
from typing import List, Dict, Any, Set

from credscan.history.diff_processor import DiffProcessor

logger = logging.getLogger(__name__)

class CommitAnalyzer:
    """
    Analyzer for detecting credentials in git commits.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the commit analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.repo_root = config.get('repo_path', os.getcwd())
        
        # Update diff processor with repo path
        diff_processor_config = config.copy()
        diff_processor_config['repo_path'] = self.repo_root
        self.diff_processor = DiffProcessor(diff_processor_config)
        
    def get_commit_info(self, commit_hash: str) -> Dict[str, Any]:
        """
        Get metadata for a specific commit.
        
        Args:
            commit_hash: The commit hash to analyze
            
        Returns:
            Dictionary with commit metadata
        """
        try:
            format_fields = [
                "%H",      # commit hash
                "%an",     # author name
                "%ae",     # author email
                "%at",     # author date (timestamp)
                "%s",      # subject (commit message first line)
            ]
            format_str = "%x00".join(format_fields)
            
            # Save current directory
            original_dir = os.getcwd()
            
            try:
                # Change to repository directory
                os.chdir(self.repo_root)
                
                result = subprocess.run(
                    ["git", "show", "-s", f"--format={format_str}", commit_hash],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Handle both null character and newline separators
                output = result.stdout.strip()
                if '\0' in output:
                    parts = output.split("\0")
                else:
                    parts = output.split("\n")
                    
                if len(parts) >= 5:
                    return {
                        "hash": parts[0],
                        "author_name": parts[1],
                        "author_email": parts[2],
                        "timestamp": int(parts[3]),
                        "message": parts[4]
                    }
                return {"hash": commit_hash}
                
            finally:
                # Change back to original directory
                os.chdir(original_dir)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting commit info for {commit_hash}: {e}")
            return {"hash": commit_hash}
    
    def analyze_commit(self, commit_hash: str) -> List[Dict[str, Any]]:
        """
        Analyze a specific commit for credentials.
        
        Args:
            commit_hash: The commit hash to analyze
            
        Returns:
            List of findings
        """
        # Save current directory
        original_dir = os.getcwd()
        
        try:
            # Change to repository directory
            os.chdir(self.repo_root)
            
            # Get commit information
            commit_info = self.get_commit_info(commit_hash)
            
            # Get changed files in commit
            changed_files = self.get_changed_files(commit_hash)
            
            all_findings = []
            
            # Process each changed file
            for file_path, change_type in changed_files:
                # Skip deleted files and binary files
                if change_type == 'D' or self.is_binary_file(file_path, commit_hash):
                    continue
                    
                # Process file changes
                findings = self.diff_processor.process_file_diff(commit_hash, file_path)
                
                # Add commit info to findings
                for finding in findings:
                    finding["commit_hash"] = commit_hash
                    finding["commit_timestamp"] = commit_info.get("timestamp", 0)
                    finding["commit_author"] = commit_info.get("author_name", "Unknown")
                    finding["commit_message"] = commit_info.get("message", "")
                    
                all_findings.extend(findings)
                
            return all_findings
            
        finally:
            # Change back to original directory
            os.chdir(original_dir)
    
    def get_changed_files(self, commit_hash: str) -> List[tuple]:
        """
        Get list of files changed in a commit with their change types.
        
        Args:
            commit_hash: The commit hash to analyze
            
        Returns:
            List of (file_path, change_type) tuples where change_type is A/M/D (added/modified/deleted)
        """
        try:
            # Execute in repository directory
            original_dir = os.getcwd()
            
            try:
                os.chdir(self.repo_root)
                
                result = subprocess.run(
                    ["git", "diff-tree", "--no-commit-id", "--name-status", "-r", commit_hash],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                changed_files = []
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue
                        
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        change_type = parts[0]
                        file_path = parts[1]
                        changed_files.append((file_path, change_type))
                
                return changed_files
                
            finally:
                os.chdir(original_dir)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting changed files for {commit_hash}: {e}")
            return []
    
    def is_binary_file(self, file_path: str, commit_hash: str) -> bool:
        """
        Check if a file is binary at a specific commit.
        
        Args:
            file_path: Path to the file
            commit_hash: Commit hash to check
            
        Returns:
            bool: True if the file is binary
        """
        try:
            # Execute in repository directory
            original_dir = os.getcwd()
            
            try:
                os.chdir(self.repo_root)
                
                result = subprocess.run(
                    ["git", "show", f"{commit_hash}:{file_path}"],
                    capture_output=True,
                    check=True
                )
                
                # Look for null bytes in the first 8KB of data
                return b'\0' in result.stdout[:8192]
                
            finally:
                os.chdir(original_dir)
                
        except subprocess.CalledProcessError:
            # If file doesn't exist, treat as non-binary
            return False