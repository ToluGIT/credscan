# src/credscan/history/scanner.py - Updated scanner

import os
import subprocess
import re
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timedelta

from credscan.core.engine import ScanEngine
from credscan.history.commit_analyzer import CommitAnalyzer
from credscan.history.result_manager import HistoryResultManager

logger = logging.getLogger(__name__)

class HistoryScanner:
    """
    Scanner for detecting credentials in git history.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the history scanner.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Get repository path from config or detect it
        self.repo_root = config.get('repo_path')
        
        # If repo_path not explicitly set, try to detect it
        if not self.repo_root:
            self.repo_root = self._get_repo_root()
            
        logger.info(f"Using git repository: {self.repo_root}")
        
        # Check if it's a valid git repository
        git_dir = os.path.join(self.repo_root, '.git')
        if not os.path.exists(git_dir):
            logger.warning(f"No .git directory found at {git_dir}")
            
        self.result_manager = HistoryResultManager()
        
        # Pass repo_root to commit analyzer
        analyzer_config = config.copy()
        analyzer_config['repo_path'] = self.repo_root
        self.commit_analyzer = CommitAnalyzer(analyzer_config)
        
        # Extract history scan configuration
        self.since = config.get('history_since')
        self.until = config.get('history_until')
        self.max_commits = config.get('history_max_commits')
        self.branch = config.get('history_branch', 'HEAD')
        self.path_filter = config.get('path')
        
    def _get_repo_root(self) -> str:
        """Get the root directory of the git repository."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error("Not in a git repository")
            return os.getcwd()
    
    def _get_commit_list(self) -> List[str]:
        """
        Get list of commits to analyze based on configuration.
        
        Returns:
            List of commit hashes
        """
        cmd = ["git", "log", "--format=%H"]
        
        # Add date range filters if specified
        if self.since:
            cmd.append(f"--since={self.since}")
        if self.until:
            cmd.append(f"--until={self.until}")
            
        # Add branch/reference
        cmd.append(self.branch)
        
        # Add path filter if specified
        if self.path_filter:
            cmd.append("--")
            cmd.append(self.path_filter)
            
        # Execute command
        try:
            # Verify we have a git repository
            git_dir = os.path.join(self.repo_root, '.git')
            if not os.path.exists(git_dir):
                logger.error(f"Git directory not found at {git_dir}")
                return []
                
            # Save current directory
            original_dir = os.getcwd()
            
            try:
                # Change to repository directory
                os.chdir(self.repo_root)
                
                logger.info(f"Running git command: {' '.join(cmd)} in {self.repo_root}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
                commits = result.stdout.strip().split('\n')
                
                # Filter empty lines
                commits = [c for c in commits if c]
                
                # Limit number of commits if specified
                if self.max_commits and len(commits) > self.max_commits:
                    logger.info(f"Limiting analysis to {self.max_commits} commits (out of {len(commits)} total)")
                    commits = commits[:self.max_commits]
                    
                return commits
            finally:
                # Change back to original directory
                os.chdir(original_dir)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting commit list: {e}")
            if e.stderr:
                logger.error(f"Git stderr: {e.stderr}")
            return []
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan git history for credentials.
        
        Returns:
            List of findings
        """
        # Get list of commits to analyze
        commits = self._get_commit_list()
        logger.info(f"Found {len(commits)} commits to analyze")
        
        if not commits:
            return []
            
        # Save current directory
        original_dir = os.getcwd()
        
        try:
            # Change to repository directory
            os.chdir(self.repo_root)
            
            # Process commits in reverse chronological order (newest first)
            total_findings = 0
            for i, commit_hash in enumerate(commits):
                logger.info(f"Analyzing commit {i+1}/{len(commits)}: {commit_hash[:8]}")
                
                # Analyze commit
                findings = self.commit_analyzer.analyze_commit(commit_hash)
                
                # Process and deduplicate findings
                unique_findings = self.result_manager.process_commit_findings(commit_hash, findings)
                
                total_findings += len(unique_findings)
                
                # Progress update every 10 commits
                if (i + 1) % 10 == 0:
                    logger.info(f"Progress: {i+1}/{len(commits)} commits analyzed, {total_findings} findings so far")
            
            # Get final results
            results = self.result_manager.get_findings()
            logger.info(f"History scan complete. Found {len(results)} unique credential exposures across {len(commits)} commits.")
            
            return results
            
        finally:
            # Change back to original directory
            os.chdir(original_dir)