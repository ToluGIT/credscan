"""
Pre-commit hook functionality for CredScan.
"""
import os
import sys
import subprocess
import tempfile
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class PreCommitScanner:
    """
    Lightweight scanner for pre-commit hook integration.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the pre-commit scanner.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.repo_root = self._get_repo_root()
        
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
        except subprocess.CalledProcessError:
            # Not in a git repository
            return os.getcwd()
    
    def get_staged_files(self) -> List[str]:
        """Get list of staged files that will be committed."""
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                capture_output=True,
                text=True,
                check=True
            )
            files = result.stdout.strip().split('\n')
            # Filter out empty strings
            return [f for f in files if f]
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting staged files: {e}")
            return []
    
    def scan_staged_files(self) -> List[Dict[str, Any]]:
        """
        Scan staged files for credentials.
        
        Returns:
            List of findings
        """
        from credscan.core.engine import ScanEngine
        from credscan.parsers.json_parser import JSONParser
        from credscan.parsers.yaml_parser import YAMLParser
        from credscan.parsers.code_parser import CodeParser
        from credscan.detection.rules import RuleLoader
        
        # Get staged files
        staged_files = self.get_staged_files()
        if not staged_files:
            return []
            
        # Create temporary config for scanning only staged files
        scan_config = self.config.copy()
        
        # If baseline file is specified, use it
        if self.config.get('hook_use_baseline') and self.config.get('baseline_file'):
            scan_config['baseline_file'] = os.path.join(
                self.repo_root, self.config.get('baseline_file')
            )
        
        # Initialize scanner
        engine = ScanEngine(scan_config)
        
        # Register parsers
        engine.register_parser(JSONParser(scan_config))
        engine.register_parser(YAMLParser(scan_config))
        engine.register_parser(CodeParser(scan_config))
        
        # Load rules
        rules = RuleLoader.load_default_rules()
        engine.register_rules(rules)
        
        # Instead of scanning directories, scan individual files
        all_findings = []
        for filepath in staged_files:
            # Convert to absolute path
            abs_path = os.path.join(self.repo_root, filepath)
            if os.path.exists(abs_path) and os.path.isfile(abs_path):
                findings = engine.scan_file(abs_path)
                if findings:
                    all_findings.extend(findings)
                    
        return all_findings

def install_hook(hook_path: Optional[str] = None) -> bool:
    """
    Install the pre-commit hook script.
    
    Args:
        hook_path: Optional custom path to the hooks directory
        
    Returns:
        bool: True if successful
    """
    try:
        # Get the git hooks directory
        if hook_path:
            hooks_dir = hook_path
        else:
            repo_root = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()
            hooks_dir = os.path.join(repo_root, ".git", "hooks")
            
        # Ensure hooks directory exists
        os.makedirs(hooks_dir, exist_ok=True)
        
        # Path to the pre-commit hook
        pre_commit_path = os.path.join(hooks_dir, "pre-commit")
        
        # Check if hook already exists
        if os.path.exists(pre_commit_path):
            with open(pre_commit_path, 'r') as f:
                content = f.read()
                if "credscan --hook-scan" in content:
                    logger.info("CredScan pre-commit hook already installed.")
                    return True
                else:
                    # Backup existing hook
                    backup_path = pre_commit_path + ".bak"
                    logger.info(f"Backing up existing hook to {backup_path}")
                    os.rename(pre_commit_path, backup_path)
        
        # Create the pre-commit hook script
        with open(pre_commit_path, 'w') as f:
            f.write(PRE_COMMIT_SCRIPT)
            
        # Make the hook executable
        os.chmod(pre_commit_path, 0o755)
        
        logger.info(f"CredScan pre-commit hook installed to {pre_commit_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error installing pre-commit hook: {e}")
        return False

# Pre-commit hook script template
PRE_COMMIT_SCRIPT = """#!/usr/bin/env bash

# CredScan pre-commit hook
# Prevents committing files with credentials

# Load git hooks config if it exists
HOOK_CONFIG="warning-only"
if [ -f ".credscan-hook.conf" ]; then
    source ".credscan-hook.conf"
fi

echo "Running CredScan pre-commit hook..."

# Run credscan in hook mode
SCAN_RESULT=$(credscan --hook-scan)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "credScan detected potential credentials in your changes!"
    echo "${SCAN_RESULT}"
    
    if [ "$HOOK_CONFIG" = "warning-only" ]; then
        echo " Hook is in warning-only mode. Commit will proceed."
        echo "To block commits with credentials, set HOOK_CONFIG=block in .credscan-hook.conf"
        exit 0
    else
        echo "Commit blocked. Please remove credentials before committing."
        echo "To allow this commit, use: git commit --no-verify"
        exit 1
    fi
else
    echo "No credentials detected in staged files."
    exit 0
fi
"""
