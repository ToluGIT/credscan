#!/usr/bin/env python3
"""
Command-line interface for the credential scanner.
"""
import argparse
import logging
import os
import sys
import yaml
from typing import Dict, Any, List

# Import internal modules with relative imports
from credscan.core.engine import ScanEngine
from credscan.detection.rules import Rule, RuleLoader
from credscan.output.reporter import Reporter
from credscan.parsers.json_parser import JSONParser
from credscan.parsers.yaml_parser import YAMLParser
from credscan.parsers.code_parser import CodeParser
from credscan.analyzers.entropy import EntropyAnalyzer
from credscan.hooks import PreCommitScanner, install_hook
from credscan.history.scanner import HistoryScanner




# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('credscan')

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='CredScan -  Credential Scanner')
    
    parser.add_argument('--path', '-p', type=str, default='.',
                        help='Path to scan (default: current directory)')
    
    parser.add_argument('--config', '-c', type=str,
                        help='Path to configuration file')
    
    parser.add_argument('--rules', '-r', type=str,
                        help='Path to rules file')
    
    parser.add_argument('--output', '-o', type=str, default='console',
                        help='Output format(s), comma-separated (options: console, json, sarif)')
    
    parser.add_argument('--output-dir', '-d', type=str, default='.',
                        help='Output directory for reports')
    
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    
    parser.add_argument('--workers', '-w', type=int, default=os.cpu_count(),
                        help='Number of worker threads')
    
    parser.add_argument('--no-entropy', action='store_true',
                        help='Disable entropy-based detection')
    
    parser.add_argument('--min-length', type=int, default=6,
                        help='Minimum length for potential credentials')
    
    parser.add_argument('--exclude', '-e', type=str,
                        help='Exclude patterns (comma-separated)')
    
    parser.add_argument('--include', '-i', type=str,
                        help='Include only patterns (comma-separated)')
    
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    baseline_group = parser.add_argument_group('Baseline Management')
    baseline_group.add_argument('--baseline-file', type=str, 
                              help='Path to baseline file for excluding false positives')
    baseline_group.add_argument('--create-baseline', type=str, metavar='OUTPUT_FILE',
                              help='Create baseline file from scan results')
    baseline_group.add_argument('--update-baseline', action='store_true',
                              help='Update existing baseline with new findings')
    baseline_group.add_argument('--show-excluded', action='store_true',
                              help='Include baseline-excluded findings in report (marked as excluded)')
    baseline_group.add_argument('--mark-fp', type=str, metavar='FINDING_ID',
                              help='Mark a finding as false positive and add to baseline')
    baseline_group.add_argument('--exclude-pattern', type=str, 
                              help='Add a regex pattern to baseline exclusions')
    baseline_group.add_argument('--exclude-path', type=str,
                              help='Add a path pattern to baseline exclusions')
    baseline_group.add_argument('--exclusion-reason', type=str, default="Marked as false positive",
                              help='Reason for adding an exclusion')
    
    hook_group = parser.add_argument_group('Git Hook Integration')
    hook_group.add_argument('--install-hook', action='store_true',
                          help='Install CredScan as a git pre-commit hook')
    hook_group.add_argument('--hook-path', type=str,
                          help='Custom path for git hooks directory')
    hook_group.add_argument('--hook-scan', action='store_true',
                          help='Run in pre-commit hook mode (scan staged files)')
    hook_group.add_argument('--hook-config', type=str, choices=['warning-only', 'block'],
                          help='Pre-commit hook behavior (warning-only or block)')
    

    history_group = parser.add_argument_group('Git History Scanning')
    history_group.add_argument('--scan-history', action='store_true',
                              help='Scan git history for credentials')
    history_group.add_argument('--since', type=str,
                              help='Scan commits more recent than a specific date (e.g., "2 weeks ago")')
    history_group.add_argument('--until', type=str,
                              help='Scan commits older than a specific date')
    history_group.add_argument('--max-commits', type=int,
                              help='Maximum number of commits to scan')
    history_group.add_argument('--branch', type=str, default='HEAD',
                              help='Git branch to scan (default: HEAD)')

    
    return parser.parse_args()

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dict containing configuration
    """
    if not config_path:
        return {}
        
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config or {}
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return {}

def build_config_from_args(args) -> Dict[str, Any]:
    """
    Build a configuration dictionary from command-line arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Dict containing configuration
    """
    # Start with loaded config file if provided
    config = load_config(args.config)
    
    # Override with command-line arguments
    config['scan_path'] = args.path
    config['verbose'] = args.verbose
    config['max_workers'] = args.workers
    
    # Configure output formats
    output_formats = args.output.split(',')
    config['output_formats'] = output_formats
    config['output_directory'] = args.output_dir
    config['disable_colors'] = args.no_color
    
    # Set exclusion patterns
    if args.exclude:
        config['exclude_patterns'] = args.exclude.split(',')
    
    # Set inclusion patterns
    if args.include:
        config['include_patterns'] = args.include.split(',')
    
    # Configure detection settings
    if 'min_length' not in config:
        config['min_length'] = args.min_length
    
    # Configure analyzers
    config['enable_entropy'] = not args.no_entropy

    if args.baseline_file:
        config['baseline_file'] = args.baseline_file
    
    config['show_excluded'] = args.show_excluded


    # Add hook configuration
    if args.hook_config:
        config['hook_config'] = args.hook_config
    
    # Default hook behavior
    if 'hook_config' not in config:
        config['hook_config'] = 'warning-only'
    
    # Hook baseline usage
    config['hook_use_baseline'] = True

    if args.since:
        config['history_since'] = args.since
    if args.until:
        config['history_until'] = args.until
    if args.max_commits:
        config['history_max_commits'] = args.max_commits
    if args.branch:
        config['history_branch'] = args.branch
    
    return config

def main():
    """Main entry point for the command-line application."""
    # Parse command-line arguments
    args = parse_args()

    # Install hook if requested
    if args.install_hook:
        logger.info("Installing CredScan as a git pre-commit hook...")
        success = install_hook(args.hook_path)
        if success:
            logger.info("Hook installation successful.")
            
            # Create sample hook config file
            try:
                with open('.credscan-hook.conf', 'w') as f:
                    f.write("""# CredScan Hook Configuration

# Set hook behavior:
# - "warning-only": Show warnings but allow commit
# - "block": Block commits with credentials
HOOK_CONFIG="warning-only"

# Scan options:
# - Set to "true" to use the project's baseline file
USE_BASELINE="true"

# Baseline file path (relative to repository root)
BASELINE_FILE=".credscan-baseline.json"
""")
                logger.info("Created sample hook configuration in .credscan-hook.conf")
            except Exception as e:
                logger.warning(f"Could not create sample configuration: {e}")
        else:
            logger.error("Hook installation failed.")
        sys.exit(0 if success else 1)
    
    # Build configuration
    config = build_config_from_args(args)

    # Run in history scan mode if requested
    if args.scan_history:
        logger.info("Starting git history scan...")
        scanner = HistoryScanner(config)
        findings = scanner.scan()
        
        # Prepare statistics for reporting
        statistics = {
            'commits_scanned': len(scanner._get_commit_list()),
            'findings_count': len(findings)
        }
        
        # Generate reports
        reporter = Reporter(config)
        reporter.report(findings, statistics)
        
        # Return exit code based on findings
        sys.exit(1 if findings else 0)
        
    # Run in hook mode if requested
    if args.hook_scan:
        scanner = PreCommitScanner(config)
        findings = scanner.scan_staged_files()
        
        if findings:
            # Prepare statistics for reporting
            statistics = {
                'files_scanned': len(scanner.get_staged_files()),
                'findings_count': len(findings)
            }
            
            # Generate reports
            reporter = Reporter(config)
            reporter.report(findings, statistics)
            
            # Exit with error code if findings were found
            sys.exit(1)
        else:
            sys.exit(0)
    
    # Build configuration
    config = build_config_from_args(args)
    
    # Set up logging level
    if config.get('verbose'):
        logger.setLevel(logging.DEBUG)
    
    # Initialize the scanning engine
    engine = ScanEngine(config)
    
    # Register parsers
    engine.register_parser(JSONParser(config))
    engine.register_parser(YAMLParser(config))
    engine.register_parser(CodeParser(config))
    
    # Register analyzers
    if config.get('enable_entropy', True):
        engine.register_analyzer(EntropyAnalyzer(config))
    
    # Load detection rules
    if args.rules:
        rules = RuleLoader.load_rules_from_file(args.rules)
    else:
        rules = RuleLoader.load_default_rules()
    
    engine.register_rules(rules)
    
    # Run the scan
    logger.info(f"Starting credential scan on {config['scan_path']}")
    findings = engine.scan()

    # Handle baseline operations
    if args.create_baseline:
        logger.info(f"Creating baseline file at {args.create_baseline}")
        if engine.create_baseline(args.create_baseline):
            logger.info("Baseline created successfully.")
        else:
            logger.error("Failed to create baseline.")
    
    if args.mark_fp and args.baseline_file:
        for finding in findings:
            if finding.get("id") == args.mark_fp:
                if engine.update_baseline([finding], args.exclusion_reason):
                    logger.info(f"Finding {args.mark_fp} added to baseline.")
                else:
                    logger.error(f"Failed to add finding {args.mark_fp} to baseline.")
                break
        else:
            logger.error(f"Finding with ID {args.mark_fp} not found.")
    
    if args.exclude_pattern and args.baseline_file:
        if engine.baseline_manager:
            try:
                engine.baseline_manager.add_pattern_exclusion(args.exclude_pattern, args.exclusion_reason)
                engine.baseline_manager.save_baseline()
                logger.info(f"Pattern {args.exclude_pattern} added to baseline.")
            except ValueError as e:
                logger.error(f"Failed to add pattern: {e}")
    
    if args.exclude_path and args.baseline_file:
        if engine.baseline_manager:
            try:
                engine.baseline_manager.add_path_exclusion(args.exclude_path, args.exclusion_reason)
                engine.baseline_manager.save_baseline()
                logger.info(f"Path pattern {args.exclude_path} added to baseline.")
            except ValueError as e:
                logger.error(f"Failed to add path pattern: {e}")

    # Prepare statistics for reporting
    statistics = {
        'files_found': engine.files_found,
        'files_scanned': engine.files_scanned,
        'findings_count': len(findings),
        'excluded_count': len(engine.excluded_findings) if hasattr(engine, 'excluded_findings') else 0
    }
    
    # Generate reports
    reporter = Reporter(config)
    reporter.report(findings, statistics)
    
    # Return exit code based on findings
    if len(findings) > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()