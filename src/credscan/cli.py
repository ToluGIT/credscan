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
from credscan.parsers.binary_parser import BinaryFileParser
from credscan.analyzers.entropy import EntropyAnalyzer
from credscan.hooks import PreCommitScanner, install_hook
from credscan.history.scanner import HistoryScanner
from credscan.enhanced.config_integration import EnhancedConfig
from credscan.enhanced.pattern_library import load_default_patterns
from credscan.web import WebScanner, WebCrawler

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
                        help='Output format(s), comma-separated (options: console, json, sarif, excel, csv, html, pdf)')
    
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
    
    parser.add_argument('--enhanced-patterns', action='store_true', default=True,
                        help='Enable enhanced pattern detection (enabled by default)')
    parser.add_argument('--legacy-patterns', action='store_true',
                        help='Use legacy pattern detection instead of enhanced patterns')
    parser.add_argument('--pattern-library', type=str,
                        help='Path to custom pattern library file')
    parser.add_argument('--pattern-categories', type=str,
                        help='Comma-separated list of pattern categories to enable')
    parser.add_argument('--enable-tech-detection', action='store_true', default=True,
                        help='Enable technology-aware credential detection (enabled by default)')
    parser.add_argument('--disable-tech-detection', action='store_true',
                        help='Disable technology-aware credential detection')
    parser.add_argument('--tech-categories', type=str,
                        help='Comma-separated list of technology categories to focus on')
    parser.add_argument('--enable-enhanced-entropy', action='store_true', default=True,
                        help='Enable enhanced entropy-based detection (enabled by default)')
    parser.add_argument('--disable-enhanced-entropy', action='store_true',
                        help='Disable enhanced entropy-based detection')
    parser.add_argument('--entropy-threshold', type=float, default=4.0,
                        help='Base entropy threshold for credential detection (default: 4.0)')
    parser.add_argument('--enable-binary-parsing', action='store_true', default=True,
                        help='Enable binary file and archive parsing (enabled by default)')
    parser.add_argument('--disable-binary-parsing', action='store_true',
                        help='Disable binary file and archive parsing')
    
    # Context-aware detection options
    parser.add_argument('--enable-context-analysis', action='store_true', default=True,
                        help='Enable context-aware detection (enabled by default)')
    parser.add_argument('--disable-context-analysis', action='store_true',
                        help='Disable context-aware detection')
    parser.add_argument('--context-confidence-threshold', type=float, default=0.1,
                        help='Minimum confidence threshold for context filtering (default: 0.1)')
    parser.add_argument('--context-window-size', type=int, default=5,
                        help='Number of lines to analyze around findings for context (default: 5)')
    
    # Confidence scoring options
    parser.add_argument('--enable-confidence-scoring', action='store_true', default=True,
                        help='Enable advanced confidence scoring (enabled by default)')
    parser.add_argument('--disable-confidence-scoring', action='store_true',
                        help='Disable advanced confidence scoring')
    parser.add_argument('--min-confidence', type=float, default=0.3,
                        help='Minimum confidence score to report findings (default: 0.3)')
    parser.add_argument('--show-confidence-details', action='store_true',
                        help='Show detailed confidence score breakdown in output')
    parser.add_argument('--confidence-weights', type=str,
                        help='JSON string or file path with custom confidence factor weights')
    
    # Result processing options
    parser.add_argument('--enable-deduplication', action='store_true', default=True,
                        help='Enable result deduplication and grouping (enabled by default)')
    parser.add_argument('--disable-deduplication', action='store_true',
                        help='Disable result deduplication (show all individual findings)')
    parser.add_argument('--summary-mode', action='store_true',
                        help='Show concise summary instead of detailed findings')
    parser.add_argument('--show-test-credentials', action='store_true',
                        help='Include identified test/example credentials in output')
    parser.add_argument('--group-by-severity', action='store_true',
                        help='Group output by severity level')
    
    parser.add_argument('--binary-max-size', type=int, default=100,
                        help='Maximum size for binary file processing in MB (default: 100)')
    
    # Web scanning arguments
    web_group = parser.add_argument_group('Web Scanning')
    web_group.add_argument('--url', type=str,
                          help='Target URL to scan for credentials')
    web_group.add_argument('--crawl', action='store_true',
                          help='Enable web crawling to discover additional files')
    web_group.add_argument('--crawl-depth', type=int, default=2,
                          help='Maximum crawling depth (default: 2)')
    web_group.add_argument('--web-timeout', type=int, default=10,
                          help='HTTP request timeout in seconds (default: 10)')
    web_group.add_argument('--crawl-delay', type=float, default=1.0,
                          help='Delay between web requests in seconds (default: 1.0)')
    
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
    
    # Web scanning configuration
    if hasattr(args, 'url') and args.url:
        config['target_url'] = args.url
    if hasattr(args, 'crawl') and args.crawl:
        config['enable_crawling'] = args.crawl
    if hasattr(args, 'crawl_depth'):
        config['crawl_max_depth'] = args.crawl_depth
    if hasattr(args, 'web_timeout'):
        config['web_timeout'] = args.web_timeout
    if hasattr(args, 'crawl_delay'):
        config['crawl_delay'] = args.crawl_delay
    
    # Result processing and display options
    if hasattr(args, 'show_test_credentials') and args.show_test_credentials:
        config['show_test_credentials'] = True
    if hasattr(args, 'summary_mode') and args.summary_mode:
        config['summary_mode'] = True
    if hasattr(args, 'group_by_severity') and args.group_by_severity:
        config['group_by_severity'] = True
    
    return config

def patch_cli_execution(args, config, engine):
    """Update execution to use enhanced detection by default, unless legacy mode is requested."""
    from credscan.enhanced.config_integration import EnhancedConfig
    
    # Use legacy patterns only if explicitly requested
    if hasattr(args, 'legacy_patterns') and args.legacy_patterns:
        logger.info("Using legacy pattern detection")
        return engine
    
    # Default to enhanced pattern detection
    logger.info("Using enhanced pattern detection")
    
    # Create enhanced config from existing config
    enhanced_config_data = config.copy()
    
    if hasattr(args, 'pattern_library') and args.pattern_library:
        enhanced_config_data['pattern_library_path'] = args.pattern_library
        
    if hasattr(args, 'pattern_categories') and args.pattern_categories:
        enhanced_config_data['enabled_pattern_categories'] = args.pattern_categories.split(',')
        
    # Technology detection settings
    if hasattr(args, 'disable_tech_detection') and args.disable_tech_detection:
        enhanced_config_data['enable_technology_detection'] = False
    elif hasattr(args, 'enable_tech_detection'):
        enhanced_config_data['enable_technology_detection'] = args.enable_tech_detection
        
    if hasattr(args, 'tech_categories') and args.tech_categories:
        enhanced_config_data['technology_categories'] = args.tech_categories.split(',')
        
    # Enhanced entropy settings
    if hasattr(args, 'disable_enhanced_entropy') and args.disable_enhanced_entropy:
        enhanced_config_data['enable_enhanced_entropy'] = False
    elif hasattr(args, 'enable_enhanced_entropy'):
        enhanced_config_data['enable_enhanced_entropy'] = args.enable_enhanced_entropy
        
    if hasattr(args, 'entropy_threshold') and args.entropy_threshold:
        enhanced_config_data['entropy_thresholds'] = {
            'generic': args.entropy_threshold,
            'base64': args.entropy_threshold + 0.5,
            'hex': args.entropy_threshold - 0.2,
            'jwt': args.entropy_threshold,
            'api_key': args.entropy_threshold + 0.2
        }
    
    # Context-aware detection settings
    if hasattr(args, 'disable_context_analysis') and args.disable_context_analysis:
        enhanced_config_data['enable_context_analysis'] = False
    elif hasattr(args, 'enable_context_analysis'):
        enhanced_config_data['enable_context_analysis'] = args.enable_context_analysis
        
    if hasattr(args, 'context_confidence_threshold') and args.context_confidence_threshold is not None:
        enhanced_config_data['context_confidence_threshold'] = args.context_confidence_threshold
        
    if hasattr(args, 'context_window_size') and args.context_window_size:
        enhanced_config_data['context_window_size'] = args.context_window_size
    
    # Confidence scoring settings
    if hasattr(args, 'disable_confidence_scoring') and args.disable_confidence_scoring:
        enhanced_config_data['enable_confidence_scoring'] = False
    elif hasattr(args, 'enable_confidence_scoring'):
        enhanced_config_data['enable_confidence_scoring'] = args.enable_confidence_scoring
        
    if hasattr(args, 'min_confidence') and args.min_confidence is not None:
        enhanced_config_data['min_confidence_threshold'] = args.min_confidence
        
    if hasattr(args, 'show_confidence_details') and args.show_confidence_details:
        enhanced_config_data['show_confidence_details'] = True
        
    if hasattr(args, 'confidence_weights') and args.confidence_weights:
        import json
        try:
            # Try to parse as JSON string first
            if args.confidence_weights.startswith('{'):
                weights = json.loads(args.confidence_weights)
            else:
                # Try to load from file
                with open(args.confidence_weights, 'r') as f:
                    weights = json.load(f)
            enhanced_config_data['confidence_factor_weights'] = weights
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Failed to load confidence weights: {e}")
    
    # Result processing settings
    if hasattr(args, 'disable_deduplication') and args.disable_deduplication:
        enhanced_config_data['enable_deduplication'] = False
    elif hasattr(args, 'enable_deduplication'):
        enhanced_config_data['enable_deduplication'] = args.enable_deduplication
        
    if hasattr(args, 'summary_mode') and args.summary_mode:
        enhanced_config_data['summary_mode'] = True
        
    if hasattr(args, 'show_test_credentials') and args.show_test_credentials:
        enhanced_config_data['show_test_credentials'] = True
        
    if hasattr(args, 'group_by_severity') and args.group_by_severity:
        enhanced_config_data['group_by_severity'] = True
    
    # Create enhanced config and engine
    enhanced_config = EnhancedConfig(enhanced_config_data)
    base_engine = enhanced_config.create_enhanced_engine()
    
    # Wrap with context-aware engine if enabled
    if enhanced_config_data.get('enable_context_analysis', True):
        from credscan.enhanced.context_aware_engine import ContextAwareEngine
        logger.info("Enabling context-aware detection")
        return ContextAwareEngine(base_engine, enhanced_config_data)
    
    return base_engine

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
    
    # Set up logging level
    if config.get('verbose'):
        logger.setLevel(logging.DEBUG)

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
    
    # Handle web scanning if URL is provided
    if hasattr(args, 'url') and args.url:
        logger.info(f"Starting web scan on {args.url}")
        
        # Initialize web scanner and crawler
        web_scanner = WebScanner(config)
        
        findings = []
        urls_to_scan = set()
        
        # Add the main URL
        urls_to_scan.add(args.url)
        
        # Use crawler if enabled
        if hasattr(args, 'crawl') and args.crawl:
            logger.info("Crawling website for additional files...")
            web_crawler = WebCrawler(config)
            discovered_urls = web_crawler.discover_urls(args.url, use_crawling=True, use_wordlists=True)
            urls_to_scan.update(discovered_urls)
            logger.info(f"Found {len(discovered_urls)} additional URLs to scan")
        
        # Scan all discovered URLs
        logger.info(f"Scanning {len(urls_to_scan)} URLs...")
        web_findings = web_scanner.scan_urls(list(urls_to_scan))
        findings.extend(web_findings)
        
        # Generate reports
        if findings:
            # Prepare statistics for reporting
            statistics = {
                'urls_scanned': len(urls_to_scan),
                'findings_count': len(findings)
            }
            
            reporter = Reporter(config)
            reporter.report(findings, statistics)
            
            # Exit with error code if findings were found
            sys.exit(1 if findings else 0)
        else:
            logger.info("No credentials found in web scan")
            sys.exit(0)
    
    # Initialize the scanning engine
    base_engine = ScanEngine(config)
    
    # Register parsers with base engine - Binary parser first to handle archives before CodeParser treats them as text
    if not (hasattr(args, 'disable_binary_parsing') and args.disable_binary_parsing):
        binary_config = config.copy()
        if hasattr(args, 'binary_max_size'):
            binary_config['max_extraction_size'] = args.binary_max_size * 1024 * 1024  # Convert MB to bytes
        base_engine.register_parser(BinaryFileParser(binary_config))
    
    base_engine.register_parser(JSONParser(config))
    base_engine.register_parser(YAMLParser(config))
    base_engine.register_parser(CodeParser(config))
    
    # Register analyzers
    if config.get('enable_entropy', True):
        base_engine.register_analyzer(EntropyAnalyzer(config))
    
    # Apply enhanced pattern detection if enabled
    engine = patch_cli_execution(args, config, base_engine)
    
    # If enhanced pattern detection is enabled, we need to make sure parsers are available
    if not (hasattr(args, 'legacy_patterns') and args.legacy_patterns):
        # Copy parsers from base engine to enhanced engine if they're different objects
        if engine != base_engine and hasattr(base_engine, 'parsers'):
            for parser in base_engine.parsers:
                if hasattr(engine, 'register_parser'):
                    engine.register_parser(parser)
                elif hasattr(engine, 'base_engine') and hasattr(engine.base_engine, 'register_parser'):
                    engine.base_engine.register_parser(parser)
    
    # Load detection rules (only for legacy engine)
    if hasattr(args, 'legacy_patterns') and args.legacy_patterns:
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