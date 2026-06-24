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
from credscan.parsers.iac_parser import IaCParser
from credscan.parsers.cicd_parser import CICDParser
from credscan.parsers.docker_parser import DockerParser
from credscan.analyzers.entropy import EntropyAnalyzer
from credscan.hooks import PreCommitScanner, install_hook
from credscan.history.scanner import HistoryScanner
from credscan.enhanced.config_integration import EnhancedConfig
from credscan.enhanced.pattern_library import load_default_patterns
# Web scanning (WebScanner/WebCrawler) is imported lazily inside the --url
# branch so the core scanner does not hard-require `requests` at startup.

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('credscan')

_EPILOG = """
examples:
  credscan                                      scan current directory
  credscan -p ./src -o json,sarif -d ./reports  scan src/, write JSON + SARIF reports
  credscan -p ./infra --group-by-severity       scan Terraform/CloudFormation, grouped output
  credscan --scan-history --max-commits 100     scan last 100 git commits
  credscan --url https://example.com/config.js  scan a web endpoint
  credscan --validate-aws -p .                  scan + verify any AWS keys found are active

exit codes:  0 = clean  |  1 = credentials found  |  2 = argument error
"""

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='CredScan — Cloud security credential scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )

    # ── Scan Target ───────────────────────────────────────────────────────────
    target = parser.add_argument_group('Scan Target')
    target.add_argument('--path', '-p', metavar='PATH', type=str, default='.',
                        help='Directory or file to scan (default: .)')
    target.add_argument('--exclude', '-e', metavar='PATTERNS', type=str,
                        help='Comma-separated path patterns to skip  e.g. "node_modules/,*.log"')
    target.add_argument('--include', '-i', metavar='PATTERNS', type=str,
                        help='Only scan paths matching these comma-separated patterns')
    target.add_argument('--staged', action='store_true',
                        help='Scan only git-staged changes (fast; for pre-commit)')
    target.add_argument('--diff', metavar='REF', type=str,
                        help='Scan only files changed vs a git ref  e.g. origin/main')
    target.add_argument('--url', metavar='URL', type=str,
                        help='Web URL to scan for credentials')
    target.add_argument('--crawl', action='store_true',
                        help='Crawl the target URL to discover additional pages')
    target.add_argument('--crawl-depth', metavar='N', type=int, default=2,
                        help='Max crawl depth (default: 2)')

    # ── Output ────────────────────────────────────────────────────────────────
    output = parser.add_argument_group('Output')
    output.add_argument('--output', '-o', metavar='FORMAT', type=str, default='console',
                        help='Report format(s): console, json, sarif, html, excel, csv, pdf, compliance  (default: console)')
    output.add_argument('--output-dir', '-d', metavar='DIR', type=str, default='.',
                        help='Directory for saved reports (default: .)')
    output.add_argument('--group-by-severity', action='store_true',
                        help='Group findings by severity (critical → high → medium → low)')
    output.add_argument('--summary-mode', action='store_true',
                        help='Print a one-line summary per file instead of full details')
    output.add_argument('--show-confidence-details', action='store_true',
                        help='Show per-factor confidence score breakdown')
    output.add_argument('--show-test-credentials', action='store_true',
                        help='Include auto-detected test/example credentials in output')
    output.add_argument('--no-color', action='store_true',
                        help='Disable ANSI colors (useful for CI logs)')
    output.add_argument('--verbose', '-v', action='store_true',
                        help='Enable debug-level logging')

    # ── Detection ─────────────────────────────────────────────────────────────
    detect = parser.add_argument_group('Detection')
    detect.add_argument('--min-confidence', metavar='SCORE', type=float, default=0.3,
                        help='Minimum confidence to report a finding, 0.0–1.0 (default: 0.3)')
    detect.add_argument('--entropy-threshold', metavar='N', type=float, default=4.0,
                        help='Shannon entropy threshold — raise to reduce false positives (default: 4.0)')
    detect.add_argument('--min-length', metavar='N', type=int, default=6,
                        help='Minimum credential value length (default: 6)')
    detect.add_argument('--no-entropy', action='store_true',
                        help='Disable all entropy-based detection')
    detect.add_argument('--no-context-analysis', action='store_true',
                        help='Disable context-aware false positive filtering')
    detect.add_argument('--no-deduplication', action='store_true',
                        help='Show every raw finding instead of grouped/deduped results')

    # ── Cloud Security ────────────────────────────────────────────────────────
    cloud = parser.add_argument_group('Cloud Security')
    cloud.add_argument('--validate-aws', action='store_true',
                       help='Verify discovered AWS keys via sts:GetCallerIdentity (read-only, opt-in)')
    cloud.add_argument('--verify', action='store_true',
                       help='Verify discovered tokens against provider identity endpoints '
                            '(GitHub/GCP/Slack/Stripe; read-only, opt-in)')

    # ── Git Integration ───────────────────────────────────────────────────────
    git = parser.add_argument_group('Git Integration')
    git.add_argument('--scan-history', action='store_true',
                     help='Scan git commit history for credentials')
    git.add_argument('--max-commits', metavar='N', type=int,
                     help='Limit history scan to the N most recent commits')
    git.add_argument('--since', metavar='DATE',
                     help='Only scan commits newer than DATE  e.g. "2 weeks ago"')
    git.add_argument('--until', metavar='DATE',
                     help='Only scan commits older than DATE')
    git.add_argument('--branch', metavar='REF', type=str, default='HEAD',
                     help='Branch or ref to scan (default: HEAD)')
    git.add_argument('--install-hook', action='store_true',
                     help='Install CredScan as a git pre-commit hook')
    git.add_argument('--hook-config', type=str, choices=['warning-only', 'block'],
                     help='Pre-commit hook mode: warn only, or block the commit')
    git.add_argument('--hook-scan', action='store_true', help=argparse.SUPPRESS)
    git.add_argument('--hook-path', type=str, help=argparse.SUPPRESS)

    # ── Baseline (False Positive Management) ─────────────────────────────────
    baseline = parser.add_argument_group('Baseline  (false positive management)')
    baseline.add_argument('--baseline-file', metavar='FILE',
                          help='Load exclusions from a baseline JSON file')
    baseline.add_argument('--create-baseline', metavar='FILE',
                          help='Write current findings to a new baseline file')
    baseline.add_argument('--show-excluded', action='store_true',
                          help='Show baseline-excluded findings (marked as excluded)')
    baseline.add_argument('--mark-fp', metavar='ID',
                          help='Mark a finding ID as false positive and add to baseline')
    baseline.add_argument('--exclusion-reason', metavar='TEXT',
                          default='Marked as false positive',
                          help='Reason stored with a baseline exclusion')
    baseline.add_argument('--exclude-pattern', metavar='REGEX', help=argparse.SUPPRESS)
    baseline.add_argument('--exclude-path', metavar='GLOB', help=argparse.SUPPRESS)
    baseline.add_argument('--update-baseline', action='store_true', help=argparse.SUPPRESS)

    # ── Advanced (hidden from default --help) ─────────────────────────────────
    adv = parser.add_argument_group(argparse.SUPPRESS)
    adv.add_argument('--config', '-c', metavar='FILE', help=argparse.SUPPRESS)
    adv.add_argument('--rules', '-r', metavar='FILE', help=argparse.SUPPRESS)
    adv.add_argument('--workers', '-w', metavar='N', type=int, default=os.cpu_count(),
                     help=argparse.SUPPRESS)
    adv.add_argument('--legacy-patterns', action='store_true', help=argparse.SUPPRESS)
    adv.add_argument('--pattern-library', metavar='FILE', help=argparse.SUPPRESS)
    adv.add_argument('--pattern-categories', metavar='LIST', help=argparse.SUPPRESS)
    adv.add_argument('--no-tech-detection', action='store_true', help=argparse.SUPPRESS)
    adv.add_argument('--tech-categories', metavar='LIST', help=argparse.SUPPRESS)
    adv.add_argument('--no-enhanced-entropy', action='store_true', help=argparse.SUPPRESS)
    adv.add_argument('--no-binary-parsing', action='store_true', help=argparse.SUPPRESS)
    adv.add_argument('--no-confidence-scoring', action='store_true', help=argparse.SUPPRESS)
    adv.add_argument('--context-confidence-threshold', metavar='N', type=float,
                     default=0.1, help=argparse.SUPPRESS)
    adv.add_argument('--context-window-size', metavar='N', type=int,
                     default=5, help=argparse.SUPPRESS)
    adv.add_argument('--confidence-weights', metavar='JSON_OR_FILE', help=argparse.SUPPRESS)
    adv.add_argument('--binary-max-size', metavar='MB', type=int,
                     default=100, help=argparse.SUPPRESS)
    adv.add_argument('--web-timeout', metavar='SEC', type=int,
                     default=10, help=argparse.SUPPRESS)
    adv.add_argument('--crawl-delay', metavar='SEC', type=float,
                     default=1.0, help=argparse.SUPPRESS)

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

    # Incremental / diff scanning: restrict to changed files via git.
    if getattr(args, 'staged', False) or getattr(args, 'diff', None):
        from credscan.diff import changed_files
        ref = getattr(args, 'diff', None)
        files = changed_files(ref, scan_path=args.path)
        config['explicit_files'] = files
        logger.info(f"Diff mode: {len(files)} changed file(s) to scan")
    
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

def build_engine(args, config, base_engine):
    """Build the scanning engine, defaulting to enhanced detection unless --legacy-patterns."""
    from credscan.enhanced.config_integration import EnhancedConfig

    if args.legacy_patterns:
        logger.info("Using legacy pattern detection")
        return base_engine

    logger.info("Using enhanced pattern detection")
    enhanced_config_data = config.copy()

    if args.pattern_library:
        enhanced_config_data['pattern_library_path'] = args.pattern_library
    if args.pattern_categories:
        enhanced_config_data['enabled_pattern_categories'] = args.pattern_categories.split(',')

    enhanced_config_data['enable_technology_detection'] = not args.no_tech_detection
    if args.tech_categories:
        enhanced_config_data['technology_categories'] = args.tech_categories.split(',')

    enhanced_config_data['enable_enhanced_entropy'] = not args.no_enhanced_entropy
    if args.entropy_threshold:
        enhanced_config_data['entropy_thresholds'] = {
            'generic': args.entropy_threshold,
            'base64': args.entropy_threshold + 0.5,
            'hex': args.entropy_threshold - 0.2,
            'jwt': args.entropy_threshold,
            'api_key': args.entropy_threshold + 0.2,
        }

    enhanced_config_data['enable_context_analysis'] = not args.no_context_analysis
    enhanced_config_data['context_confidence_threshold'] = args.context_confidence_threshold
    enhanced_config_data['context_window_size'] = args.context_window_size

    enhanced_config_data['enable_confidence_scoring'] = not args.no_confidence_scoring
    enhanced_config_data['min_confidence_threshold'] = args.min_confidence
    if args.show_confidence_details:
        enhanced_config_data['show_confidence_details'] = True
    if args.confidence_weights:
        import json
        try:
            if args.confidence_weights.startswith('{'):
                enhanced_config_data['confidence_factor_weights'] = json.loads(args.confidence_weights)
            else:
                with open(args.confidence_weights, 'r') as f:
                    enhanced_config_data['confidence_factor_weights'] = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Failed to load confidence weights: {e}")

    enhanced_config_data['enable_deduplication'] = not args.no_deduplication
    enhanced_config_data['summary_mode'] = args.summary_mode
    enhanced_config_data['show_test_credentials'] = args.show_test_credentials
    enhanced_config_data['group_by_severity'] = args.group_by_severity

    enhanced_config = EnhancedConfig(enhanced_config_data)
    engine = enhanced_config.create_enhanced_engine()

    if not args.no_context_analysis:
        from credscan.enhanced.context_aware_engine import ContextAwareEngine
        logger.info("Enabling context-aware detection")
        return ContextAwareEngine(engine, enhanced_config_data)

    return engine

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

        try:
            from credscan.web import WebScanner, WebCrawler
        except ImportError:
            logger.error("Web scanning requires the 'requests' package. "
                         "Install it with: pip install requests")
            sys.exit(2)

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
    
    # Binary parser first — handles archives before CodeParser treats them as text
    if not args.no_binary_parsing:
        binary_config = config.copy()
        binary_config['max_extraction_size'] = args.binary_max_size * 1024 * 1024
        base_engine.register_parser(BinaryFileParser(binary_config))
    
    # Specialised parsers registered before generic ones so they claim their
    # file types before CodeParser or YAMLParser.
    base_engine.register_parser(DockerParser(config))
    base_engine.register_parser(IaCParser(config))
    base_engine.register_parser(CICDParser(config))
    base_engine.register_parser(JSONParser(config))
    base_engine.register_parser(YAMLParser(config))
    base_engine.register_parser(CodeParser(config))
    
    # Register analyzers
    if config.get('enable_entropy', True):
        base_engine.register_analyzer(EntropyAnalyzer(config))
    
    engine = build_engine(args, config, base_engine)

    # Load detection rules (only for legacy engine)
    if args.legacy_patterns:
        rules = RuleLoader.load_rules_from_file(args.rules) if args.rules else RuleLoader.load_default_rules()
        engine.register_rules(rules)
    
    # Run the scan
    logger.info(f"Starting credential scan on {config['scan_path']}")
    findings = engine.scan()

    # Optionally validate discovered AWS credentials (opt-in only)
    if getattr(args, 'validate_aws', False) and findings:
        logger.info("Validating discovered AWS credentials (sts:GetCallerIdentity)...")
        from credscan.validators import AWSCredentialValidator
        validator = AWSCredentialValidator(config)
        findings = validator.enrich_findings(findings)

    # Optionally verify discovered tokens against provider endpoints (opt-in)
    if getattr(args, 'verify', False) and findings:
        logger.info("Verifying discovered tokens against provider identity endpoints...")
        from credscan.validators import TokenValidator
        token_validator = TokenValidator(config)
        findings = token_validator.enrich_findings(findings)

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