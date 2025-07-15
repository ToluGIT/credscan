# CredScan

CredScan is a credential and secret detection tool designed to identify sensitive information in codebases. It provides advanced pattern matching, context-aware analysis, and intelligent filtering to help security teams and developers detect credentials, API keys, tokens, and other secrets that may have been accidentally committed.

## Core Features

### Detection Capabilities
- **Enhanced pattern matching**: Uses a library of patterns for detecting credentials across major cloud providers, services, and frameworks
- **Context-aware analysis**: Evaluates the surrounding code context to reduce false positives and assess risk levels
- **Technology-specific detection**: Applies specialized patterns based on detected technologies (Docker, Kubernetes, CI/CD platforms, etc.)
- **Multi-factor confidence scoring**: Combines pattern matching, context analysis, entropy assessment, and technology context for accurate detection
- **Entropy analysis**: Identifies high-entropy strings with configurable thresholds for different credential types
- **Test credential identification**: Automatically identifies and filters example/test credentials to reduce noise

### File Support
- **Multi-format scanning**: Supports JSON, YAML, code files (Python, JavaScript, Java, Go, etc.), configuration files, and more
- **Binary file analysis**: Extracts and scans contents from archives (ZIP, TAR, JAR) and container images
- **Web content scanning**: Direct scanning of web pages and APIs with optional crawling capabilities

### Git Integration
- **History scanning**: Examines commit history for credentials that may have been previously committed and removed
- **Pre-commit hook integration**: Prevents accidental credential commits with configurable blocking or warning modes
- **Baseline management**: Maintains exclusion lists to reduce false positives while tracking legitimate findings

### Output and Reporting
- **Multiple output formats**: Console (with colors), JSON, SARIF, Excel, CSV, HTML, and PDF reports
- **Intelligent deduplication**: Groups similar detections and eliminates duplicate findings
- **Risk-based prioritization**: Categorizes findings by severity and confidence levels
- **Technology context reporting**: Shows detected technologies and associated risk levels

## Installation

```bash
# Install from source
git clone https://github.com/ToluGIT/credscan.git
cd credscan
pip install -e .

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Basic scan of current directory
credscan

# Scan specific path with detection
credscan --path /path/to/scan

# Show detailed confidence analysis
credscan --path /path/to/scan --show-confidence-details

# Include test credentials in output
credscan --path /path/to/scan --show-test-credentials
```

## Configuration Options

### Detection Settings

```bash
# Enable/disable specific detection methods
credscan --disable-enhanced-entropy          # Disable entropy analysis
credscan --disable-context-analysis          # Disable context awareness
credscan --disable-tech-detection            # Disable technology detection
credscan --no-entropy                        # Disable basic entropy analysis

# Adjust detection thresholds
credscan --entropy-threshold 4.5             # Set entropy threshold
credscan --min-confidence 0.7                # Set minimum confidence score
credscan --context-confidence-threshold 0.2  # Set context filtering threshold
credscan --min-length 8                      # Minimum credential length

# Advanced confidence configuration
credscan --show-confidence-details           # Show detailed confidence breakdown
credscan --confidence-weights weights.json   # Custom confidence factor weights
```

### Output Control

```bash
# Control result processing
credscan --disable-deduplication             # Show all individual findings
credscan --summary-mode                      # Show concise summary
credscan --group-by-severity                 # Group output by severity level

# Output formats and directories
credscan --output json,sarif,excel           # Multiple formats
credscan --output-dir ./security-reports     # Custom output directory
credscan --no-color                          # Disable colored output

# File filtering
credscan --exclude "node_modules/,*.log"     # Exclude patterns
credscan --include "src/,config/"            # Include only these patterns
```

### Technology-Specific Scanning

```bash
# Focus on specific technologies
credscan --tech-categories "Docker/Containers,Kubernetes,CI/CD Platforms"

# Pattern configuration
credscan --pattern-library ./custom-patterns.json
credscan --pattern-categories "cloud,api,database"
credscan --legacy-patterns                   # Use legacy detection patterns

# Binary file handling
credscan --disable-binary-parsing            # Skip binary file analysis
credscan --binary-max-size 50                # Max binary file size in MB
```

## Advanced Usage

### Git History Analysis

Scan repository history to find credentials that were previously committed:

```bash
# Scan entire git history
credscan --scan-history

# Scan recent commits
credscan --scan-history --since "1 month ago" --until "1 week ago"

# Scan specific branch with commit limit
credscan --scan-history --branch develop --max-commits 100
```

### Pre-commit Hook Setup

Prevent credential leakage by installing automated scanning:

```bash
# Install pre-commit hook
credscan --install-hook

# Configure hook behavior (creates .credscan-hook.conf)
# Options: "warning-only" or "block"
```

The hook configuration file supports:
```bash
# Hook behavior: "warning-only" or "block"
HOOK_CONFIG="warning-only"

# Use project baseline file
USE_BASELINE="true"
BASELINE_FILE=".credscan-baseline.json"
```

### Baseline Management

Manage false positives and maintain scan accuracy:

```bash
# Create baseline from current scan
credscan --create-baseline .credscan-baseline.json

# Use baseline to filter known false positives
credscan --baseline-file .credscan-baseline.json

# Show excluded findings
credscan --baseline-file .credscan-baseline.json --show-excluded

# Add specific exclusions
credscan --exclude-pattern "test_.*_key" --exclusion-reason "Test patterns"
credscan --exclude-path "tests/" --exclusion-reason "Test directory"
```

### Web Scanning

Scan web applications and APIs for exposed credentials:

```bash
# Scan single URL
credscan --url https://example.com/api/config

# Scan with crawling
credscan --url https://example.com --crawl --crawl-depth 3

# Configure request behavior
credscan --url https://example.com --web-timeout 30 --crawl-delay 2.0
```

## Configuration File

Create `config.yaml` for complex setups:

```yaml
# Core scanning options
scan_path: "."
max_workers: 8
verbose: true
min_length: 8

# File filtering
exclude_patterns:
  - "vendor/"
  - "node_modules/"
  - ".git/"
  - "*.log"

include_patterns:
  - "src/"
  - "config/"

# Detection configuration
min_length: 8
entropy_threshold: 4.0
enable_enhanced_entropy: true
enable_context_analysis: true
enable_technology_detection: true

# Confidence scoring
min_confidence_threshold: 0.3
confidence_factor_weights:
  pattern_match: 0.30
  context: 0.25
  entropy: 0.20
  technology: 0.15
  environment: 0.05
  validation: 0.05

# Output settings
output_formats:
  - "console"
  - "json"
  - "sarif"
output_directory: "./reports"
disable_colors: false
show_confidence_details: true
enable_deduplication: true
group_by_severity: false
show_test_credentials: false

# Baseline configuration
baseline_file: ".credscan-baseline.json"
show_excluded: false
```

## Understanding Output

CredScan provides detailed analysis of each finding:

```
=== Credential Scan Results ===

Files found: 15
Files scanned: 15
Credentials found: 8

Note: 3 test/example credentials filtered out (use --show-test-credentials to see them)

 File: src/config/database.py 

[HIGH] Enhanced Pattern: AWS Access Key
  Line: 12
  Variable: AWS_ACCESS_KEY_ID
  Value: AKIA1234567890ABCDEF
  Detects aws_access_key_id credentials in production environment configuration [HIGH RISK]
  Overall Confidence: 0.876
  • Pattern matching confidence: 0.95 (weight: 0.30, contribution: 0.285)
  • Context analysis confidence (security_config, high risk): 0.85 (weight: 0.25, contribution: 0.213)
  • Technology confidence (Cloud Platforms): 0.80 (weight: 0.15, contribution: 0.120)
  Context: security_config (high risk)

[MEDIUM] Enhanced Entropy Analysis (GENERIC) (2 detections grouped)
  Detection methods: Enhanced Entropy Analysis, Enhanced Pattern
  Line: 15
  Variable: database_password
  Value: "p4$$w0rd_c0mpl3x_2024!"
  High entropy string detected in database configuration context [MEDIUM RISK]
  Overall Confidence: 0.742
  Context: database_credentials (medium risk)

Summary: 8 potential credential(s) found.
High severity: 3
Medium severity: 4
Low severity: 1
```

### Key Output Elements

- **Technology Context**: Shows detected technologies and associated risk levels
- **Confidence Scoring**: Multi-factor confidence assessment with detailed breakdown
- **Deduplication**: Groups similar detections to reduce noise
- **Test Filtering**: Automatically identifies and optionally filters test/example credentials
- **Risk Assessment**: Context-aware risk evaluation (None/Low/Medium/High)

## Detection Categories

CredScan recognizes credentials across multiple technology categories:

### Cloud Platforms
- AWS (Access Keys, Secret Keys, Session Tokens)
- Google Cloud (Service Account Keys, API Keys)
- Azure (Connection Strings, Access Keys)
- Extended cloud providers (IBM, Oracle, Alibaba, etc.)

### CI/CD Platforms
- GitHub Actions, GitLab CI, Jenkins
- CircleCI, Travis CI, Azure DevOps
- BuildKite, Drone, and others

### Container Technologies
- Docker (Registry tokens, secrets)
- Kubernetes (Service account tokens, secrets)
- Helm charts and Kustomize configurations

### Databases
- PostgreSQL, MySQL, MongoDB
- Redis, Elasticsearch, Cassandra
- Modern databases (Supabase, PlanetScale, etc.)

### API Services
- Stripe, SendGrid, Twilio
- Slack, Discord, Telegram
- Social media and analytics platforms

### Framework-Specific
- Django, Flask, Laravel, Spring Boot
- WordPress, Drupal configurations
- JWT secrets and session keys

## Best Practices

### Regular Scanning
- Integrate into CI/CD pipelines for continuous monitoring
- Run periodic full repository scans including git history
- Use baseline files to maintain scan accuracy over time

### Configuration Management
- Adjust confidence thresholds based on your environment
- Customize technology categories for your tech stack
- Configure appropriate exclusion patterns for test environments

### False Positive Management
- Use baseline files to exclude known false positives
- Regularly review and update exclusion patterns
- Leverage test credential identification features

### Security Integration
- Export findings in SARIF format for security tools
- Set up alerting for high-confidence findings
- Document remediation procedures for different credential types

## Performance Considerations

CredScan can also scan large codebases:

- **Parallel processing**: Configurable worker threads for concurrent file scanning
- **Smart filtering**: Early filtering of binary files and excluded patterns
- **Efficient pattern matching**: Compiled regex patterns and intelligent caching
- **Memory management**: Streaming processing for large files and archives
- **Technology detection**: Context-aware pattern application to reduce false positives

For large repositories:
```bash
# Optimize for performance
credscan --workers 12 --disable-binary-parsing --binary-max-size 50
```

## Troubleshooting

### Common Issues

**High false positive rate**: Adjust confidence thresholds and use baseline files
```bash
credscan --min-confidence 0.5 --context-confidence-threshold 0.3
```

**Missing detections**: Lower thresholds and enable all detection methods
```bash
credscan --min-confidence 0.1 --show-confidence-details --show-test-credentials
```

**Performance issues**: Reduce worker count and exclude large directories
```bash
credscan --workers 4 --exclude "node_modules/,vendor/,dist/"
```

**Context analysis errors**: Check file encoding and content format
```bash
credscan --disable-context-analysis --verbose
```

## Contributing

Contributions are welcomed:

- Additional credential patterns and detection rules
- New technology category support
- Performance optimizations
- Output format enhancements
- Documentation improvements

## Security Notice

CredScan helps identify potential credentials but cannot guarantee detection of all exposed secrets. It should be used as part of a comprehensive security strategy that includes:

- Proper secret management systems (HashiCorp Vault, AWS Secrets Manager, etc.)
- Regular security audits and penetration testing
- Developer security training and awareness
- Secure development lifecycle practices
- Network security and access controls

Always ensure validate findings and implement proper remediation procedures for any discovered credentials.