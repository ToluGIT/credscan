# CredScan

CredScan is a credential and secret detection tool designed to identify sensitive information in your codebase. It helps security teams and developers detect credentials, API keys, tokens, and other secrets that may have been accidentally committed.

## Features

- **Multi-format scanning**: Detects secrets in JSON, YAML, and code files (Python, JavaScript, Java, etc.)
- **Pattern-based detection**: Uses rules to detect common credential formats
- **Entropy analysis**: Identifies high-entropy strings that may represent secrets
- **Git history scanning**: Examines commit history for credentials that may have been removed
- **Pre-commit hook integration**: Prevents accidental credential commits
- **Baseline management**: Reduces false positives with customizable exclusions
- **Multiple output formats**: Console, JSON, and SARIF reporting options

## Installation

```bash
# Install from PyPI
pip install credscan

# Install from source
git clone https://github.com/yourusername/credscan.git
cd credscan
pip install .
```

## Basic Usage

```bash
# Scan your current directory
credscan

# Scan a specific path
credscan --path /path/to/scan

# Scan with verbose output
credscan --path /path/to/scan --verbose
```

## Configuration

CredScan can be configured using command-line options or a configuration file:

```bash
# Use a config file
credscan --config ./config/config_example.yaml

# Override config with command-line options
credscan --config ./config/config_example.yaml --workers 8 --output json
```

Example configuration file:

```yaml
# Scanning options
scan_path: "."
max_workers: 4
verbose: false

# File handling
exclude_patterns:
  - "vendor/"
  - "node_modules/"
  - ".git/"

# Output options
output_formats:
  - "console"
  - "json"
output_directory: "./reports"
disable_colors: false

# Detection settings
min_length: 8
enable_entropy: true
entropy_threshold: 4.2
```

## Advanced Usage

### Git Hook Integration

Prevent credential leakage by installing CredScan as a pre-commit hook:

```bash
# Install the pre-commit hook
credscan --install-hook

# Configure hook behavior in .credscan-hook.conf
```

The hook will automatically scan staged files before each commit.

### Git History Scanning

Scan your repository's git history for credentials:

```bash
# Scan the entire history
credscan --scan-history

# Scan commits from the last 2 weeks
credscan --scan-history --since "2 weeks ago"

# Scan a specific branch
credscan --scan-history --branch develop
```

### Baseline Management

Create and maintain a baseline to exclude known false positives:

```bash
# Create a baseline from current findings
credscan --create-baseline .credscan-baseline.json

# Use an existing baseline for scans
credscan --baseline-file .credscan-baseline.json

```

## Example Output

When scanning a repository, CredScan provides detailed information about potential credentials:

```
=== Credential Scan Results ===

Files found: 42
Files scanned: 42
Credentials found: 3

 File: src/config/set.json 

[HIGH] Common Credential Patterns
  Line: 5
  Variable: api_key
  Value: AKIASFODNN7EXAMPLE
  Potential AWS Client ID found

[MEDIUM] Sensitive Variable Names
  Line: 3
  Variable: password
  Value: super_secret_db_password
  Potential credential in variable 'password'

 File: src/app.py 

[MEDIUM] Sensitive Variable Names
  Line: 2
  Variable: API_SECRET
  Value: this_is_a_real_secret_12345
  Potential credential in variable 'API_SECRET'

Summary: 3 potential credential(s) found.
High severity: 1
Medium severity: 2


```
<img width="1244" alt="Screenshot 2025-04-10 at 08 42 47" src="https://github.com/user-attachments/assets/e41809b0-4650-4007-a757-ea95ae3a8e60" />


## Detection Rules

CredScan uses a rule-based system to detect credentials. The rules are defined in YAML format and can be customized:

```bash
# Use custom rules
credscan --rules ./path/to/rules.yaml
```

Example rule format:

```yaml
- id: sensitive_variable_names
  name: Sensitive Variable Names
  description: Detects variables with names suggesting they contain credentials
  severity: medium
  variable_patterns:
    - (?i)passwd|password
    - (?i)secret
    - (?i)token
    - (?i)apiKey|api[_-]key
  min_length: 6
```

## Planned Enhancements

The following features are planned for future releases:

- **Enhanced visualization**: Visual reports and dashboard for easier analysis
- **Cloud integration**: Direct scanning of cloud resources (AWS, GCP, Azure)
- **Machine learning detection**: Improved accuracy with ML-based credential detection
- **CI/CD integration**: Better integration with common CI/CD platforms
- **User interface**: Web-based interface for easier management
- **Expanded language support**: Additional parsers for more programming languages
- **Policy enforcement**: Configurable policy enforcement and compliance reporting


## Acknowledgements

- This tool was inspired by other credential scanning tools like truffleHog and git-secrets

---

**Disclaimer**: CredScan helps identify potential credentials in your codebase but cannot guarantee to find all exposed secrets. Regular security audits and secure credential management practices are still essential.
