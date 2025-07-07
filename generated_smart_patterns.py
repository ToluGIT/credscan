def load_default_patterns() -> PatternLibrary:
    """Load credential patterns with smart detection."""
    library = PatternLibrary()

    # Token patterns - 8 variations
    token_patterns = PatternCategory(
        name="token_patterns",
        description="Token credentials and secrets"
    )

    token_patterns.add_pattern(CredentialPattern(
        name="Generic Token",
        pattern=r'(?i)token\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
        description="Generic token with minimum length requirement",
        severity="high",
        confidence=0.8
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Pipeline Token",
        pattern=r'(?i)pipeline[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Pipeline service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Powerbi Token",
        pattern=r'(?i)powerbi[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Powerbi service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Gcp Token",
        pattern=r'(?i)gcp[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Gcp service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Gitlab Token",
        pattern=r'(?i)gitlab[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Gitlab service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Rapidapi Token",
        pattern=r'(?i)rapidapi[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Rapidapi service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Slack Token",
        pattern=r'(?i)slack[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Slack service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Github Token",
        pattern=r'(?i)github[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Github service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Auth Token",
        pattern=r'(?i)auth[_-]?token\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Auth service tokens",
        severity="high",
        confidence=0.85
    ))

    token_patterns.add_pattern(CredentialPattern(
        name="Bearer Token",
        pattern=r'(?i)(?:bearer|authorization)\s*[=:]\s*["\']?Bearer\s+([a-zA-Z0-9_\-\.=]+)',
        description="Bearer authentication tokens",
        severity="high",
        confidence=0.9
    ))

    library.add_category(token_patterns)

    # Key patterns - 8 variations
    key_patterns = PatternCategory(
        name="key_patterns",
        description="Key credentials and secrets"
    )

    key_patterns.add_pattern(CredentialPattern(
        name="AWS API Key",
        pattern=r'(?i)aws[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="AWS API keys",
        severity="critical",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="GCP API Key",
        pattern=r'(?i)gcp[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="GCP API keys",
        severity="critical",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="AZURE API Key",
        pattern=r'(?i)azure[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="AZURE API keys",
        severity="critical",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="STRIPE API Key",
        pattern=r'(?i)stripe[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="STRIPE API keys",
        severity="high",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="GITHUB API Key",
        pattern=r'(?i)github[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="GITHUB API keys",
        severity="high",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="GITLAB API Key",
        pattern=r'(?i)gitlab[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="GITLAB API keys",
        severity="high",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="SLACK API Key",
        pattern=r'(?i)slack[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="SLACK API keys",
        severity="high",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="SENDGRID API Key",
        pattern=r'(?i)sendgrid[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="SENDGRID API keys",
        severity="high",
        confidence=0.9
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="Generic API Key",
        pattern=r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        description="Generic API keys with minimum length",
        severity="high",
        confidence=0.75
    ))

    key_patterns.add_pattern(CredentialPattern(
        name="Private Key Reference",
        pattern=r'(?i)private[_-]?key\s*[=:]\s*["\']([^"\']+\.(?:pem|key|p12|pfx))["\']',
        description="References to private key files",
        severity="critical",
        confidence=0.95
    ))

    library.add_category(key_patterns)

    # Secret patterns - 6 variations
    secret_patterns = PatternCategory(
        name="secret_patterns",
        description="Secret credentials and secrets"
    )

    secret_patterns.add_pattern(CredentialPattern(
        name="Client Secret",
        pattern=r'(?i)client[_-]?secret\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        description="OAuth client secrets",
        severity="critical",
        confidence=0.9
    ))

    secret_patterns.add_pattern(CredentialPattern(
        name="High Entropy Secret",
        pattern=r'(?i)secret\s*[=:]\s*["\']([a-zA-Z0-9+/=_\-]{32,})["\']',
        description="Secrets with high entropy (32+ chars)",
        severity="high",
        confidence=0.85
    ))

    library.add_category(secret_patterns)

    # Password patterns - 6 variations
    password_patterns = PatternCategory(
        name="password_patterns",
        description="Password credentials and secrets"
    )

    password_patterns.add_pattern(CredentialPattern(
        name="Password Assignment",
        pattern=r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\'${\s]{8,})["\']',
        description="Password assignments with quoted values (min 8 chars)",
        severity="critical",
        confidence=0.9
    ))

    password_patterns.add_pattern(CredentialPattern(
        name="Database Password",
        pattern=r'(?i)(?:db[_-]?|database[_-]?|mysql[_-]?|postgres[_-]?|mongo[_-]?|redis[_-]?|oracle[_-]?)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\'${]+)["\']',
        description="Database password assignments",
        severity="critical",
        confidence=0.95
    ))

    password_patterns.add_pattern(CredentialPattern(
        name="Password Environment Variable",
        pattern=r'(?i)^[A-Z_]*(?:PASSWORD|PASSWD|PWD|PASS)\s*=\s*([^\s${]+)$',
        description="Password in environment variable format",
        severity="high",
        confidence=0.85
    ))

    library.add_category(password_patterns)

    return library