"""
Expanded pattern library with categorized credential patterns.
This module contains a comprehensive set of patterns for detecting credentials.
"""

from typing import Dict, List
import json
import os
import yaml
import re

from .pattern_structure import PatternLibrary, PatternCategory, CredentialPattern


def load_default_patterns() -> PatternLibrary:
    """Load the default credential patterns."""
    library = PatternLibrary()
    
    # First try to load from comprehensive patterns file
    try:
        config_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'config')
        comprehensive_patterns_file = os.path.join(config_dir, 'comprehensive_patterns.json')
        
        if os.path.exists(comprehensive_patterns_file):
            with open(comprehensive_patterns_file, 'r') as f:
                comprehensive_data = json.load(f)
                
            # Convert comprehensive patterns to enhanced patterns
            for category_name, pattern_list in comprehensive_data.items():
                category = PatternCategory(
                    name=category_name.lower().replace(' ', '_').replace('/', '_'),
                    description=f"{category_name} credentials and tokens"
                )
                
                for pattern_keyword in pattern_list:
                    # Create regex patterns for each keyword
                    category.add_pattern(CredentialPattern(
                        name=f"{pattern_keyword.replace('_', ' ').title()}",
                        pattern=rf"(?i){re.escape(pattern_keyword)}\s*[:=]\s*['\"]?([^\s'\"{{}}]+)['\"]?",
                        description=f"Detects {pattern_keyword} credentials",
                        severity="high" if any(x in pattern_keyword.lower() for x in ['secret', 'key', 'token', 'password']) else "medium",
                        confidence=0.8
                    ))
                
                library.add_category(category)
                
            # Return the comprehensive pattern library
            return library
            
    except Exception as e:
        print(f"Warning: Could not load comprehensive patterns: {e}")
        # Fall back to hardcoded patterns below
    
    # AWS Patterns
    aws_category = PatternCategory(
        name="aws",
        description="Amazon Web Services credentials and configuration",
    )
    
    aws_category.add_pattern(CredentialPattern(
        name="AWS Access Key ID",
        pattern=r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        description="AWS Access Key IDs used for API authentication",
        severity="high",
        examples=["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPL"]
    ))
    
    aws_category.add_pattern(CredentialPattern(
        name="AWS Secret Access Key",
        pattern=r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
        description="AWS Secret Access Keys used with access key IDs",
        severity="critical",
        examples=["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
    ))

    aws_category.add_pattern(CredentialPattern(
        name="AWS Secret Access Key (Assignment)",
        pattern=r"(?i)(?:aws[_\-\s]?(?:secret[_\-\s]?(?:access[_\-\s]?)?key|secret))\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?",
        description="AWS Secret Access Keys in assignment context",
        severity="medium",
        examples=["aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
    ))
    
    aws_category.add_pattern(CredentialPattern(
        name="AWS MWS Key",
        pattern=r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        description="Amazon Marketplace Web Service Keys",
        severity="high"
    ))
    
    library.add_category(aws_category)
    
    # Google Cloud Patterns
    gcp_category = PatternCategory(
        name="gcp",
        description="Google Cloud Platform keys and tokens",
    )
    
    gcp_category.add_pattern(CredentialPattern(
        name="Google API Key",
        pattern=r"AIza[0-9A-Za-z-_]{35}",
        description="Google API Keys for GCP service authentication",
        severity="high"
    ))
    
    gcp_category.add_pattern(CredentialPattern(
        name="Google OAuth ID",
        pattern=r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        description="Google OAuth IDs used for authentication",
        severity="medium"
    ))
    
    gcp_category.add_pattern(CredentialPattern(
        name="Google OAuth Access Token",
        pattern=r"ya29\.[0-9A-Za-z\-_]+",
        description="Google OAuth Access Tokens",
        severity="critical"
    ))
    
    library.add_category(gcp_category)
    
    # Database Connection Strings
    db_category = PatternCategory(
        name="database",
        description="Database connection strings and credentials",
    )
    
    db_category.add_pattern(CredentialPattern(
        name="PostgreSQL Connection URI",
        pattern=r"postgres(?:ql)?:\/\/(?:[^:]+):([^@]+)@[^:]+(?::[0-9]+)\/[^?]+(?:\?.*)?",
        description="PostgreSQL connection strings with embedded credentials",
        severity="high",
        examples=["postgresql://user:password@localhost:5432/database"]
    ))
    
    db_category.add_pattern(CredentialPattern(
        name="MySQL Connection URI",
        pattern=r"mysql:\/\/(?:[^:]+):([^@]+)@[^:]+(?::[0-9]+)\/[^?]+(?:\?.*)?",
        description="MySQL connection strings with embedded credentials",
        severity="high"
    ))
    
    db_category.add_pattern(CredentialPattern(
        name="MongoDB Connection URI",
        pattern=r"mongodb(?:\+srv)?:\/\/(?:[^:]+):([^@]+)@[^\/]+(?:\/[^?]+)?(?:\?.*)?",
        description="MongoDB connection strings with embedded credentials",
        severity="high"
    ))
    
    db_category.add_pattern(CredentialPattern(
        name="Redis Connection URI",
        pattern=r"redis:\/\/(?:[^:]+):([^@]+)@[^:]+(?::[0-9]+)?(?:\/[0-9]+)?",
        description="Redis connection strings with embedded credentials",
        severity="high"
    ))
    
    library.add_category(db_category)
    
    # Payment Processing Services
    payment_category = PatternCategory(
        name="payment",
        description="Payment processing service credentials",
    )
    
    payment_category.add_pattern(CredentialPattern(
        name="Stripe API Key",
        pattern=r"(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}",
        description="Stripe API Keys for payment processing",
        severity="critical",
        examples=["sk_live_123456789012345678901234", "rk_test_1234567890123456789012"]
    ))
    
    payment_category.add_pattern(CredentialPattern(
        name="Stripe Publishable Key",
        pattern=r"pk_(?:live|test)_[0-9a-zA-Z]{24}",
        description="Stripe Publishable Keys (less sensitive)",
        severity="medium",
        examples=["pk_live_123456789012345678901234"]
    ))
    
    payment_category.add_pattern(CredentialPattern(
        name="PayPal Braintree Access Token",
        pattern=r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        description="PayPal Braintree Access Tokens",
        severity="high"
    ))
    
    payment_category.add_pattern(CredentialPattern(
        name="Square Access Token",
        pattern=r"sq0atp-[0-9A-Za-z\-_]{22}",
        description="Square Access Tokens for payment processing",
        severity="high"
    ))
    
    payment_category.add_pattern(CredentialPattern(
        name="Square OAuth Secret",
        pattern=r"sq0csp-[0-9A-Za-z\-_]{43}",
        description="Square OAuth Secrets",
        severity="critical"
    ))
    
    library.add_category(payment_category)
    
    # Communication & Messaging Services
    messaging_category = PatternCategory(
        name="messaging",
        description="Communication and messaging service credentials",
    )
    
    messaging_category.add_pattern(CredentialPattern(
        name="Slack API Token",
        pattern=r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
        description="Slack API Tokens",
        severity="high",
        examples=["xoxb-123456789012-123456789012-a1b2c3d4e5f6g7h8i9j0"]
    ))
    
    messaging_category.add_pattern(CredentialPattern(
        name="Slack Webhook URL",
        pattern=r"https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,10}\/B[a-zA-Z0-9_]{8,10}\/[a-zA-Z0-9_]{24}",
        description="Slack Incoming Webhook URLs",
        severity="high"
    ))
    
    messaging_category.add_pattern(CredentialPattern(
        name="Twilio API Key",
        pattern=r"SK[0-9a-fA-F]{32}",
        description="Twilio API Keys",
        severity="high"
    ))
    
    messaging_category.add_pattern(CredentialPattern(
        name="Twilio Account SID",
        pattern=r"AC[a-zA-Z0-9]{32}",
        description="Twilio Account SIDs",
        severity="medium"
    ))
    
    messaging_category.add_pattern(CredentialPattern(
        name="Twilio Auth Token",
        pattern=r"(?<=[^A-Za-z0-9])[a-zA-Z0-9]{32}(?=[^A-Za-z0-9])",
        description="Twilio Auth Tokens (when near Account SID)",
        severity="high"
    ))
    
    library.add_category(messaging_category)
    
    # Social Media & Platforms
    social_category = PatternCategory(
        name="social",
        description="Social media platform credentials",
    )
    
    social_category.add_pattern(CredentialPattern(
        name="Facebook Access Token",
        pattern=r"EAA[a-zA-Z0-9]{14}[0-9A-Za-z\.\-]+",
        description="Facebook Access Tokens",
        severity="high"
    ))
    
    social_category.add_pattern(CredentialPattern(
        name="Facebook OAuth",
        pattern=r"(?i)facebook(.{0,20})?['\"][0-9a-f]{32}['\"]",
        description="Facebook OAuth Credentials",
        severity="high"
    ))
    
    social_category.add_pattern(CredentialPattern(
        name="Twitter API Key",
        pattern=r"(?i)twitter(.{0,20})?['\"][0-9a-zA-Z]{35,44}['\"]",
        description="Twitter API Keys",
        severity="high"
    ))
    
    social_category.add_pattern(CredentialPattern(
        name="LinkedIn Client ID",
        pattern=r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]",
        description="LinkedIn Client IDs",
        severity="medium"
    ))
    
    social_category.add_pattern(CredentialPattern(
        name="LinkedIn Secret Key",
        pattern=r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
        description="LinkedIn Secret Keys",
        severity="high"
    ))
    
    library.add_category(social_category)
    
    # Private Keys & Certificates
    keys_category = PatternCategory(
        name="private_keys",
        description="Private keys, certificates, and authentication files",
    )
    
    keys_category.add_pattern(CredentialPattern(
        name="Private Key",
        pattern=r"-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----",
        description="Private keys in various formats",
        severity="critical"
    ))
    
    keys_category.add_pattern(CredentialPattern(
        name="SSH Private Key",
        pattern=r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        description="SSH private keys",
        severity="critical"
    ))
    
    keys_category.add_pattern(CredentialPattern(
        name="PGP Private Key",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        description="PGP private keys",
        severity="critical"
    ))
    
    keys_category.add_pattern(CredentialPattern(
        name="Certificate",
        pattern=r"-----BEGIN CERTIFICATE-----",
        description="Digital certificates",
        severity="medium"
    ))
    
    library.add_category(keys_category)
    
    # JWT Tokens
    jwt_category = PatternCategory(
        name="jwt",
        description="JWT tokens and authentication",
    )
    
    jwt_category.add_pattern(CredentialPattern(
        name="JWT",
        pattern=r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        description="JSON Web Tokens",
        severity="high",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"]
    ))
    
    library.add_category(jwt_category)
    
    # Generic API Credentials
    api_category = PatternCategory(
        name="api",
        description="Generic API credentials and authentication tokens",
    )
    
    api_category.add_pattern(CredentialPattern(
        name="Generic API Key",
        pattern=r"(?i)api[._-]?key\s*[=:]\s*['\"]([a-zA-Z0-9]{32,45})['\"]",
        description="Generic API keys of standard length",
        severity="high"
    ))
    
    api_category.add_pattern(CredentialPattern(
        name="Authorization Header",
        pattern=r"(?i)authorization[_\-]?[=:]\s*['\"]?(Bearer|Basic|Digest|HMAC)['\"]?\s+[A-Za-z0-9+/=._\-]+",
        description="Authorization headers with credentials",
        severity="high"
    ))
    
    api_category.add_pattern(CredentialPattern(
        name="Generic Secret",
        pattern=r"(?i)secret[_\-]?[=:]\s*['\"]?[A-Za-z0-9+/=._\-]{32,}['\"]?",
        description="Generic secret keys of substantial length",
        severity="high"
    ))
    
    library.add_category(api_category)
    
    # Generic Passwords
    password_category = PatternCategory(
        name="password",
        description="Generic passwords and authentication credentials",
    )
    
    password_category.add_pattern(CredentialPattern(
        name="Generic Password",
        pattern=r"(?i)(?:password|passwd|pwd)[\s:=]+['\"]?[^'\"\s]{8,}['\"]?",
        description="Generic passwords of sufficient length",
        severity="high"
    ))
    
    password_category.add_pattern(CredentialPattern(
        name="Password in URL",
        pattern=r"[a-zA-Z]{3,10}://[^/\s:@]+:[^/\s:@]+@[^/\s:@]+",
        description="URLs with embedded credentials",
        severity="high",
        examples=["https://username:password@example.com"]
    ))
    
    library.add_category(password_category)
    
    # AI/ML Services
    ai_ml_category = PatternCategory(
        name="ai_ml",
        description="AI and Machine Learning service credentials",
    )
    
    ai_ml_category.add_pattern(CredentialPattern(
        name="OpenAI API Key",
        pattern=r"sk-[a-zA-Z0-9]{48}",
        description="OpenAI API Keys",
        severity="high"
    ))
    
    ai_ml_category.add_pattern(CredentialPattern(
        name="Hugging Face API Key",
        pattern=r"hf_[a-zA-Z0-9]{34}",
        description="Hugging Face API Keys",
        severity="high"
    ))
    
    ai_ml_category.add_pattern(CredentialPattern(
        name="Anthropic API Key",
        pattern=r"sk-ant-api03-[a-zA-Z0-9-_]{27}",
        description="Anthropic API Keys",
        severity="high"
    ))
    
    library.add_category(ai_ml_category)

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



def load_patterns_from_file(filepath: str) -> PatternLibrary:
    """Load patterns from a YAML or JSON file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Pattern file not found: {filepath}")
    
    with open(filepath, 'r') as f:
        content = f.read()
        
    if filepath.lower().endswith('.yaml') or filepath.lower().endswith('.yml'):
        data = yaml.safe_load(content)
    elif filepath.lower().endswith('.json'):
        data = json.loads(content)
    else:
        raise ValueError(f"Unsupported file format: {filepath}. Only YAML and JSON are supported.")
    
    return PatternLibrary.from_dict(data)


def save_patterns_to_file(library: PatternLibrary, filepath: str):
    """Save patterns to a YAML or JSON file."""
    data = library.to_dict()
    
    if filepath.lower().endswith('.yaml') or filepath.lower().endswith('.yml'):
        with open(filepath, 'w') as f:
            yaml.dump(data, f, sort_keys=False, default_flow_style=False)
    elif filepath.lower().endswith('.json'):
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    else:
        raise ValueError(f"Unsupported file format: {filepath}. Only YAML and JSON are supported.")


def merge_pattern_libraries(base_library: PatternLibrary, additional_library: PatternLibrary) -> PatternLibrary:
    """Merge two pattern libraries, with the additional library taking precedence."""
    merged_library = PatternLibrary()
    
    # First add all categories from the base library
    for category_name, category in base_library.categories.items():
        merged_library.add_category(category)
    
    # Then add or update categories from the additional library
    for category_name, category in additional_library.categories.items():
        if category_name in merged_library.categories:
            # Category exists, add patterns
            for pattern in category.patterns:
                merged_library.categories[category_name].add_pattern(pattern)
            
            # Update enabled status if the additional library disables it
            if not category.enabled and category_name in merged_library.enabled_categories:
                merged_library.disable_category(category_name)
        else:
            # Category doesn't exist, add it
            merged_library.add_category(category)
    
    return merged_library