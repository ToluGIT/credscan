"""
Web scanner for detecting credentials in remote files and web content.
"""
import re
import requests
import json
import os
import concurrent.futures
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)

class WebScanner:
    """Scanner for detecting credentials in web content and remote files."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the web scanner with configuration."""
        self.config = config
        self.timeout = config.get('web_timeout', 10)
        self.max_retries = config.get('web_max_retries', 3)
        self.user_agent = config.get('web_user_agent', 'Mozilla/5.0 (compatible; CredScan/1.0)')
        
        # Load patterns and false positives
        self.patterns = self._load_patterns()
        self.pattern_categories = self._load_pattern_categories()
        self.false_positives = self._load_false_positives()
        
        # Build regex patterns
        self.web_regex = self._build_web_regex()
        
    def _load_patterns(self) -> List[str]:
        """Load credential patterns from config."""
        # Use a focused set of patterns for web scanning to avoid regex complexity
        web_patterns = [
            "password", "passwd", "pwd", "pass", "secret", "token", "auth_token",
            "access_token", "api_key", "apikey", "api_secret", "client_secret",
            "jwt_token", "bearer", "authorization", "aws_access_key", "aws_secret",
            "database_password", "db_password", "stripe_secret_key", "github_token",
            "slack_token", "google_api_key", "sendgrid_api_key", "twilio_auth_token",
            "mailgun_api_key", "private_key", "public_key", "session_token",
            "refresh_token", "csrf_token", "xsrf_token"
        ]
        
        try:
            from credscan.config_paths import config_file
            patterns_file = config_file('comprehensive_patterns.json')
            
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    
                # Add high-value patterns from comprehensive list
                high_value_keywords = ['secret', 'key', 'token', 'password', 'auth', 'api']
                for category_patterns in data.values():
                    for pattern in category_patterns:
                        if any(keyword in pattern.lower() for keyword in high_value_keywords):
                            if pattern not in web_patterns:
                                web_patterns.append(pattern)
                                
                return web_patterns[:50]  # Limit to 50 patterns for performance
        except Exception as e:
            logger.warning(f"Could not load comprehensive patterns: {e}")
        
        return web_patterns
    
    def _load_pattern_categories(self) -> Dict[str, str]:
        """Load pattern categories for classification."""
        try:
            from credscan.config_paths import config_file
            patterns_file = config_file('comprehensive_patterns.json')
            
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    categories = {}
                    for category_name, patterns in data.items():
                        for pattern in patterns:
                            categories[pattern.lower()] = category_name
                    return categories
        except Exception as e:
            logger.warning(f"Could not load pattern categories: {e}")
        
        return {}
    
    def _load_false_positives(self) -> List[re.Pattern]:
        """Load false positive patterns."""
        patterns = [
            r"\$_POST\[[^\]]*\]\s*=\s*['\"]?[a-zA-Z0-9_]+['\"]?",
            r"csrf_token\s*=",
            r"password\s*=\s*['\"]?(YES|NO)['\"]?",
            r"password\s*=\s*['\"]?\$\{[^}]+\}['\"]?",  # Template variables
            r"token\s*=\s*['\"]?\$\{[^}]+\}['\"]?",
            r"key\s*=\s*['\"]?\$\{[^}]+\}['\"]?",
        ]
        
        compiled_patterns = []
        for pattern in patterns:
            try:
                compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Invalid false positive pattern {pattern}: {e}")
        
        return compiled_patterns
    
    def _build_web_regex(self) -> re.Pattern:
        """Build regex pattern for web scanning."""
        pattern_body = '|'.join(re.escape(p) for p in self.patterns)
        # More permissive regex for web content - handles JS object notation and various formats
        return re.compile(
            rf"({pattern_body})\s*[:=]\s*['\"]([^'\"{{}}]+?)['\"]", 
            re.IGNORECASE
        )
    
    def _is_false_positive(self, line: str) -> bool:
        """Check if a line contains false positive patterns."""
        return any(pattern.search(line) for pattern in self.false_positives)
    
    def _get_category(self, variable: str) -> str:
        """Get category for a detected variable."""
        return self.pattern_categories.get(variable.lower(), "Unknown")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format."""
        url = url.strip().replace(" ", "")
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            url = f"http://{parsed.path}"
        return url
    
    def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan a single URL for credentials.
        
        Args:
            url: URL to scan
            
        Returns:
            List of findings
        """
        results = []
        normalized_url = self._normalize_url(url)
        
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(normalized_url, timeout=self.timeout, headers=headers)
            
            if response.status_code not in [200, 301, 302]:
                logger.debug(f"URL {url} returned status {response.status_code}")
                return results
            
            # Scan response content
            for line_num, line in enumerate(response.text.splitlines(), 1):
                if self._is_false_positive(line):
                    continue
                
                # Debug logging
                if any(keyword in line.lower() for keyword in ['api_key', 'password', 'secret', 'token', 'key']):
                    logger.debug(f"Checking line {line_num}: {line.strip()}")
                    
                for match in self.web_regex.finditer(line):
                    variable, value = match.groups()
                    category = self._get_category(variable)
                    logger.debug(f"Found match: {variable} = {value}")
                    
                    finding = {
                        "rule_id": "web_credential_detection",
                        "rule_name": "Web Credential Detection",
                        "severity": "high",
                        "type": "credential_in_web_content",
                        "category": category,
                        "variable": variable,
                        "value": value,
                        "line": line_num,
                        "path": normalized_url,
                        "description": f"Potential credential '{variable}' found in web content"
                    }
                    results.append(finding)
                    
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout accessing {url}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error accessing {url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error scanning {url}: {e}")
        
        return results
    
    def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple URLs for credentials in parallel.

        Args:
            urls: List of URLs to scan

        Returns:
            List of all findings
        """
        if not urls:
            return []

        max_workers = self.config.get('web_max_workers', min(10, len(urls)))
        all_results = []

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                    except Exception as e:
                        logger.error(f"Error scanning {url}: {e}")
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")

        return all_results