# tools/generate_smart_patterns.py
"""
Generate high-quality, context-aware patterns from scan4secrets keywords.
"""

import json
import re
from typing import List, Dict, Set
from collections import defaultdict

class SmartPatternGenerator:
    def __init__(self, keywords_by_group: Dict[str, List[str]]):
        self.keywords_by_group = keywords_by_group
        
    def generate_patterns_for_group(self, base_term: str, keywords: List[str]) -> List[Dict]:
        """Generate smart patterns for a group of related keywords."""
        patterns = []
        
        # Analyze the keywords to understand variations
        variations = self.analyze_variations(keywords)
        
        if base_term == 'password':
            patterns.extend(self.generate_password_patterns(variations))
        elif base_term == 'token':
            patterns.extend(self.generate_token_patterns(variations))
        elif base_term == 'key':
            patterns.extend(self.generate_key_patterns(variations))
        elif base_term == 'secret':
            patterns.extend(self.generate_secret_patterns(variations))
        else:
            patterns.extend(self.generate_generic_patterns(base_term, variations))
            
        return patterns
    
    def analyze_variations(self, keywords: List[str]) -> Dict:
        """Analyze keyword variations to understand prefixes/suffixes."""
        prefixes = defaultdict(list)
        suffixes = defaultdict(list)
        standalone = []
        
        for keyword in keywords:
            parts = re.split(r'[_-]', keyword)
            if len(parts) == 1:
                standalone.append(keyword)
            elif parts[-1] in ['password', 'token', 'key', 'secret']:
                # It's a prefix variation
                prefix = '_'.join(parts[:-1])
                prefixes[parts[-1]].append(prefix)
            elif parts[0] in ['password', 'token', 'key', 'secret']:
                # It's a suffix variation
                suffix = '_'.join(parts[1:])
                suffixes[parts[0]].append(suffix)
                
        return {
            'prefixes': dict(prefixes),
            'suffixes': dict(suffixes),
            'standalone': standalone
        }
    
    def generate_password_patterns(self, variations: Dict) -> List[Dict]:
        """Generate smart password patterns."""
        patterns = []
        
        # Pattern 1: Password assignment with minimum length
        patterns.append({
            'name': 'Password Assignment',
            'pattern': r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\'${\s]{8,})["\']',
            'description': 'Password assignments with quoted values (min 8 chars)',
            'severity': 'critical',
            'confidence': 0.9
        })
        
        # Pattern 2: Database passwords specifically
        db_prefixes = ['db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'oracle']
        db_pattern = '|'.join(f'{p}[_-]?' for p in db_prefixes)
        patterns.append({
            'name': 'Database Password',
            'pattern': rf'(?i)(?:{db_pattern})(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\'${{]+)["\']',
            'description': 'Database password assignments',
            'severity': 'critical',
            'confidence': 0.95
        })
        
        # Pattern 3: Environment variable format
        patterns.append({
            'name': 'Password Environment Variable',
            'pattern': r'(?i)^[A-Z_]*(?:PASSWORD|PASSWD|PWD|PASS)\s*=\s*([^\s${]+)$',
            'description': 'Password in environment variable format',
            'severity': 'high',
            'confidence': 0.85
        })
        
        return patterns
    
    def generate_token_patterns(self, variations: Dict) -> List[Dict]:
        """Generate smart token patterns."""
        patterns = []
        
        # Group tokens by service
        service_tokens = defaultdict(list)
        for keyword in self.keywords_by_group.get('token', []):
            if '_' in keyword:
                service = keyword.split('_')[0]
                service_tokens[service].append(keyword)
        
        # Pattern 1: Generic token with entropy check
        patterns.append({
            'name': 'Generic Token',
            'pattern': r'(?i)token\s*[=:]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            'description': 'Generic token with minimum length requirement',
            'severity': 'high',
            'confidence': 0.8
        })
        
        # Pattern 2: Service-specific tokens (top 10 services)
        top_services = sorted(service_tokens.items(), key=lambda x: len(x[1]), reverse=True)[:10]
        for service, tokens in top_services:
            service_pattern = f'{service}[_-]?'
            patterns.append({
                'name': f'{service.title()} Token',
                'pattern': rf'(?i){service_pattern}token\s*[=:]\s*["\']([^"\'${{]+)["\']',
                'description': f'{service.title()} service tokens',
                'severity': 'high',
                'confidence': 0.85
            })
        
        # Pattern 3: Bearer tokens
        patterns.append({
            'name': 'Bearer Token',
            'pattern': r'(?i)(?:bearer|authorization)\s*[=:]\s*["\']?Bearer\s+([a-zA-Z0-9_\-\.=]+)',
            'description': 'Bearer authentication tokens',
            'severity': 'high',
            'confidence': 0.9
        })
        
        return patterns
    
    def generate_key_patterns(self, variations: Dict) -> List[Dict]:
        """Generate smart key patterns."""
        patterns = []
        
        # Pattern 1: API Keys with service prefixes
        api_services = ['aws', 'gcp', 'azure', 'stripe', 'github', 'gitlab', 'slack', 'sendgrid']
        for service in api_services:
            patterns.append({
                'name': f'{service.upper()} API Key',
                'pattern': rf'(?i){service}[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']([^"\'${{]+)["\']',
                'description': f'{service.upper()} API keys',
                'severity': 'critical' if service in ['aws', 'gcp', 'azure'] else 'high',
                'confidence': 0.9
            })
        
        # Pattern 2: Generic API key with length requirement
        patterns.append({
            'name': 'Generic API Key',
            'pattern': r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            'description': 'Generic API keys with minimum length',
            'severity': 'high',
            'confidence': 0.75
        })
        
        # Pattern 3: Private keys
        patterns.append({
            'name': 'Private Key Reference',
            'pattern': r'(?i)private[_-]?key\s*[=:]\s*["\']([^"\']+\.(?:pem|key|p12|pfx))["\']',
            'description': 'References to private key files',
            'severity': 'critical',
            'confidence': 0.95
        })
        
        return patterns
    
    def generate_secret_patterns(self, variations: Dict) -> List[Dict]:
        """Generate smart secret patterns."""
        patterns = []
        
        # Pattern 1: Client secrets (OAuth pattern)
        patterns.append({
            'name': 'Client Secret',
            'pattern': r'(?i)client[_-]?secret\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            'description': 'OAuth client secrets',
            'severity': 'critical',
            'confidence': 0.9
        })
        
        # Pattern 2: Generic secrets with entropy
        patterns.append({
            'name': 'High Entropy Secret',
            'pattern': r'(?i)secret\s*[=:]\s*["\']([a-zA-Z0-9+/=_\-]{32,})["\']',
            'description': 'Secrets with high entropy (32+ chars)',
            'severity': 'high',
            'confidence': 0.85
        })
        
        return patterns
    
    def generate_python_code(self) -> str:
        """Generate Python code for pattern_library.py."""
        code_lines = ['def load_default_patterns() -> PatternLibrary:']
        code_lines.append('    """Load credential patterns with smart detection."""')
        code_lines.append('    library = PatternLibrary()')
        code_lines.append('')
        
        # Generate patterns for each group
        for base_term, keywords in self.keywords_by_group.items():
            if len(keywords) < 2:  # Skip single keywords
                continue
                
            patterns = self.generate_patterns_for_group(base_term, keywords)
            
            if patterns:
                # Create category
                category_name = f"{base_term}_patterns"
                code_lines.append(f'    # {base_term.title()} patterns - {len(keywords)} variations')
                code_lines.append(f'    {category_name} = PatternCategory(')
                code_lines.append(f'        name="{category_name}",')
                code_lines.append(f'        description="{base_term.title()} credentials and secrets"')
                code_lines.append('    )')
                code_lines.append('')
                
                # Add patterns
                for pattern in patterns:
                    code_lines.append(f'    {category_name}.add_pattern(CredentialPattern(')
                    code_lines.append(f'        name="{pattern["name"]}",')
                    code_lines.append(f'        pattern=r\'{pattern["pattern"]}\',')
                    code_lines.append(f'        description="{pattern["description"]}",')
                    code_lines.append(f'        severity="{pattern["severity"]}",')
                    code_lines.append(f'        confidence={pattern["confidence"]}')
                    code_lines.append('    ))')
                    code_lines.append('')
                
                code_lines.append(f'    library.add_category({category_name})')
                code_lines.append('')
        
        code_lines.append('    return library')
        return '\n'.join(code_lines)


# Example usage
if __name__ == "__main__":
    # Parse the consolidated patterns output
    keywords_by_group = {
        'token': ['pipeline_token', 'powerbi_token', 'gcp_user_token', 'gitlab_ci_token', 
                  'rapidapi_token', 'slack_token', 'github_token', 'auth_token'],
        'key': ['stability_key', 'airtable_api_key', 'email_api_key', 'tls_key', 
                'registration_key', 'aws_key', 'stripe_key', 'api_key'],
        'secret': ['infura_project_secret', 'prisma_secret', 'smtp_secret', 
                   'scaleway_secret', 'app_secret', 'client_secret'],
        'password': ['password', 'pem_password', 'mssql_password', 'MYSQL_PASSWORD', 
                     'database_password', 'db_password'],
    }
    
    generator = SmartPatternGenerator(keywords_by_group)
    code = generator.generate_python_code()
    
    with open('generated_smart_patterns.py', 'w') as f:
        f.write(code)
    
    print("Smart patterns generated and saved to generated_smart_patterns.py")