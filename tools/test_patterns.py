# tools/test_patterns.py
"""Test pattern quality and effectiveness."""

import re
import sys
import json
from typing import List, Dict, Tuple

class PatternTester:
    def __init__(self, patterns: List[Dict]):
        self.patterns = patterns
        
    def test_true_positives(self) -> Dict[str, float]:
        """Test patterns against known credential samples."""
        test_cases = {
            'password': [
                ('password = "actualSecret123"', True),
                ('DB_PASSWORD="mysecretpass"', True),
                ('password = "short"', False),  # Too short
                ('password_policy = "8 chars"', False),  # Not a credential
                ('password: "${PASS_VAR}"', False),  # Template variable
            ],
            'token': [
                ('auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"', True),
                ('github_token = "ghp_1234567890abcdef1234567890abcdef12"', True),
                ('token_type = "Bearer"', False),  # Not a credential
                ('slack_token = "xoxb-123456789012-1234567890123-abcdef"', True),
                ('api_token="${API_TOKEN}"', False),  # Environment variable reference
            ],
            'key': [
                ('api_key = "1234567890abcdef1234567890abcdef"', True),
                ('aws_access_key = "AKIAIOSFODNN7EXAMPLE"', True),
                ('key_name = "my-ssh-key"', False),  # Just a name
                ('stripe_api_key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"', True),
            ],
            'secret': [
                ('client_secret = "1234567890abcdef1234567890abcdef"', True),
                ('app_secret = "super_long_secret_value_here_123456"', True),
                ('secret_name = "prod-db-secret"', False),  # Just a name
            ]
        }
        
        results = {}
        for pattern in self.patterns:
            tp, fp, tn, fn = 0, 0, 0, 0
            
            # Determine which test cases to use based on pattern name
            pattern_name_lower = pattern['name'].lower()
            relevant_tests = []
            
            for test_type, cases in test_cases.items():
                if test_type in pattern_name_lower:
                    relevant_tests.extend(cases)
            
            # If no specific tests, use all tests
            if not relevant_tests:
                for cases in test_cases.values():
                    relevant_tests.extend(cases)
            
            # Run tests
            for test_string, should_match in relevant_tests:
                try:
                    regex = re.compile(pattern['pattern'])
                    matched = bool(regex.search(test_string))
                    
                    if matched and should_match:
                        tp += 1
                    elif matched and not should_match:
                        fp += 1
                    elif not matched and not should_match:
                        tn += 1
                    else:
                        fn += 1
                except re.error as e:
                    print(f"Error in pattern '{pattern['name']}': {e}")
                    continue
            
            # Calculate metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            
            results[pattern['name']] = {
                'true_positives': tp,
                'false_positives': fp,
                'true_negatives': tn,
                'false_negatives': fn,
                'precision': precision,
                'recall': recall,
                'f1': 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            }
        
        return results
    
    def test_pattern_compilation(self) -> List[Dict]:
        """Test that all patterns compile without errors."""
        errors = []
        for pattern in self.patterns:
            try:
                re.compile(pattern['pattern'])
            except re.error as e:
                errors.append({
                    'name': pattern['name'],
                    'pattern': pattern['pattern'],
                    'error': str(e)
                })
        return errors


def load_patterns_from_generated_file(filepath: str) -> List[Dict]:
    """Extract patterns from the generated Python file."""
    patterns = []
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Parse patterns using regex (simple approach)
    # Look for CredentialPattern(...) blocks
    pattern_blocks = re.findall(
        r'CredentialPattern\((.*?)\)\)',
        content,
        re.DOTALL
    )
    
    for block in pattern_blocks:
        # Extract fields
        name_match = re.search(r'name="([^"]+)"', block)
        pattern_match = re.search(r'pattern=r[\'"]([^\'"]*)[\'"]\s*,', block)
        desc_match = re.search(r'description="([^"]+)"', block)
        severity_match = re.search(r'severity="([^"]+)"', block)
        confidence_match = re.search(r'confidence=([\d.]+)', block)
        
        if name_match and pattern_match:
            patterns.append({
                'name': name_match.group(1),
                'pattern': pattern_match.group(1),
                'description': desc_match.group(1) if desc_match else '',
                'severity': severity_match.group(1) if severity_match else 'medium',
                'confidence': float(confidence_match.group(1)) if confidence_match else 0.8
            })
    
    return patterns


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_patterns.py <generated_patterns.py>")
        sys.exit(1)
    
    patterns_file = sys.argv[1]
    
    # Load patterns
    print(f"Loading patterns from {patterns_file}...")
    patterns = load_patterns_from_generated_file(patterns_file)
    print(f"Loaded {len(patterns)} patterns\n")
    
    # Create tester
    tester = PatternTester(patterns)
    
    # Test compilation
    print("Testing pattern compilation...")
    errors = tester.test_pattern_compilation()
    if errors:
        print(f"❌ {len(errors)} patterns failed to compile:")
        for error in errors:
            print(f"  - {error['name']}: {error['error']}")
    else:
        print("✅ All patterns compile successfully!\n")
    
    # Test effectiveness
    print("Testing pattern effectiveness...")
    results = tester.test_true_positives()
    
    # Display results
    print("\nPattern Test Results:")
    print("-" * 80)
    print(f"{'Pattern Name':<30} {'TP':<4} {'FP':<4} {'TN':<4} {'FN':<4} {'Precision':<10} {'Recall':<10} {'F1':<10}")
    print("-" * 80)
    
    for name, metrics in results.items():
        print(f"{name:<30} "
              f"{metrics['true_positives']:<4} "
              f"{metrics['false_positives']:<4} "
              f"{metrics['true_negatives']:<4} "
              f"{metrics['false_negatives']:<4} "
              f"{metrics['precision']:<10.2f} "
              f"{metrics['recall']:<10.2f} "
              f"{metrics['f1']:<10.2f}")
    
    # Summary
    print("\n" + "=" * 80)
    avg_precision = sum(m['precision'] for m in results.values()) / len(results)
    avg_recall = sum(m['recall'] for m in results.values()) / len(results)
    avg_f1 = sum(m['f1'] for m in results.values()) / len(results)
    
    print(f"Average Precision: {avg_precision:.2f}")
    print(f"Average Recall: {avg_recall:.2f}")
    print(f"Average F1 Score: {avg_f1:.2f}")
    
    # Recommendations
    print("\nRecommendations:")
    for name, metrics in results.items():
        if metrics['precision'] < 0.7:
            print(f"⚠️  {name} has low precision ({metrics['precision']:.2f}) - too many false positives")
        if metrics['recall'] < 0.7:
            print(f"⚠️  {name} has low recall ({metrics['recall']:.2f}) - missing real credentials")


if __name__ == "__main__":
    main()