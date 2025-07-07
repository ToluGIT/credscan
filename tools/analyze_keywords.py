# tools/analyze_keywords.py
"""
Analyze keywords from scan4secrets patterns.json to group similar terms
and help create consolidated, high-quality patterns.
"""

import json
import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import sys
import os

class KeywordAnalyzer:
    def __init__(self, patterns_file_path: str):
        """Initialize with path to scan4secrets patterns.json."""
        with open(patterns_file_path, 'r') as f:
            self.patterns_data = json.load(f)
        
        self.all_keywords = set()
        self.category_keywords = {}
        
        # Extract all keywords
        for category, keywords in self.patterns_data.items():
            self.category_keywords[category] = keywords
            self.all_keywords.update(keywords)
    
    def analyze_keyword_patterns(self) -> Dict[str, List[str]]:
        """Group keywords by common patterns."""
        groups = defaultdict(list)
        
        # Group by base term (e.g., password, token, key)
        for keyword in self.all_keywords:
            base_term = self._extract_base_term(keyword)
            groups[base_term].append(keyword)
        
        return dict(groups)
    
    def _extract_base_term(self, keyword: str) -> str:
        """Extract the base term from a keyword."""
        # Common patterns to identify base terms
        if 'password' in keyword.lower():
            return 'password'
        elif 'token' in keyword.lower():
            return 'token'
        elif 'key' in keyword.lower() and 'keyword' not in keyword.lower():
            return 'key'
        elif 'secret' in keyword.lower():
            return 'secret'
        elif 'credential' in keyword.lower():
            return 'credential'
        elif 'auth' in keyword.lower():
            return 'auth'
        elif 'api' in keyword.lower():
            return 'api'
        elif 'db' in keyword.lower() or 'database' in keyword.lower():
            return 'database'
        else:
            # Try to extract the last meaningful part
            parts = re.split(r'[_\-]', keyword)
            if len(parts) > 1:
                return parts[-1]
            return keyword
    
    def analyze_prefixes_suffixes(self) -> Tuple[Set[str], Set[str]]:
        """Analyze common prefixes and suffixes in keywords."""
        prefixes = defaultdict(int)
        suffixes = defaultdict(int)
        
        for keyword in self.all_keywords:
            parts = re.split(r'[_\-]', keyword)
            
            if len(parts) > 1:
                # Count prefixes
                prefixes[parts[0]] += 1
                # Count suffixes
                suffixes[parts[-1]] += 1
        
        # Get common prefixes/suffixes (appearing 3+ times)
        common_prefixes = {p for p, count in prefixes.items() if count >= 3}
        common_suffixes = {s for s, count in suffixes.items() if count >= 3}
        
        return common_prefixes, common_suffixes
    
    def suggest_pattern_consolidation(self) -> List[Dict[str, any]]:
        """Suggest how to consolidate keywords into patterns."""
        suggestions = []
        keyword_groups = self.analyze_keyword_patterns()
        
        for base_term, keywords in keyword_groups.items():
            if len(keywords) > 1:
                # Create regex pattern that matches all variations
                pattern_parts = []
                for kw in keywords:
                    # Escape special chars and replace underscore/dash with flexible pattern
                    escaped = re.escape(kw).replace(r'\_', '[_-]?').replace(r'\-', '[_-]?')
                    pattern_parts.append(escaped)
                
                # Combine into one pattern
                if len(pattern_parts) <= 5:
                    combined_pattern = '|'.join(pattern_parts)
                else:
                    # For many variations, create a more flexible pattern
                    # Extract the common pattern
                    if base_term in ['password', 'token', 'key', 'secret']:
                        combined_pattern = f"(?:.*[_-])?{base_term}(?:[_-].*)?"
                    else:
                        combined_pattern = '|'.join(pattern_parts[:5]) + '|...'
                
                suggestions.append({
                    'base_term': base_term,
                    'keywords': keywords,
                    'count': len(keywords),
                    'suggested_pattern': f"(?i)({combined_pattern})",
                    'categories': [cat for cat, kws in self.category_keywords.items() 
                                 if any(kw in kws for kw in keywords)]
                })
        
        return sorted(suggestions, key=lambda x: x['count'], reverse=True)
    
    def generate_report(self):
        """Generate analysis report."""
        print("=" * 80)
        print("SCAN4SECRETS KEYWORD ANALYSIS REPORT")
        print("=" * 80)
        
        # Basic stats
        print(f"\nTotal Categories: {len(self.patterns_data)}")
        print(f"Total Unique Keywords: {len(self.all_keywords)}")
        print(f"Total Keywords (with duplicates): {sum(len(kws) for kws in self.patterns_data.values())}")
        
        # Category breakdown
        print("\n\nKEYWORDS PER CATEGORY:")
        print("-" * 40)
        for category, keywords in sorted(self.patterns_data.items(), 
                                       key=lambda x: len(x[1]), reverse=True):
            print(f"{category:.<35} {len(keywords):>4} keywords")
        
        # Keyword groups
        print("\n\nKEYWORD GROUPING BY BASE TERM:")
        print("-" * 40)
        keyword_groups = self.analyze_keyword_patterns()
        for base_term, keywords in sorted(keyword_groups.items(), 
                                         key=lambda x: len(x[1]), reverse=True)[:20]:
            print(f"{base_term:.<20} {len(keywords):>4} variations")
            if len(keywords) <= 5:
                for kw in sorted(keywords):
                    print(f"  - {kw}")
        
        # Common prefixes/suffixes
        prefixes, suffixes = self.analyze_prefixes_suffixes()
        print("\n\nCOMMON PREFIXES:")
        print("-" * 40)
        for prefix in sorted(prefixes):
            print(f"  - {prefix}")
        
        print("\n\nCOMMON SUFFIXES:")
        print("-" * 40)
        for suffix in sorted(suffixes):
            print(f"  - {suffix}")
        
        # Pattern consolidation suggestions
        print("\n\nPATTERN CONSOLIDATION SUGGESTIONS:")
        print("-" * 80)
        suggestions = self.suggest_pattern_consolidation()
        for i, suggestion in enumerate(suggestions[:15], 1):
            print(f"\n{i}. Base Term: {suggestion['base_term']} ({suggestion['count']} keywords)")
            print(f"   Categories: {', '.join(suggestion['categories'])}")
            print(f"   Suggested Pattern: {suggestion['suggested_pattern']}")
            if suggestion['count'] <= 5:
                print("   Keywords:")
                for kw in suggestion['keywords']:
                    print(f"     - {kw}")
    
    def export_consolidated_patterns(self, output_file: str):
        """Export consolidated patterns in cred-scan format."""
        suggestions = self.suggest_pattern_consolidation()
        
        with open(output_file, 'w') as f:
            f.write("# Consolidated patterns from scan4secrets analysis\n\n")
            
            for suggestion in suggestions:
                if suggestion['count'] >= 2:  # Only consolidate if 2+ keywords
                    f.write(f"# {suggestion['base_term'].title()} patterns - "
                           f"{suggestion['count']} variations consolidated\n")
                    f.write(f"# Original keywords: {', '.join(suggestion['keywords'][:5])}")
                    if suggestion['count'] > 5:
                        f.write(f" and {suggestion['count']-5} more")
                    f.write("\n")
                    f.write(f"# Categories: {', '.join(suggestion['categories'])}\n")
                    f.write(f"pattern = r\"{suggestion['suggested_pattern']}\"\n\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_keywords.py <path_to_scan4secrets_patterns.json>")
        print("Example: python analyze_keywords.py ../scan4secrets/config/patterns.json")
        sys.exit(1)
    
    patterns_file = sys.argv[1]
    
    if not os.path.exists(patterns_file):
        print(f"Error: File not found - {patterns_file}")
        sys.exit(1)
    
    analyzer = KeywordAnalyzer(patterns_file)
    analyzer.generate_report()
    
    # Export consolidated patterns
    output_file = "consolidated_patterns.txt"
    analyzer.export_consolidated_patterns(output_file)
    print(f"\n\nConsolidated patterns exported to: {output_file}")


if __name__ == "__main__":
    main()