#!/usr/bin/env python3
"""Test script for enhanced patterns."""

import sys
import os
sys.path.insert(0, 'src')

try:
    from credscan.enhanced.config_integration import EnhancedConfig
    from credscan.enhanced.pattern_library import load_default_patterns
    print('✓ Enhanced modules imported successfully')
    
    # Test loading patterns
    patterns = load_default_patterns()
    print(f'✓ Loaded {len(patterns.categories)} pattern categories')
    for name, category in patterns.categories.items():
        print(f'  - {name}: {len(category.patterns)} patterns')
        
    # Test enhanced config
    config_data = {
        'scan_path': 'credential-test-file.txt',
        'verbose': False,
        'max_workers': 4
    }
    
    enhanced_config = EnhancedConfig(config_data)
    print('✓ Enhanced config created successfully')
    
    # Test creating enhanced engine
    engine = enhanced_config.create_enhanced_engine()
    print('✓ Enhanced engine created successfully')
    
except Exception as e:
    print(f'✗ Error: {e}')
    import traceback
    traceback.print_exc()