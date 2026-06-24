"""
Enhanced pattern detection for credential scanning.
"""

# Finally config integration (depends on all the above)
from .config_integration import EnhancedConfig, get_example_config

# Then import from pattern_library (depends on pattern_structure)
from .pattern_library import (
    load_default_patterns,
    load_patterns_from_file,
    merge_pattern_libraries,
    save_patterns_to_file,
)

# Import from pattern_structure first (no dependencies)
from .pattern_structure import CredentialPattern, PatternCategory, PatternLibrary

# Then rule integration (depends on pattern_library and pattern_structure)
from .rule_engine_integration import (
    EnhancedRule,
    EnhancedRuleLoader,
    EnhancedScanEngine,
)
