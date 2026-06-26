"""
Build a fully-configured scan engine from a plain config dict.

This is the shared construction path used by the GUI/API (and available to any
non-CLI caller). It mirrors the parser/analyzer registration and enhanced +
context-aware wrapping that the CLI performs, but takes a config dict instead of
argparse arguments so it has no CLI dependency.
"""

from typing import Any, Dict


def build_scan_engine(config: Dict[str, Any]):
    """Construct the default (enhanced, context-aware) scan engine.

    Honors the same toggles the CLI uses, read from the config dict:
      no_binary_parsing, enable_entropy, enable_context_analysis, and the
      enhanced-detection settings consumed by EnhancedConfig.
    """
    from credscan.analyzers.entropy import EntropyAnalyzer
    from credscan.core.engine import ScanEngine
    from credscan.parsers.binary_parser import BinaryFileParser
    from credscan.parsers.cicd_parser import CICDParser
    from credscan.parsers.code_parser import CodeParser
    from credscan.parsers.docker_parser import DockerParser
    from credscan.parsers.iac_parser import IaCParser
    from credscan.parsers.json_parser import JSONParser
    from credscan.parsers.yaml_parser import YAMLParser

    base_engine = ScanEngine(config)

    if not config.get("no_binary_parsing", False):
        base_engine.register_parser(BinaryFileParser(config))

    # Specialised parsers before generic ones so they claim their file types.
    base_engine.register_parser(DockerParser(config))
    base_engine.register_parser(IaCParser(config))
    base_engine.register_parser(CICDParser(config))
    base_engine.register_parser(JSONParser(config))
    base_engine.register_parser(YAMLParser(config))
    base_engine.register_parser(CodeParser(config))

    if config.get("enable_entropy", True):
        base_engine.register_analyzer(EntropyAnalyzer(config))

    # Enhanced detection (pattern library + entropy) wrapped, then context-aware.
    from credscan.enhanced.config_integration import EnhancedConfig

    enhanced = EnhancedConfig(config).create_enhanced_engine()
    # Carry over the parsers/analyzers registered on the base engine.
    for parser in base_engine.parsers:
        enhanced.register_parser(parser)
    for analyzer in getattr(base_engine, "analyzers", []):
        enhanced.register_analyzer(analyzer)

    if config.get("enable_context_analysis", True):
        from credscan.enhanced.context_aware_engine import ContextAwareEngine

        return ContextAwareEngine(enhanced, config)
    return enhanced
