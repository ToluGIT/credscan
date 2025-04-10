"""
Core engine and base components for credential detection.
"""
from .engine import ScanEngine
from .parser_base import BaseParser

__all__ = ['ScanEngine', 'BaseParser']
