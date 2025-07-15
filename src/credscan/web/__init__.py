"""
Web scanning module for credential detection in remote files and websites.
"""

from .scanner import WebScanner
from .crawler import WebCrawler

__all__ = ['WebScanner', 'WebCrawler']