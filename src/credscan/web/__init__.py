"""
Web scanning module for credential detection in remote files and websites.
"""

from .crawler import WebCrawler
from .scanner import WebScanner

__all__ = ["WebScanner", "WebCrawler"]
