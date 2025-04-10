"""
Base parser interface for credential detection.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import os
import logging

logger = logging.getLogger(__name__)

class BaseParser(ABC):
    """
    Abstract base class for file parsers.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the parser with configuration.
        
        Args:
            config: Configuration for the parser
        """
        self.config = config or {}
    
    @abstractmethod
    def can_parse(self, filepath: str) -> bool:
        """
        Determine if this parser can handle the given file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            bool: True if the parser can handle this file, False otherwise
        """
        pass
    
    @abstractmethod
    def parse(self, filepath: str) -> Dict[str, Any]:
        """
        Parse the file and return structured content.
        
        Args:
            filepath: Path to the file
            
        Returns:
            Dict containing the structured content and metadata
        """
        pass
    
    def get_file_extension(self, filepath: str) -> str:
        """
        Get the file extension from a filepath.
        
        Args:
            filepath: Path to the file
            
        Returns:
            str: File extension (lowercase, with dot)
        """
        _, ext = os.path.splitext(filepath)
        return ext.lower()
    
    def get_file_name(self, filepath: str) -> str:
        """
        Get the file name from a filepath.
        
        Args:
            filepath: Path to the file
            
        Returns:
            str: File name without path
        """
        return os.path.basename(filepath)
    
    def read_file(self, filepath: str) -> str:
        """
        Read a file and return its contents.
        
        Args:
            filepath: Path to the file
            
        Returns:
            str: File contents
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")
            return ""
