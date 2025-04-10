"""
YAML file parser for credential detection.
"""
import yaml
from typing import Dict, Any, List, Optional
import logging
# Use absolute import instead of relative
from  credscan.core.parser_base import BaseParser

logger = logging.getLogger(__name__)

class YAMLParser(BaseParser):
    """
    Parser for YAML files.
    """
    
    def can_parse(self, filepath: str) -> bool:
        """
        Check if the file is a YAML file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            bool: True if it's a YAML file, False otherwise
        """
        ext = self.get_file_extension(filepath)
        return ext in ('.yaml', '.yml')
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """
        Parse a YAML file and return its structure.
        
        Args:
            filepath: Path to the YAML file
            
        Returns:
            Dict containing the structured content and metadata
        """
        content = self.read_file(filepath)
        if not content:
            return {"type": "yaml", "path": filepath, "content": None, "error": "Empty file"}
        
        try:
            parsed = yaml.safe_load(content)
            
            # Create a result object with metadata
            result = {
                "type": "yaml",
                "path": filepath,
                "content": parsed,
                "items": [],
                "error": None
            }
            
            # Extract key-value pairs for easier processing
            self.extract_pairs(parsed, result["items"])
            
            return result
            
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {filepath}: {e}")
            return {
                "type": "yaml",
                "path": filepath,
                "content": None,
                "error": f"YAML parse error: {str(e)}"
            }
    
    def extract_pairs(self, data: Any, items: List[Dict[str, Any]], parent_path: str = "") -> None:
        """
        Recursively extract key-value pairs from YAML data.
        
        Args:
            data: YAML data object (dict, list, or primitive)
            items: List to collect key-value pairs
            parent_path: Path of parent keys
        """
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{parent_path}.{key}" if parent_path else key
                
                if isinstance(value, (str, int, float, bool)) and value is not None:
                    items.append({
                        "key": key,
                        "value": str(value),
                        "path": current_path,
                        "type": "property"
                    })
                
                # Recurse into nested structures
                self.extract_pairs(value, items, current_path)
                
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{parent_path}[{i}]"
                
                if isinstance(item, (str, int, float, bool)) and item is not None:
                    items.append({
                        "key": None,
                        "value": str(item),
                        "path": current_path,
                        "type": "list_item" 
                    })
                
                # Recurse into nested structures
                self.extract_pairs(item, items, current_path)