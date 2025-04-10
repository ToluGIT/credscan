"""
Generic code file parser for credential detection.
"""
import re
from typing import Dict, Any, List, Tuple, Set
import logging
import os
# Use absolute import instead of relative
from  credscan.core.parser_base import BaseParser

logger = logging.getLogger(__name__)

class CodeParser(BaseParser):
    """
    Parser for generic code files.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the parser with configuration.
        
        Args:
            config: Configuration for the parser
        """
        super().__init__(config)
        
        # Define supported file extensions
        self.supported_extensions = self.config.get('code_extensions', [
            '.py', '.js', '.java', '.go', '.php', '.rb', '.cs', '.cpp', '.c', 
            '.h', '.swift', '.kt', '.ts', '.sh', '.bash', '.pl', '.pm'
        ])
        
        # Regular expressions for parsing
        self.string_pattern = re.compile(r'(["\'])((?:\\.|(?!\1).)*)\1')
        self.assignment_pattern = re.compile(r'(?:const|var|let|private|public|protected)?\s*(\w+)\s*[=:]\s*(["\'])((?:\\.|(?!\2).)*)\2')
        self.single_line_comment_markers = {
            '.py': '#',
            '.rb': '#',
            '.sh': '#', 
            '.bash': '#',
            '.js': '//',
            '.ts': '//',
            '.java': '//',
            '.cpp': '//', 
            '.c': '//', 
            '.cs': '//',
            '.go': '//', 
            '.swift': '//', 
            '.php': ['#', '//'],
            '.kt': '//',
        }
        self.multi_line_comment_markers = {
            '.js': {'start': '/*', 'end': '*/'},
            '.ts': {'start': '/*', 'end': '*/'},
            '.java': {'start': '/*', 'end': '*/'},
            '.cpp': {'start': '/*', 'end': '*/'},
            '.c': {'start': '/*', 'end': '*/'},
            '.cs': {'start': '/*', 'end': '*/'},
            '.go': {'start': '/*', 'end': '*/'},
            '.swift': {'start': '/*', 'end': '*/'},
            '.php': {'start': '/*', 'end': '*/'},
            '.kt': {'start': '/*', 'end': '*/'},
            '.py': {'start': '"""', 'end': '"""'}
        }
    
    def can_parse(self, filepath: str) -> bool:
        """
        Check if the file is a supported code file.
        
        Args:
            filepath: Path to the file
            
        Returns:
            bool: True if it's a supported code file, False otherwise
        """
        ext = self.get_file_extension(filepath)
        return ext in self.supported_extensions
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """
        Parse a code file and extract variables, comments, and string literals.
        
        Args:
            filepath: Path to the code file
            
        Returns:
            Dict containing the structured content and metadata
        """
        content = self.read_file(filepath)
        if not content:
            return {"type": "code", "path": filepath, "content": None, "error": "Empty file"}
        
        ext = self.get_file_extension(filepath)
        
        # Add debug logging
        logger.debug(f"Parsing code file: {filepath}")
        logger.debug(f"File content first 100 chars: {content[:100]}")
        
        try:
            # Parse the file line by line
            variables = []
            comments = []
            string_literals = []
            
            lines = content.split('\n')
            logger.debug(f"File has {len(lines)} lines")
            
            in_multiline_comment = False
            multiline_comment_content = []
            multiline_comment_start_line = 0
            
            for line_num, line in enumerate(lines, 1):
                # Handle the end of multiline comments
                if in_multiline_comment:
                    multiline_comment_content.append(line)
                    if self.multi_line_comment_markers.get(ext, {}).get('end', '') in line:
                        comment_text = '\n'.join(multiline_comment_content)
                        comments.append({
                            "line": multiline_comment_start_line,
                            "text": comment_text,
                            "type": "multi_line_comment"
                        })
                        in_multiline_comment = False
                        multiline_comment_content = []
                    continue
                
                # Check for the start of multiline comments
                if ext in self.multi_line_comment_markers and self.multi_line_comment_markers[ext]['start'] in line:
                    start_marker = self.multi_line_comment_markers[ext]['start']
                    end_marker = self.multi_line_comment_markers[ext]['end']
                    
                    # Check if the comment starts and ends on the same line
                    if start_marker in line and end_marker in line and line.find(start_marker) < line.find(end_marker):
                        # Extract the comment
                        start_idx = line.find(start_marker)
                        end_idx = line.find(end_marker, start_idx + len(start_marker)) + len(end_marker)
                        comment_text = line[start_idx:end_idx]
                        
                        comments.append({
                            "line": line_num,
                            "text": comment_text,
                            "type": "multi_line_comment"
                        })
                    else:
                        in_multiline_comment = True
                        multiline_comment_start_line = line_num
                        multiline_comment_content.append(line)
                        continue
                
                # Check for single line comments
                comment_markers = self.single_line_comment_markers.get(ext, [])
                if not isinstance(comment_markers, list):
                    comment_markers = [comment_markers]
                
                for marker in comment_markers:
                    if marker and marker in line:
                        comment_text = line[line.find(marker):]
                        comments.append({
                            "line": line_num,
                            "text": comment_text,
                            "type": "single_line_comment"
                        })
                        # Remove the comment for further processing
                        line = line[:line.find(marker)]
                        break
                
                # Extract variable assignments
                for match in self.assignment_pattern.finditer(line):
                    var_name, _, var_value = match.groups()
                    logger.debug(f"Found variable: {var_name} = {var_value} at line {line_num}")
                    variables.append({
                        "line": line_num,
                        "name": var_name,
                        "value": var_value,
                        "type": "variable"
                    })
                
                # Extract string literals
                for match in self.string_pattern.finditer(line):
                    _, string_value = match.groups()
                    if string_value:  # Ignore empty strings
                        string_literals.append({
                            "line": line_num,
                            "value": string_value,
                            "type": "string_literal"
                        })
            
            # At the end, log what we found
            logger.debug(f"Extracted {len(variables)} variables, {len(comments)} comments, {len(string_literals)} string literals")
            
            # Create result object
            result = {
                "type": "code",
                "language": ext[1:] if ext else "unknown",  # Remove the leading dot
                "path": filepath,
                "variables": variables,
                "comments": comments,
                "string_literals": string_literals,
                "items": [],  # Will contain flattened items for rule processing
                "error": None
            }
            
            # Flatten items for easier rule processing
            for var in variables:
                result["items"].append({
                    "key": var["name"],
                    "value": var["value"],
                    "line": var["line"],
                    "type": "variable"
                })
            
            for comment in comments:
                result["items"].append({
                    "key": None,
                    "value": comment["text"],
                    "line": comment["line"],
                    "type": "comment"
                })
            
            for string in string_literals:
                result["items"].append({
                    "key": None,
                    "value": string["value"],
                    "line": string["line"],
                    "type": "string_literal"
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing code file {filepath}: {e}")
            return {
                "type": "code",
                "path": filepath,
                "content": None,
                "error": f"Parse error: {str(e)}"
            }