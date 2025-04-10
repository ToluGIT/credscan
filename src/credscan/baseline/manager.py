"""
Baseline manager for handling false positive exclusions.
"""
import hashlib
import json
import datetime
import re
import os
from typing import Dict, Any, List, Set, Optional, Pattern

class BaselineManager:
    """
    Manages false positive baselines for credential detection.
    """
    
    def __init__(self, baseline_file: Optional[str] = None):
        """
        Initialize the baseline manager.
        
        Args:
            baseline_file: Path to the baseline file
        """
        self.baseline_file = baseline_file
        self.exclusions = {
            "findings": [],
            "patterns": [],
            "paths": []
        }
        self.pattern_regexes = []
        self.path_regexes = []
        
        # Load baseline if provided
        if baseline_file and os.path.exists(baseline_file):
            self.load_baseline()
    
    def load_baseline(self) -> bool:
        """
        Load baseline from file.
        
        Returns:
            bool: True if baseline was loaded successfully
        """
        try:
            with open(self.baseline_file, 'r') as f:
                data = json.load(f)
                
            self.exclusions = data.get("exclusions", {
                "findings": [],
                "patterns": [],
                "paths": []
            })
            
            # Compile regexes for pattern matching
            self.pattern_regexes = [
                (p["id"], re.compile(p["pattern"])) 
                for p in self.exclusions.get("patterns", [])
            ]
            
            # Compile regexes for path matching
            self.path_regexes = [
                (p["id"], re.compile(p["path_pattern"])) 
                for p in self.exclusions.get("paths", [])
            ]
            
            return True
        except Exception as e:
            print(f"Error loading baseline: {e}")
            return False
    
    def save_baseline(self, metadata: Dict[str, Any] = None) -> bool:
        """
        Save baseline to file.
        
        Args:
            metadata: Additional metadata to include
            
        Returns:
            bool: True if baseline was saved successfully
        """
        if not self.baseline_file:
            return False
            
        try:
            # Prepare metadata
            now = datetime.datetime.now().isoformat()
            meta = {
                "updated_at": now
            }
            
            if metadata:
                meta.update(metadata)
                
            # If this is a new file, add created_at
            if not os.path.exists(self.baseline_file):
                meta["created_at"] = now
                
            # Create full baseline object
            baseline = {
                "version": 1,
                "metadata": meta,
                "exclusions": self.exclusions
            }
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(self.baseline_file)), exist_ok=True)
            
            # Write to file
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
                
            return True
        except Exception as e:
            print(f"Error saving baseline: {e}")
            return False
    
    def is_excluded(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if a finding is excluded by the baseline.
        
        Args:
            finding: The finding to check
            
        Returns:
            Dict with 'excluded' (bool) and 'reason' (str) if excluded
        """
        # Check if the exact finding is excluded
        value_hash = self._hash_value(finding.get("value", ""))
        path = finding.get("path", "")
        line = finding.get("line", 0)
        
        # 1. Check exact finding matches
        for excluded in self.exclusions.get("findings", []):
            if (excluded.get("path") == path and 
                excluded.get("line") == line and 
                excluded.get("value_hash") == value_hash):
                return {
                    "excluded": True, 
                    "reason": excluded.get("reason", "Baseline match"),
                    "id": excluded.get("id")
                }
        
        # 2. Check pattern exclusions
        value = finding.get("value", "")
        for pattern_id, pattern in self.pattern_regexes:
            if pattern.search(value):
                return {
                    "excluded": True,
                    "reason": f"Pattern match: {pattern_id}",
                    "id": pattern_id
                }
        
        # 3. Check path exclusions
        for path_id, path_pattern in self.path_regexes:
            if path_pattern.search(path):
                return {
                    "excluded": True,
                    "reason": f"Path exclusion: {path_id}",
                    "id": path_id
                }
        
        return {"excluded": False}
    
    def add_finding_exclusion(self, finding: Dict[str, Any], reason: str) -> str:
        """
        Add a finding to the exclusions list.
        
        Args:
            finding: The finding to exclude
            reason: Reason for exclusion
            
        Returns:
            str: ID of the new exclusion
        """
        # Generate a unique ID for this exclusion
        exclusion_id = self._generate_id()
        
        # Create an exclusion entry
        exclusion = {
            "id": exclusion_id,
            "rule_id": finding.get("rule_id", "unknown"),
            "path": finding.get("path", ""),
            "line": finding.get("line", 0),
            "value_hash": self._hash_value(finding.get("value", "")),
            "reason": reason,
            "added_at": datetime.datetime.now().isoformat()
        }
        
        # Add to exclusions
        self.exclusions["findings"].append(exclusion)
        
        return exclusion_id
    
    def add_pattern_exclusion(self, pattern: str, reason: str) -> str:
        """
        Add a pattern to the exclusions list.
        
        Args:
            pattern: Regex pattern to exclude
            reason: Reason for exclusion
            
        Returns:
            str: ID of the new exclusion
        """
        # Validate pattern
        try:
            re.compile(pattern)
        except re.error:
            raise ValueError(f"Invalid regex pattern: {pattern}")
        
        # Generate a unique ID
        exclusion_id = self._generate_id("p")
        
        # Create an exclusion entry
        exclusion = {
            "id": exclusion_id,
            "pattern": pattern,
            "reason": reason,
            "added_at": datetime.datetime.now().isoformat()
        }
        
        # Add to exclusions
        self.exclusions["patterns"].append(exclusion)
        
        # Update compiled regexes
        self.pattern_regexes.append((exclusion_id, re.compile(pattern)))
        
        return exclusion_id
    
    def add_path_exclusion(self, path_pattern: str, reason: str) -> str:
        """
        Add a path pattern to the exclusions list.
        
        Args:
            path_pattern: Path pattern to exclude
            reason: Reason for exclusion
            
        Returns:
            str: ID of the new exclusion
        """
        # Validate pattern
        try:
            re.compile(path_pattern)
        except re.error:
            raise ValueError(f"Invalid regex pattern: {path_pattern}")
        
        # Generate a unique ID
        exclusion_id = self._generate_id("d")
        
        # Create an exclusion entry
        exclusion = {
            "id": exclusion_id,
            "path_pattern": path_pattern,
            "reason": reason,
            "added_at": datetime.datetime.now().isoformat()
        }
        
        # Add to exclusions
        self.exclusions["paths"].append(exclusion)
        
        # Update compiled regexes
        self.path_regexes.append((exclusion_id, re.compile(path_pattern)))
        
        return exclusion_id
    
    def remove_exclusion(self, exclusion_id: str) -> bool:
        """
        Remove an exclusion by ID.
        
        Args:
            exclusion_id: ID of the exclusion to remove
            
        Returns:
            bool: True if exclusion was removed
        """
        # Check findings
        for i, excl in enumerate(self.exclusions["findings"]):
            if excl.get("id") == exclusion_id:
                del self.exclusions["findings"][i]
                return True
        
        # Check patterns
        for i, excl in enumerate(self.exclusions["patterns"]):
            if excl.get("id") == exclusion_id:
                del self.exclusions["patterns"][i]
                # Update compiled regexes
                self.pattern_regexes = [(id, p) for id, p in self.pattern_regexes if id != exclusion_id]
                return True
        
        # Check paths
        for i, excl in enumerate(self.exclusions["paths"]):
            if excl.get("id") == exclusion_id:
                del self.exclusions["paths"][i]
                # Update compiled regexes
                self.path_regexes = [(id, p) for id, p in self.path_regexes if id != exclusion_id]
                return True
        
        return False
    
    def _hash_value(self, value: str) -> str:
        """Generate a hash of a value."""
        return hashlib.sha256(value.encode()).hexdigest()
    
    def _generate_id(self, prefix: str = "") -> str:
        """Generate a unique ID."""
        import random
        import string
        chars = string.ascii_lowercase + string.digits
        random_str = ''.join(random.choice(chars) for _ in range(16))
        return f"{prefix}{random_str}"
