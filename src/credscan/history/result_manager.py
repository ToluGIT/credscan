"""
Manage and deduplicate findings across git history.
"""
import hashlib
import logging
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

class HistoryResultManager:
    """
    Manages findings from git history scanning.
    """
    
    def __init__(self):
        """
        Initialize the history result manager.
        """
        self.findings = {}  # Dict of finding_id -> finding
        self.finding_hashes = set()  # Set of finding hashes for deduplication
    
    def process_commit_findings(self, commit_hash: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and deduplicate findings from a commit.
        
        Args:
            commit_hash: The commit hash
            findings: List of findings from the commit
            
        Returns:
            List of unique (new) findings
        """
        unique_findings = []
        
        for finding in findings:
            # Generate a hash for deduplication
            finding_hash = self._generate_finding_hash(finding)
            
            # If this is a new unique finding, add it
            if finding_hash not in self.finding_hashes:
                # Add unique ID to finding
                finding_id = self._generate_id()
                finding["id"] = finding_id
                
                # Track the finding
                self.findings[finding_id] = finding
                self.finding_hashes.add(finding_hash)
                
                unique_findings.append(finding)
        
        return unique_findings
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings from git history.
        
        Returns:
            List of all findings
        """
        # Convert dict to list and sort by commit timestamp (newest first)
        result = list(self.findings.values())
        result.sort(key=lambda x: x.get("commit_timestamp", 0), reverse=True)
        
        return result
    
    def _generate_finding_hash(self, finding: Dict[str, Any]) -> str:
        """
        Generate a hash for a finding to identify duplicates.
        
        Args:
            finding: The finding to hash
            
        Returns:
            Hash string for the finding
        """
        # Construct a string combining key properties that identify a unique finding
        hash_components = [
            str(finding.get("rule_id", "")),
            str(finding.get("original_file", "")),
            str(finding.get("variable", "")),
            str(finding.get("value", ""))
        ]
        
        # Extra debugging for unexpected None values
        for i, component in enumerate(hash_components):
            if component == 'None':  # This means the original value was None
                logger.debug(f"Warning: None value in finding hash component {i}: {finding}")
        
        hash_str = "|".join(hash_components)
        return hashlib.md5(hash_str.encode()).hexdigest()
    
    def _generate_id(self) -> str:
        """
        Generate a unique ID for a finding.
        
        Returns:
            Unique ID string
        """
        import uuid
        return f"hist-{uuid.uuid4()}"
