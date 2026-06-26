"""
Manage and deduplicate findings across git history.
"""

import hashlib
import logging
from typing import Any, Dict, List, Set

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
        self._id_by_hash = {}  # finding_hash -> finding_id, for window updates

    def process_commit_findings(
        self, commit_hash: str, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
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

                # Seed the exposure window. Commits are processed newest-first,
                # so the first time we see a credential is its most recent
                # appearance; older duplicates extend first_seen below.
                ts = finding.get("commit_timestamp", 0)
                finding["last_seen_commit"] = commit_hash
                finding["last_seen_timestamp"] = ts
                finding["first_seen_commit"] = commit_hash
                finding["first_seen_timestamp"] = ts
                finding["exposure_commit_count"] = 1

                # Track the finding (and remember its hash for window updates).
                self.findings[finding_id] = finding
                self.finding_hashes.add(finding_hash)
                self._id_by_hash[finding_hash] = finding_id

                unique_findings.append(finding)
            else:
                # Same credential seen in an earlier (older) commit: widen the
                # exposure window rather than dropping the duplicate. This is
                # what lets a finding report "exposed for N months across M
                # commits" instead of just a single commit.
                existing = self.findings.get(self._id_by_hash.get(finding_hash))
                if existing is not None:
                    ts = finding.get("commit_timestamp", 0)
                    existing["exposure_commit_count"] = (
                        existing.get("exposure_commit_count", 1) + 1
                    )
                    if ts and ts < existing.get("first_seen_timestamp", ts):
                        existing["first_seen_timestamp"] = ts
                        existing["first_seen_commit"] = commit_hash
                    if ts > existing.get("last_seen_timestamp", 0):
                        existing["last_seen_timestamp"] = ts
                        existing["last_seen_commit"] = commit_hash

        return unique_findings

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings from git history.

        Returns:
            List of all findings
        """
        # Convert dict to list and sort by commit timestamp (newest first)
        result = list(self.findings.values())
        for finding in result:
            finding["exposure_window"] = self._exposure_window(finding)
        result.sort(key=lambda x: x.get("commit_timestamp", 0), reverse=True)

        return result

    @staticmethod
    def _exposure_window(finding: Dict[str, Any]) -> str:
        """A one-line human summary of how long/widely a secret was exposed.

        A credential committed once lives in every clone forever; reporting the
        window ("exposed ~14 months across 6 commits") tells a responder how
        urgent rotation is and how far the blast radius reaches.
        """
        first = finding.get("first_seen_timestamp", 0)
        last = finding.get("last_seen_timestamp", 0)
        count = finding.get("exposure_commit_count", 1)
        commits = f"{count} commit" + ("s" if count != 1 else "")
        if not first or not last:
            return f"seen in {commits}"
        span_days = max(0, (last - first) // 86400)
        if span_days >= 60:
            dur = f"~{span_days // 30} months"
        elif span_days >= 1:
            dur = f"{span_days} day" + ("s" if span_days != 1 else "")
        else:
            dur = "a single day"
        return f"exposed {dur} across {commits}"

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
            str(finding.get("value", "")),
        ]

        # Extra debugging for unexpected None values
        for i, component in enumerate(hash_components):
            if component == "None":  # This means the original value was None
                logger.debug(
                    f"Warning: None value in finding hash component {i}: {finding}"
                )

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
