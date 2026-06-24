"""
Context-aware analyzer that understands code structure and environment
to improve credential detection accuracy and reduce false positives.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ContextAnalyzer:
    """Analyzes code and configuration context to improve detection accuracy."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the context analyzer."""
        self.config = config or {}
        self.context_patterns = self._load_context_patterns()
        self.compiled_patterns = self._compile_patterns()

        # Context analysis settings
        self.context_window_size = self.config.get(
            "context_window_size", 5
        )  # Lines before/after
        self.min_confidence_threshold = self.config.get("min_confidence_threshold", 0.1)
        self.max_confidence_multiplier = self.config.get(
            "max_confidence_multiplier", 2.0
        )

    def _load_context_patterns(self) -> Dict[str, Any]:
        """Load context patterns from configuration file."""
        try:
            from credscan.config_paths import config_file

            patterns_file = config_file("context_patterns.json")

            if os.path.exists(patterns_file):
                with open(patterns_file, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load context patterns: {e}")

        return {}

    def _compile_patterns(self) -> Dict[str, Dict[str, List[re.Pattern]]]:
        """Compile regex patterns for each context category."""
        compiled = {}

        for context_category, contexts in self.context_patterns.items():
            compiled[context_category] = {}

            for context_name, context_data in contexts.items():
                patterns = context_data.get("patterns", [])
                compiled_patterns = []

                for pattern in patterns:
                    try:
                        compiled_patterns.append(
                            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                        )
                    except re.error as e:
                        logger.warning(
                            f"Invalid regex pattern '{pattern}' in {context_category}.{context_name}: {e}"
                        )

                compiled[context_category][context_name] = compiled_patterns

        return compiled

    def analyze_context(
        self,
        file_path: str,
        content: str,
        finding_line: int,
        finding_key: str = None,
        finding_value: str = None,
    ) -> Dict[str, Any]:
        """
        Analyze the context around a potential credential finding.

        Args:
            file_path: Path to the file being analyzed
            content: Full file content
            finding_line: Line number of the finding (1-based)
            finding_key: Variable name or key (if available)
            finding_value: The potential credential value

        Returns:
            Dictionary containing context analysis results
        """
        context_result = {
            "file_context": self._analyze_file_context(file_path),
            "code_context": self._analyze_code_context(content, finding_line),
            "config_context": self._analyze_config_context(
                content, finding_line, file_path
            ),
            "api_context": self._analyze_api_context(content, finding_line),
            "framework_context": self._analyze_framework_context(content, file_path),
            "confidence_modifier": 1.0,
            "risk_level": "medium",
            "context_type": "unknown",
            "reasons": [],
        }

        # Calculate overall confidence modifier and determine primary context
        context_result["confidence_modifier"] = self._calculate_confidence_modifier(
            context_result
        )
        context_result["risk_level"] = self._determine_risk_level(context_result)
        context_result["context_type"] = self._determine_primary_context(context_result)

        return context_result

    def _analyze_file_context(self, file_path: str) -> Dict[str, Any]:
        """Analyze file path and name for context clues."""
        file_path_lower = file_path.lower()
        filename = os.path.basename(file_path_lower)
        directory = os.path.dirname(file_path_lower)

        detected_contexts = []
        confidence_modifiers = []

        # Check file and directory patterns
        for context_name, context_data in self.context_patterns.get(
            "file_contexts", {}
        ).items():
            patterns = context_data.get("patterns", [])
            modifier = context_data.get("confidence_modifier", 1.0)

            for pattern in patterns:
                if pattern in filename or pattern in directory:
                    detected_contexts.append(context_name)
                    confidence_modifiers.append(modifier)
                    break

        # Special file type analysis
        file_extension = Path(file_path).suffix.lower()
        special_files = {
            ".env": ("environment_config", 1.4),
            "dockerfile": ("docker", 1.3),
            ".tf": ("terraform", 1.3),
            ".tfvars": ("terraform", 1.3),
            "docker-compose.yml": ("docker", 1.3),
            "docker-compose.yaml": ("docker", 1.3),
            ".k8s.yml": ("kubernetes", 1.4),
            ".k8s.yaml": ("kubernetes", 1.4),
        }

        if file_extension in special_files or any(
            sf in filename for sf in special_files.keys()
        ):
            for special_file, (context, modifier) in special_files.items():
                if file_extension == special_file or special_file in filename:
                    detected_contexts.append(context)
                    confidence_modifiers.append(modifier)

        return {
            "detected_contexts": detected_contexts,
            "confidence_modifiers": confidence_modifiers,
            "file_extension": file_extension,
            "filename": filename,
            "directory": directory,
        }

    def _analyze_code_context(self, content: str, finding_line: int) -> Dict[str, Any]:
        """Analyze code context around the finding."""
        lines = content.splitlines()
        if not lines or finding_line < 1 or finding_line > len(lines):
            return {"detected_contexts": [], "confidence_modifiers": []}

        # Get context window around the finding
        start_line = max(0, finding_line - 1 - self.context_window_size)
        end_line = min(len(lines), finding_line + self.context_window_size)
        context_lines = lines[start_line:end_line]
        context_text = "\n".join(context_lines)

        detected_contexts = []
        confidence_modifiers = []

        # Check code context patterns
        for context_name, patterns in self.compiled_patterns.get(
            "code_contexts", {}
        ).items():
            context_data = self.context_patterns["code_contexts"][context_name]
            modifier = context_data.get("confidence_modifier", 1.0)

            for pattern in patterns:
                try:
                    if pattern.search(context_text):
                        detected_contexts.append(context_name)
                        confidence_modifiers.append(modifier)
                        break
                except re.error as e:
                    logger.debug(f"Regex error in context analysis: {e}")
                    continue

        return {
            "detected_contexts": detected_contexts,
            "confidence_modifiers": confidence_modifiers,
            "context_window": context_text,
            "line_content": (
                lines[finding_line - 1] if finding_line <= len(lines) else ""
            ),
        }

    def _analyze_config_context(
        self, content: str, finding_line: int, file_path: str
    ) -> Dict[str, Any]:
        """Analyze configuration file context."""
        detected_contexts = []
        confidence_modifiers = []

        # Only analyze if this looks like a configuration file
        config_extensions = {
            ".yaml",
            ".yml",
            ".json",
            ".toml",
            ".ini",
            ".conf",
            ".cfg",
            ".env",
        }
        file_extension = Path(file_path).suffix.lower()

        if (
            file_extension not in config_extensions
            and "config" not in file_path.lower()
        ):
            return {
                "detected_contexts": detected_contexts,
                "confidence_modifiers": confidence_modifiers,
            }

        lines = content.splitlines()
        if not lines or finding_line < 1 or finding_line > len(lines):
            return {
                "detected_contexts": detected_contexts,
                "confidence_modifiers": confidence_modifiers,
            }

        # Analyze the structure around the finding
        context_start = max(
            0, finding_line - 10
        )  # Look further back for config structure
        context_lines = lines[context_start : finding_line + 5]
        context_text = "\n".join(context_lines)

        # Check config context patterns
        for context_name, patterns in self.compiled_patterns.get(
            "config_contexts", {}
        ).items():
            context_data = self.context_patterns["config_contexts"][context_name]
            modifier = context_data.get("confidence_modifier", 1.0)

            for pattern in patterns:
                try:
                    if pattern.search(context_text):
                        detected_contexts.append(context_name)
                        confidence_modifiers.append(modifier)
                        break
                except re.error as e:
                    logger.debug(f"Regex error in context analysis: {e}")
                    continue

        return {
            "detected_contexts": detected_contexts,
            "confidence_modifiers": confidence_modifiers,
            "config_section": self._identify_config_section(context_text),
            "is_config_file": True,
        }

    def _analyze_api_context(self, content: str, finding_line: int) -> Dict[str, Any]:
        """Analyze API-related context around the finding."""
        lines = content.splitlines()
        if not lines or finding_line < 1 or finding_line > len(lines):
            return {"detected_contexts": [], "confidence_modifiers": []}

        # Larger context window for API patterns
        start_line = max(0, finding_line - 1 - 10)
        end_line = min(len(lines), finding_line + 10)
        context_lines = lines[start_line:end_line]
        context_text = "\n".join(context_lines)

        detected_contexts = []
        confidence_modifiers = []

        # Check API context patterns
        for context_name, patterns in self.compiled_patterns.get(
            "api_contexts", {}
        ).items():
            context_data = self.context_patterns["api_contexts"][context_name]
            modifier = context_data.get("confidence_modifier", 1.0)

            for pattern in patterns:
                try:
                    if pattern.search(context_text):
                        detected_contexts.append(context_name)
                        confidence_modifiers.append(modifier)
                        break
                except re.error as e:
                    logger.debug(f"Regex error in context analysis: {e}")
                    continue

        return {
            "detected_contexts": detected_contexts,
            "confidence_modifiers": confidence_modifiers,
            "api_patterns_found": len(detected_contexts) > 0,
        }

    def _analyze_framework_context(
        self, content: str, file_path: str
    ) -> Dict[str, Any]:
        """Analyze framework-specific context."""
        detected_contexts = []
        confidence_modifiers = []

        # Check framework context patterns
        for context_name, patterns in self.compiled_patterns.get(
            "framework_contexts", {}
        ).items():
            context_data = self.context_patterns["framework_contexts"][context_name]
            modifier = context_data.get("confidence_modifier", 1.0)

            # Check both content and file path
            found_in_content = any(pattern.search(content) for pattern in patterns)
            found_in_path = any(
                pattern.search(file_path.lower())
                for pattern in patterns
                if hasattr(pattern, "search")
            )

            if found_in_content or found_in_path:
                detected_contexts.append(context_name)
                confidence_modifiers.append(modifier)

        return {
            "detected_contexts": detected_contexts,
            "confidence_modifiers": confidence_modifiers,
            "frameworks_detected": detected_contexts,
        }

    def _identify_config_section(self, context_text: str) -> str:
        """Identify which configuration section the finding is in."""
        # Look for YAML-style section headers
        section_patterns = [
            r"^\s*([a-zA-Z_][a-zA-Z0-9_]*):",  # YAML section
            r"^\s*\[([^\]]+)\]",  # INI section
            r'^\s*"([^"]+)"\s*:',  # JSON section
        ]

        lines = context_text.split("\n")
        current_section = "root"

        for line in reversed(lines):  # Look backwards for section headers
            for pattern in section_patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)

        return current_section

    def _calculate_confidence_modifier(self, context_result: Dict[str, Any]) -> float:
        """Calculate overall confidence modifier based on all context analysis."""
        all_modifiers = []

        # Collect all confidence modifiers
        for context_type in [
            "file_context",
            "code_context",
            "config_context",
            "api_context",
            "framework_context",
        ]:
            modifiers = context_result[context_type].get("confidence_modifiers", [])
            all_modifiers.extend(modifiers)

        if not all_modifiers:
            return 1.0

        # Calculate weighted average, giving more weight to stronger indicators
        sorted_modifiers = sorted(all_modifiers, reverse=True)

        if len(sorted_modifiers) == 1:
            final_modifier = sorted_modifiers[0]
        else:
            # Weight the strongest modifier more heavily
            weights = [0.5, 0.3] + [0.2 / (len(sorted_modifiers) - 2)] * (
                len(sorted_modifiers) - 2
            )
            final_modifier = sum(
                mod * weight for mod, weight in zip(sorted_modifiers, weights)
            )

        # Clamp to reasonable bounds
        return max(
            self.min_confidence_threshold,
            min(self.max_confidence_multiplier, final_modifier),
        )

    def _determine_risk_level(self, context_result: Dict[str, Any]) -> str:
        """Determine overall risk level based on context."""
        confidence_modifier = context_result["confidence_modifier"]

        # Check for production indicators
        file_contexts = context_result["file_context"]["detected_contexts"]
        if "production_indicators" in file_contexts:
            return "high"
        elif "staging_indicators" in file_contexts:
            return "medium"
        elif (
            "test_indicators" in file_contexts
            or "development_indicators" in file_contexts
        ):
            return "low"

        # Base on confidence modifier
        if confidence_modifier >= 1.5:
            return "high"
        elif confidence_modifier >= 1.0:
            return "medium"
        else:
            return "low"

    def _determine_primary_context(self, context_result: Dict[str, Any]) -> str:
        """Determine the primary context type for the finding."""
        # Priority order for context types
        context_priorities = {
            "api_context": 3,
            "config_context": 2,
            "framework_context": 2,
            "code_context": 1,
            "file_context": 1,
        }

        primary_context = "unknown"
        highest_priority = 0

        for context_type, priority in context_priorities.items():
            contexts = context_result[context_type].get("detected_contexts", [])
            if contexts and priority > highest_priority:
                primary_context = contexts[0]  # Take the first detected context
                highest_priority = priority

        return primary_context

    def enhance_finding(
        self, finding: Dict[str, Any], context_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enhance a finding with context-aware information."""
        enhanced_finding = finding.copy()

        # Apply confidence modifier
        original_confidence = finding.get("confidence", 0.7)
        context_modifier = context_analysis["confidence_modifier"]
        new_confidence = min(1.0, original_confidence * context_modifier)

        # Update finding with context information
        enhanced_finding.update(
            {
                "confidence": round(new_confidence, 2),
                "context_type": context_analysis["context_type"],
                "risk_level": context_analysis["risk_level"],
                "context_modifier": round(context_modifier, 2),
                "context_analysis": {
                    "primary_context": context_analysis["context_type"],
                    "detected_contexts": self._flatten_detected_contexts(
                        context_analysis
                    ),
                    "confidence_reasoning": self._generate_confidence_reasoning(
                        context_analysis
                    ),
                },
            }
        )

        # Adjust severity based on context
        enhanced_finding["severity"] = self._adjust_severity(
            finding.get("severity", "medium"),
            context_analysis["risk_level"],
            new_confidence,
        )

        return enhanced_finding

    def _flatten_detected_contexts(self, context_analysis: Dict[str, Any]) -> List[str]:
        """Flatten all detected contexts from different analysis types."""
        all_contexts = []

        for context_type in [
            "file_context",
            "code_context",
            "config_context",
            "api_context",
            "framework_context",
        ]:
            contexts = context_analysis[context_type].get("detected_contexts", [])
            all_contexts.extend(contexts)

        return list(set(all_contexts))  # Remove duplicates

    def _generate_confidence_reasoning(self, context_analysis: Dict[str, Any]) -> str:
        """Generate human-readable reasoning for confidence adjustment."""
        modifier = context_analysis["confidence_modifier"]
        context_type = context_analysis["context_type"]

        if modifier > 1.3:
            return f"High confidence due to {context_type} context in production-like environment"
        elif modifier > 1.0:
            return f"Increased confidence due to {context_type} context"
        elif modifier < 0.5:
            return f"Reduced confidence due to test/example context"
        else:
            return f"Standard confidence with {context_type} context"

    def _adjust_severity(
        self, original_severity: str, risk_level: str, confidence: float
    ) -> str:
        """Adjust severity based on context and confidence."""
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        risk_map = {"low": 1, "medium": 2, "high": 3}

        original_score = severity_map.get(original_severity, 2)
        risk_score = risk_map.get(risk_level, 2)

        # Adjust based on risk level and confidence
        if risk_level == "high" and confidence > 0.8:
            adjusted_score = min(4, original_score + 1)
        elif risk_level == "low" or confidence < 0.3:
            adjusted_score = max(1, original_score - 1)
        else:
            adjusted_score = original_score

        severity_reverse_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        return severity_reverse_map.get(adjusted_score, original_severity)
