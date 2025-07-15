"""
Advanced confidence scoring system for pattern-based credential detection.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ConfidenceFactorType(Enum):
    """Types of factors that affect confidence scoring."""

    PATTERN_MATCH = "pattern_match"
    CONTEXT = "context"
    ENTROPY = "entropy"
    TECHNOLOGY = "technology"
    ENVIRONMENT = "environment"
    VALIDATION = "validation"


@dataclass
class ConfidenceFactor:
    """Individual factor contributing to confidence score."""

    factor_type: ConfidenceFactorType
    weight: float  # 0.0 to 1.0
    score: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def weighted_score(self) -> float:
        """Calculate weighted contribution to overall confidence."""
        return self.weight * self.score


class PatternConfidenceScorer:
    """Advanced confidence scoring system for credential detection patterns."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize confidence scorer with configuration."""
        self.config = config or {}

        # Weight configuration for different factors
        self.factor_weights = self.config.get(
            "factor_weights",
            {
                ConfidenceFactorType.PATTERN_MATCH: 0.3,
                ConfidenceFactorType.CONTEXT: 0.25,
                ConfidenceFactorType.ENTROPY: 0.2,
                ConfidenceFactorType.TECHNOLOGY: 0.15,
                ConfidenceFactorType.ENVIRONMENT: 0.05,
                ConfidenceFactorType.VALIDATION: 0.05,
            },
        )

        # Confidence thresholds
        self.min_confidence = self.config.get("min_confidence", 0.1)
        self.max_confidence = self.config.get("max_confidence", 1.0)

        # Pattern-specific scoring rules
        self._init_pattern_scoring_rules()

        logger.debug(
            "PatternConfidenceScorer initialized with weights: %s", self.factor_weights
        )

    def _init_pattern_scoring_rules(self):
        """Initialize pattern-specific scoring rules."""

        # High-confidence pattern indicators
        self.high_confidence_patterns = {
            "exact_match": [
                r"(?i)api[_-]?key",
                r"(?i)secret[_-]?key",
                r"(?i)private[_-]?key",
                r"(?i)access[_-]?token",
                r"(?i)auth[_-]?token",
                r"(?i)bearer[_-]?token",
            ],
            "service_specific": [
                r"(?i)aws[_-]?access[_-]?key",
                r"(?i)github[_-]?token",
                r"(?i)slack[_-]?token",
                r"(?i)stripe[_-]?key",
                r"(?i)twilio[_-]?auth",
            ],
            "format_specific": [
                r"^[A-Za-z0-9+/]{40,}={0,2}$",  # Base64
                r"^[0-9a-f]{32,}$",  # Hex
                r"^[A-Za-z0-9_-]{20,}$",  # URL-safe Base64
            ],
        }

        # Medium-confidence pattern indicators
        self.medium_confidence_patterns = {
            "generic_secret": [
                r"(?i)password",
                r"(?i)passwd",
                r"(?i)secret",
                r"(?i)token",
                r"(?i)key",
            ],
            "config_terms": [
                r"(?i)config",
                r"(?i)settings",
                r"(?i)env",
                r"(?i)credential",
            ],
        }

        # Low-confidence pattern indicators (likely false positives)
        self.low_confidence_patterns = {
            "test_indicators": [
                r"(?i)test",
                r"(?i)example",
                r"(?i)sample",
                r"(?i)demo",
                r"(?i)mock",
                r"(?i)fake",
                r"(?i)dummy",
            ],
            "common_words": [
                r"(?i)^(true|false|yes|no|null|undefined)$",
                r"(?i)^(localhost|127\.0\.0\.1)$",
                r"(?i)^(user|admin|root)$",
            ],
        }

    def calculate_confidence_score(
        self,
        finding: Dict[str, Any],
        context_analysis: Optional[Dict[str, Any]] = None,
        entropy_analysis: Optional[Dict[str, Any]] = None,
        technology_analysis: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive confidence score for a finding.

        Args:
            finding: The credential finding to score
            context_analysis: Optional context analysis results
            entropy_analysis: Optional entropy analysis results
            technology_analysis: Optional technology analysis results

        Returns:
            Dict containing confidence score and detailed breakdown
        """
        factors = []

        # 1. Pattern matching confidence
        pattern_factor = self._calculate_pattern_confidence(finding)
        factors.append(pattern_factor)

        # 2. Context confidence
        if context_analysis:
            context_factor = self._calculate_context_confidence(
                finding, context_analysis
            )
            factors.append(context_factor)

        # 3. Entropy confidence
        if entropy_analysis:
            entropy_factor = self._calculate_entropy_confidence(
                finding, entropy_analysis
            )
            factors.append(entropy_factor)

        # 4. Technology confidence
        if technology_analysis:
            tech_factor = self._calculate_technology_confidence(
                finding, technology_analysis
            )
            factors.append(tech_factor)

        # 5. Environment confidence
        env_factor = self._calculate_environment_confidence(finding)
        factors.append(env_factor)

        # 6. Validation confidence
        validation_factor = self._calculate_validation_confidence(finding)
        factors.append(validation_factor)

        # Calculate weighted overall confidence
        total_weighted_score = sum(factor.weighted_score for factor in factors)
        total_weight = sum(factor.weight for factor in factors)

        if total_weight > 0:
            overall_confidence = total_weighted_score / total_weight
        else:
            overall_confidence = 0.5  # Default neutral confidence

        # Apply bounds
        overall_confidence = max(
            self.min_confidence, min(self.max_confidence, overall_confidence)
        )

        # Generate confidence explanation
        explanation = self._generate_confidence_explanation(factors, overall_confidence)

        return {
            "confidence": round(overall_confidence, 3),
            "factors": [
                {
                    "type": factor.factor_type.value,
                    "weight": factor.weight,
                    "score": factor.score,
                    "weighted_score": factor.weighted_score,
                    "description": factor.description,
                    "evidence": factor.evidence,
                }
                for factor in factors
            ],
            "explanation": explanation,
            "score_breakdown": {
                "total_weighted_score": round(total_weighted_score, 3),
                "total_weight": round(total_weight, 3),
                "factor_count": len(factors),
            },
        }

    def _calculate_pattern_confidence(
        self, finding: Dict[str, Any]
    ) -> ConfidenceFactor:
        """Calculate confidence based on pattern matching quality."""
        variable_name = finding.get("variable", "").lower()
        value = finding.get("value", "")
        pattern_name = finding.get("pattern_name", "")

        score = 0.5  # Base score
        evidence = {}

        # Check for high-confidence patterns
        for category, patterns in self.high_confidence_patterns.items():
            for pattern in patterns:
                if re.search(pattern, variable_name) or re.search(pattern, value):
                    score = max(score, 0.9)
                    evidence[f"high_confidence_{category}"] = pattern
                    break

        # Check for medium-confidence patterns
        for category, patterns in self.medium_confidence_patterns.items():
            for pattern in patterns:
                if re.search(pattern, variable_name):
                    score = max(score, 0.7)
                    evidence[f"medium_confidence_{category}"] = pattern
                    break

        # Check for low-confidence patterns (reduce score)
        for category, patterns in self.low_confidence_patterns.items():
            for pattern in patterns:
                if re.search(pattern, variable_name) or re.search(pattern, value):
                    score = min(score, 0.3)
                    evidence[f"low_confidence_{category}"] = pattern
                    break

        # Adjust based on pattern specificity
        if pattern_name and "generic" not in pattern_name.lower():
            score += 0.1
            evidence["specific_pattern"] = pattern_name

        description = (
            f"Pattern matching confidence based on variable name and value patterns"
        )

        return ConfidenceFactor(
            factor_type=ConfidenceFactorType.PATTERN_MATCH,
            weight=self.factor_weights[ConfidenceFactorType.PATTERN_MATCH],
            score=min(1.0, score),
            description=description,
            evidence=evidence,
        )

    def _calculate_context_confidence(
        self, finding: Dict[str, Any], context_analysis: Dict[str, Any]
    ) -> ConfidenceFactor:
        """Calculate confidence based on context analysis."""
        context_modifier = context_analysis.get("confidence_modifier", 1.0)
        context_type = context_analysis.get("context_type", "unknown")
        risk_level = context_analysis.get("risk_level", "medium")

        # Convert context modifier to confidence score
        if context_modifier >= 1.5:
            score = 0.9
        elif context_modifier >= 1.2:
            score = 0.8
        elif context_modifier >= 1.0:
            score = 0.7
        elif context_modifier >= 0.8:
            score = 0.5
        else:
            score = 0.3

        # Adjust based on risk level
        risk_adjustments = {"high": 0.1, "medium": 0.0, "low": -0.1}
        score += risk_adjustments.get(risk_level, 0.0)

        description = f"Context analysis confidence ({context_type}, {risk_level} risk)"
        evidence = {
            "context_type": context_type,
            "risk_level": risk_level,
            "confidence_modifier": context_modifier,
        }

        return ConfidenceFactor(
            factor_type=ConfidenceFactorType.CONTEXT,
            weight=self.factor_weights[ConfidenceFactorType.CONTEXT],
            score=max(0.0, min(1.0, score)),
            description=description,
            evidence=evidence,
        )

    def _calculate_entropy_confidence(
        self, finding: Dict[str, Any], entropy_analysis: Dict[str, Any]
    ) -> ConfidenceFactor:
        """Calculate confidence based on entropy analysis."""
        entropy = entropy_analysis.get("entropy", 0.0)
        encoding_type = entropy_analysis.get("encoding_type", "unknown")
        diversity = entropy_analysis.get("character_diversity", 0.0)

        # Base score from entropy
        if entropy >= 5.0:
            score = 0.9
        elif entropy >= 4.0:
            score = 0.8
        elif entropy >= 3.5:
            score = 0.7
        elif entropy >= 3.0:
            score = 0.6
        else:
            score = 0.4

        # Adjust based on encoding type
        encoding_bonuses = {"base64": 0.1, "hex": 0.05, "jwt": 0.15, "uuid": 0.1}
        score += encoding_bonuses.get(encoding_type, 0.0)

        # Adjust based on character diversity
        if diversity >= 0.8:
            score += 0.1
        elif diversity <= 0.3:
            score -= 0.1

        description = f"Entropy analysis confidence (entropy: {entropy:.2f}, type: {encoding_type})"
        evidence = {
            "entropy": entropy,
            "encoding_type": encoding_type,
            "character_diversity": diversity,
        }

        return ConfidenceFactor(
            factor_type=ConfidenceFactorType.ENTROPY,
            weight=self.factor_weights[ConfidenceFactorType.ENTROPY],
            score=max(0.0, min(1.0, score)),
            description=description,
            evidence=evidence,
        )

    def _calculate_technology_confidence(
        self, finding: Dict[str, Any], technology_analysis: Dict[str, Any]
    ) -> ConfidenceFactor:
        """Calculate confidence based on technology-specific patterns."""
        tech_category = technology_analysis.get("technology_category", "unknown")
        tech_confidence = technology_analysis.get("confidence", 0.7)

        # Technology-specific confidence adjustments
        tech_confidence_map = {
            "aws": 0.9,
            "gcp": 0.9,
            "azure": 0.9,
            "github": 0.85,
            "stripe": 0.85,
            "slack": 0.8,
            "generic": 0.6,
        }

        score = tech_confidence_map.get(tech_category, tech_confidence)

        description = f"Technology-specific confidence ({tech_category})"
        evidence = {
            "technology_category": tech_category,
            "original_confidence": tech_confidence,
        }

        return ConfidenceFactor(
            factor_type=ConfidenceFactorType.TECHNOLOGY,
            weight=self.factor_weights[ConfidenceFactorType.TECHNOLOGY],
            score=score,
            description=description,
            evidence=evidence,
        )

    def _calculate_environment_confidence(
        self, finding: Dict[str, Any]
    ) -> ConfidenceFactor:
        """Calculate confidence based on environment indicators."""
        file_path = finding.get("path", "").lower()
        variable_name = finding.get("variable", "").lower()

        score = 0.5  # Neutral base score
        evidence = {}

        # Production indicators (increase confidence)
        prod_indicators = ["prod", "production", "live", "release"]
        if any(
            indicator in file_path or indicator in variable_name
            for indicator in prod_indicators
        ):
            score = 0.8
            evidence["environment"] = "production"
        else:
            # Test/development indicators (slightly decrease confidence, but not too much)
            test_indicators = [
                "test",
                "dev",
                "development",
                "staging",
                "demo",
                "example",
            ]
            if any(
                indicator in file_path or indicator in variable_name
                for indicator in test_indicators
            ):
                # Don't be too aggressive - test files can still contain real credential patterns
                score = 0.6  # Changed from 0.3 to 0.6
                evidence["environment"] = "test/development"

        # Configuration file indicators
        config_indicators = [".env", "config", "settings", ".yaml", ".json"]
        if any(indicator in file_path for indicator in config_indicators):
            score += 0.1
            evidence["file_type"] = "configuration"

        description = f"Environment-based confidence assessment"

        return ConfidenceFactor(
            factor_type=ConfidenceFactorType.ENVIRONMENT,
            weight=self.factor_weights[ConfidenceFactorType.ENVIRONMENT],
            score=max(0.0, min(1.0, score)),
            description=description,
            evidence=evidence,
        )

    def _calculate_validation_confidence(
        self, finding: Dict[str, Any]
    ) -> ConfidenceFactor:
        """Calculate confidence based on value validation."""
        value = finding.get("value", "")
        variable_name = finding.get("variable", "").lower()

        score = 0.5  # Base score
        evidence = {}

        # Length-based validation
        if len(value) < 8:
            score = 0.2
            evidence["length_check"] = "too_short"
        elif len(value) > 256:
            score = 0.3
            evidence["length_check"] = "too_long"
        elif 16 <= len(value) <= 128:
            score = 0.8
            evidence["length_check"] = "appropriate"

        # Common false positive patterns
        false_positive_patterns = [
            r"^(true|false|yes|no|null|undefined|none)$",
            r"^\d{1,4}$",  # Simple numbers
            r"^[a-zA-Z]\w*$",  # Simple variable names
            r"^https?://",  # URLs (usually not secrets themselves)
        ]

        for pattern in false_positive_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                score = min(score, 0.2)
                evidence["false_positive_pattern"] = pattern
                break

        # Credential-like format validation
        if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", value):  # Base64-like
            score = max(score, 0.7)
            evidence["format"] = "base64_like"
        elif re.match(r"^[0-9a-f]{32,}$", value):  # Hex-like
            score = max(score, 0.7)
            evidence["format"] = "hex_like"
        elif re.match(r"^[A-Za-z0-9_-]{20,}$", value):  # Token-like
            score = max(score, 0.6)
            evidence["format"] = "token_like"

        description = "Value validation confidence assessment"

        return ConfidenceFactor(
            factor_type=ConfidenceFactorType.VALIDATION,
            weight=self.factor_weights[ConfidenceFactorType.VALIDATION],
            score=max(0.0, min(1.0, score)),
            description=description,
            evidence=evidence,
        )

    def _generate_confidence_explanation(
        self, factors: List[ConfidenceFactor], overall_confidence: float
    ) -> str:
        """Generate human-readable explanation of confidence score."""

        # Sort factors by weighted contribution
        sorted_factors = sorted(factors, key=lambda f: f.weighted_score, reverse=True)

        # Overall confidence level
        if overall_confidence >= 0.8:
            confidence_level = "HIGH"
        elif overall_confidence >= 0.6:
            confidence_level = "MEDIUM-HIGH"
        elif overall_confidence >= 0.4:
            confidence_level = "MEDIUM"
        else:
            confidence_level = "LOW"

        explanation_parts = [
            f"Overall confidence: {confidence_level} ({overall_confidence:.3f})"
        ]

        # Top contributing factors
        top_factors = sorted_factors[:3]  # Show top 3 factors
        for factor in top_factors:
            contribution = factor.weighted_score
            explanation_parts.append(
                f"• {factor.description}: {factor.score:.2f} "
                f"(weight: {factor.weight:.2f}, contribution: {contribution:.3f})"
            )

        return "\n".join(explanation_parts)

    def batch_score_findings(
        self, findings: List[Dict[str, Any]], analyses: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Score confidence for multiple findings efficiently.

        Args:
            findings: List of findings to score
            analyses: Optional dict containing pre-computed analyses keyed by finding ID

        Returns:
            List of findings with confidence scores added
        """
        scored_findings = []

        for i, finding in enumerate(findings):
            finding_id = finding.get("id", str(i))

            # Extract relevant analyses for this finding
            context_analysis = None
            entropy_analysis = None
            technology_analysis = None

            if analyses:
                finding_analyses = analyses.get(finding_id, {})
                context_analysis = finding_analyses.get("context")
                entropy_analysis = finding_analyses.get("entropy")
                technology_analysis = finding_analyses.get("technology")

            # Calculate confidence score
            confidence_result = self.calculate_confidence_score(
                finding, context_analysis, entropy_analysis, technology_analysis
            )

            # Add confidence information to finding
            enhanced_finding = finding.copy()
            enhanced_finding.update(
                {
                    "confidence": confidence_result["confidence"],
                    "confidence_factors": confidence_result["factors"],
                    "confidence_explanation": confidence_result["explanation"],
                    "confidence_breakdown": confidence_result["score_breakdown"],
                }
            )

            scored_findings.append(enhanced_finding)

        return scored_findings
