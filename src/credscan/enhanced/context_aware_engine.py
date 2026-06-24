"""
Context-aware engine that enhances credential detection with intelligent context analysis.
"""

import os
from typing import Dict, List, Any, Optional
import logging

from .context_analyzer import ContextAnalyzer
from .confidence_scorer import PatternConfidenceScorer
from .result_deduplicator import ResultDeduplicator

logger = logging.getLogger(__name__)


class ContextAwareEngine:
    """Engine that integrates context analysis with credential scanning."""
    
    def __init__(self, base_engine, config: Dict[str, Any] = None):
        """Initialize with a base scanning engine and context analyzer."""
        self.base_engine = base_engine
        self.config = config or {}
        self.context_analyzer = ContextAnalyzer(config)
        
        # Context-aware settings
        self.enable_context_analysis = self.config.get('enable_context_analysis', True)
        self.context_confidence_threshold = self.config.get('context_confidence_threshold', 0.1)
        self.enable_context_filtering = self.config.get('enable_context_filtering', True)
        
        # Confidence scoring settings
        self.enable_confidence_scoring = self.config.get('enable_confidence_scoring', True)
        self.min_confidence_threshold = self.config.get('min_confidence_threshold', 0.3)
        self.show_confidence_details = self.config.get('show_confidence_details', False)
        
        # Result processing settings
        self.enable_deduplication = self.config.get('enable_deduplication', True)
        self.show_summary = self.config.get('show_summary', True)
        
        # Initialize confidence scorer if enabled
        if self.enable_confidence_scoring:
            confidence_config = self.config.copy()
            if 'confidence_factor_weights' in self.config:
                confidence_config['factor_weights'] = self.config['confidence_factor_weights']
            self.confidence_scorer = PatternConfidenceScorer(confidence_config)
        else:
            self.confidence_scorer = None
        
        # Initialize deduplicator
        if self.enable_deduplication:
            self.deduplicator = ResultDeduplicator(self.config)
        else:
            self.deduplicator = None
        
        logger.debug(f"ContextAwareEngine initialized with context analysis: {self.enable_context_analysis}, "
                    f"confidence scoring: {self.enable_confidence_scoring}")
    
    def scan(self) -> List[Dict[str, Any]]:
        """Perform context-aware credential scanning."""
        if not self.enable_context_analysis:
            return self.base_engine.scan()
        
        # Get base findings
        base_findings = self.base_engine.scan()
        logger.debug(f"Base engine found {len(base_findings)} findings")

        # Enhance findings with context analysis
        enhanced_findings = []

        # Only read files that actually have findings — avoids a second full traversal
        # and prevents loading the entire repo into memory at once.
        file_paths_with_findings = {f.get('path') for f in base_findings if f.get('path')}
        from credscan.file_cache import read_text
        file_contents = {}
        for file_path in file_paths_with_findings:
            content = read_text(file_path)
            if content is None:
                logger.debug(f"Could not read {file_path} for context analysis")
            file_contents[file_path] = content or ""
        
        # Analyze and enhance each finding
        for finding in base_findings:
            enhanced_finding = self._enhance_finding_with_context(finding, file_contents)
            
            # Apply confidence-based filtering
            should_include = True
            context_confidence = enhanced_finding.get('confidence', 1.0)  # Default to high if missing
            overall_confidence = enhanced_finding.get('overall_confidence', context_confidence)  # Fallback to context confidence
            
            # Only filter if we have valid confidence scores and they're genuinely low
            if self.enable_context_filtering and context_confidence < self.context_confidence_threshold:
                should_include = False
                logger.debug(f"Filtered out by context confidence: {enhanced_finding.get('value', '')[:30]}...")
            
            # For overall confidence, be less aggressive - if context analysis failed, don't over-filter
            if self.enable_confidence_scoring and overall_confidence > 0 and overall_confidence < self.min_confidence_threshold:
                should_include = False
                logger.debug(f"Filtered out by overall confidence: {enhanced_finding.get('value', '')[:30]}...")
            
            if should_include:
                enhanced_findings.append(enhanced_finding)
        
        logger.debug(f"Context analysis completed. {len(enhanced_findings)} findings after context filtering")
        
        # Apply deduplication if enabled
        if self.enable_deduplication and self.deduplicator and enhanced_findings:
            logger.debug(f"Deduplicating {len(enhanced_findings)} findings...")
            enhanced_findings = self.deduplicator.deduplicate_findings(enhanced_findings)
            logger.debug(f"After deduplication: {len(enhanced_findings)} unique findings")
        
        return enhanced_findings
    
    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Perform context-aware scanning of a single file."""
        if not self.enable_context_analysis:
            return self.base_engine.scan_file(filepath)
        
        # Get base findings
        base_findings = self.base_engine.scan_file(filepath)
        
        if not base_findings:
            return base_findings
        
        # Read file content for context analysis
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {filepath} for context analysis: {e}")
            return base_findings
        
        file_contents = {filepath: content}
        
        # Enhance findings with context analysis
        enhanced_findings = []
        for finding in base_findings:
            enhanced_finding = self._enhance_finding_with_context(finding, file_contents)
            
            # Apply confidence-based filtering
            should_include = True
            
            if self.enable_context_filtering and enhanced_finding.get('confidence', 0) < self.context_confidence_threshold:
                should_include = False
            
            if self.enable_confidence_scoring and enhanced_finding.get('overall_confidence', 0) < self.min_confidence_threshold:
                should_include = False
            
            if should_include:
                enhanced_findings.append(enhanced_finding)
        
        return enhanced_findings
    
    def _enhance_finding_with_context(self, finding: Dict[str, Any], file_contents: Dict[str, str]) -> Dict[str, Any]:
        """Enhance a single finding with context analysis."""
        file_path = finding.get('path', '')
        line_number = finding.get('line', 1)
        variable_name = finding.get('variable')
        value = finding.get('value', '')
        
        # Get file content
        content = file_contents.get(file_path, '')
        if not content:
            logger.debug(f"No content available for context analysis of {file_path}")
            return finding
        
        try:
            # Perform context analysis
            context_analysis = self.context_analyzer.analyze_context(
                file_path=file_path,
                content=content,
                finding_line=line_number,
                finding_key=variable_name,
                finding_value=value
            )
            
            # Enhance the finding with context information
            enhanced_finding = self.context_analyzer.enhance_finding(finding, context_analysis)
            
            # Add context-aware description
            enhanced_finding['description'] = self._generate_context_aware_description(
                enhanced_finding, context_analysis
            )
            
            # Add confidence scoring if enabled
            if self.enable_confidence_scoring and self.confidence_scorer:
                # Get entropy analysis if available
                entropy_analysis = enhanced_finding.get('entropy_analysis')
                
                # Get technology analysis if available
                technology_analysis = enhanced_finding.get('technology_analysis')
                
                # Calculate comprehensive confidence score
                confidence_result = self.confidence_scorer.calculate_confidence_score(
                    enhanced_finding, context_analysis, entropy_analysis, technology_analysis
                )
                
                # Add confidence information to the finding
                enhanced_finding['overall_confidence'] = confidence_result['confidence']
                enhanced_finding['confidence_factors'] = confidence_result['factors']
                enhanced_finding['confidence_explanation'] = confidence_result['explanation']
                
                if self.show_confidence_details:
                    enhanced_finding['confidence_breakdown'] = confidence_result['score_breakdown']
                
                logger.debug(f"Enhanced finding with confidence: {confidence_result['confidence']:.3f}")
            
            logger.debug(f"Enhanced finding with context: {context_analysis['context_type']} "
                        f"(modifier: {context_analysis['confidence_modifier']:.2f})")
            
            return enhanced_finding
            
        except Exception as e:
            logger.debug(f"Error in context analysis for {file_path}:{line_number}: {e}")
            # Return the original finding with minimal confidence scoring if enabled
            if self.enable_confidence_scoring and self.confidence_scorer:
                try:
                    # Calculate confidence without context analysis
                    confidence_result = self.confidence_scorer.calculate_confidence_score(
                        finding, None, None, None  # No context/entropy/tech analysis
                    )
                    
                    enhanced_finding = finding.copy()
                    enhanced_finding['overall_confidence'] = confidence_result['confidence']
                    enhanced_finding['confidence_factors'] = confidence_result['factors']
                    enhanced_finding['confidence_explanation'] = confidence_result['explanation']
                    
                    if self.show_confidence_details:
                        enhanced_finding['confidence_breakdown'] = confidence_result['score_breakdown']
                    
                    return enhanced_finding
                except Exception as conf_e:
                    logger.debug(f"Error in fallback confidence scoring: {conf_e}")
                    return finding
            else:
                return finding
    
    def _generate_context_aware_description(self, finding: Dict[str, Any], 
                                          context_analysis: Dict[str, Any]) -> str:
        """Generate a context-aware description for the finding."""
        base_description = finding.get('description', 'Potential credential detected')
        context_type = context_analysis.get('context_type', 'unknown')
        risk_level = context_analysis.get('risk_level', 'medium')
        
        # Context-specific descriptions
        context_descriptions = {
            # API contexts
            'express_auth': 'in Express.js authentication middleware',
            'django_auth': 'in Django REST framework authentication',
            'spring_auth': 'in Spring Boot security configuration',
            'webhook_signatures': 'in webhook signature validation',
            'oauth_flow': 'in OAuth authentication flow',
            'rest_api_endpoints': 'in REST API endpoint configuration',
            'graphql_endpoints': 'in GraphQL API configuration',
            'api_middleware': 'in API middleware configuration',
            'external_api_clients': 'in external API client configuration',
            
            # Configuration contexts
            'database_credentials': 'in database configuration',
            'api_configuration': 'in API service configuration',
            'security_config': 'in security configuration section',
            'cloud_config': 'in cloud provider configuration',
            'logging_config': 'in logging configuration',
            'messaging_config': 'in message queue configuration',
            'cache_config': 'in cache configuration',
            'environment_config': 'in environment configuration',
            
            # Environment contexts
            'production_indicators': 'in production environment',
            'staging_indicators': 'in staging environment',
            'development_indicators': 'in development environment',
            'test_indicators': 'in test/example code',
            
            # Framework contexts
            'docker': 'in Docker container configuration',
            'kubernetes': 'in Kubernetes deployment',
            'terraform': 'in Terraform infrastructure code',
            
            # Code contexts
            'documentation': 'in documentation/comments',
            'error_handling': 'in error handling code',
            'constants_global': 'in global constants',
            'function_parameters': 'in function parameters'
        }
        
        context_suffix = context_descriptions.get(context_type, f'in {context_type} context')
        
        # Risk level indicators
        risk_indicators = {
            'high': ' [HIGH RISK]',
            'medium': ' [MEDIUM RISK]',
            'low': ' [LOW RISK]'
        }
        
        risk_suffix = risk_indicators.get(risk_level, '')
        
        return f"{base_description} {context_suffix}{risk_suffix}"
    
    def __getattr__(self, name):
        """Delegate missing attributes to the base engine."""
        return getattr(self.base_engine, name)
    
    @property
    def parsers(self):
        """Delegate parsers property to base engine."""
        return self.base_engine.parsers
    
    def get_parser_for_file(self, filepath: str):
        """Delegate parser selection to base engine."""
        return self.base_engine.get_parser_for_file(filepath)
    
    def register_parser(self, parser):
        """Delegate parser registration to base engine."""
        return self.base_engine.register_parser(parser)
    
    def register_analyzer(self, analyzer):
        """Delegate analyzer registration to base engine."""
        return self.base_engine.register_analyzer(analyzer)
    
    def register_rules(self, rules):
        """Delegate rule registration to base engine."""
        return self.base_engine.register_rules(rules)
    
    def find_files(self):
        """Delegate file finding to base engine."""
        return self.base_engine.find_files()


class ContextAwareConfig:
    """Configuration helper for context-aware detection settings."""
    
    @staticmethod
    def get_default_config() -> Dict[str, Any]:
        """Get default configuration for context-aware detection."""
        return {
            'enable_context_analysis': True,
            'context_confidence_threshold': 0.1,
            'enable_context_filtering': True,
            'context_window_size': 5,
            'min_confidence_threshold': 0.1,
            'max_confidence_multiplier': 2.0
        }
    
    @staticmethod
    def get_strict_config() -> Dict[str, Any]:
        """Get strict configuration that filters aggressively."""
        return {
            'enable_context_analysis': True,
            'context_confidence_threshold': 0.3,
            'enable_context_filtering': True,
            'context_window_size': 8,
            'min_confidence_threshold': 0.2,
            'max_confidence_multiplier': 1.8
        }
    
    @staticmethod
    def get_permissive_config() -> Dict[str, Any]:
        """Get permissive configuration that keeps most findings."""
        return {
            'enable_context_analysis': True,
            'context_confidence_threshold': 0.05,
            'enable_context_filtering': False,
            'context_window_size': 3,
            'min_confidence_threshold': 0.05,
            'max_confidence_multiplier': 2.5
        }