"""
Core business logic modules for Checkov severity extraction.

This package contains the main extraction engine and supporting components.
"""

from .extractor import CheckovSeverityExtractor

# Alias for consistency
SeverityExtractor = CheckovSeverityExtractor
from .patterns import MatchResult, PatternMatcher, RegexPatternMatcher
from .processor import FileProcessor, ProcessingStats
from .validator import (
    DataValidator,
    ValidationIssue,
    ValidationReport,
    ValidationSeverity,
)

__all__ = [
    # Main extractor
    "SeverityExtractor",
    # Pattern matching
    "PatternMatcher",
    "RegexPatternMatcher",
    "MatchResult",
    # Validation
    "DataValidator",
    "ValidationReport",
    "ValidationIssue",
    "ValidationSeverity",
    # File processing
    "FileProcessor",
    "ProcessingStats",
]
