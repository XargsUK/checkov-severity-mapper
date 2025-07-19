"""
Data models and validation schemas for Checkov severity extraction.
"""

from .checkov import CheckovId, CheckovMatch, CheckovPattern, ExtractionResult
from .config import ExtractionConfig, OutputConfig, ProcessingConfig
from .database import DatabaseMetadata, SeverityDatabase
from .severity import SeverityLevel, SeverityStats

__all__ = [
    "CheckovId",
    "CheckovMatch",
    "CheckovPattern",
    "ExtractionResult",
    "SeverityLevel",
    "SeverityStats",
    "SeverityDatabase",
    "DatabaseMetadata",
    "ExtractionConfig",
    "ProcessingConfig",
    "OutputConfig",
]
