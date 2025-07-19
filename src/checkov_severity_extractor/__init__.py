"""
Checkov Severity Extractor

A modern, modular Python package for extracting Checkov ID to severity mappings
from Prisma Cloud documentation and generating optimised JSON databases.
"""

__version__ = "1.0.0"
__author__ = "XargsUK"
__email__ = "51077147+XargsUK@users.noreply.github.com"

from .core.extractor import CheckovSeverityExtractor
from .models.checkov import CheckovId, CheckovMatch
from .models.database import SeverityDatabase
from .models.severity import SeverityLevel

__all__ = [
    "CheckovSeverityExtractor",
    "SeverityExtractor",
    "SeverityDatabase",
    "CheckovId",
    "CheckovMatch",
    "SeverityLevel",
]

# Alias for backward compatibility
SeverityExtractor = CheckovSeverityExtractor
