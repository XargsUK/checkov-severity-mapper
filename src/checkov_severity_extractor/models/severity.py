"""
Severity level models and validation.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """Enumeration of valid Checkov severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, value: str) -> Optional["SeverityLevel"]:
        """Convert string to SeverityLevel, case-insensitive."""
        try:
            return cls(value.upper())
        except ValueError:
            return None

    @property
    def numeric_value(self) -> int:
        """Get numeric value for severity sorting (higher = more severe)."""
        return {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0,
        }[self]

    def __lt__(self, other: "SeverityLevel") -> bool:
        """Enable sorting by severity level."""
        return self.numeric_value < other.numeric_value


class SeverityStats(BaseModel):
    """Statistics about severity distribution."""

    total_mappings: int = Field(..., ge=0, description="Total number of mappings")
    severity_counts: dict[SeverityLevel, int] = Field(
        default_factory=dict, description="Count of mappings per severity level"
    )

    @field_validator("severity_counts")
    @classmethod
    def validate_counts(cls, v):
        """Ensure all counts are non-negative."""
        for severity, count in v.items():
            if count < 0:
                raise ValueError(f"Count for {severity} cannot be negative")
        return v

    @property
    def severity_percentages(self) -> dict[SeverityLevel, float]:
        """Calculate percentage distribution of severities."""
        if self.total_mappings == 0:
            return {}

        return {
            severity: (count / self.total_mappings) * 100
            for severity, count in self.severity_counts.items()
        }

    def add_severity(self, severity: SeverityLevel) -> None:
        """Add a severity to the statistics."""
        self.severity_counts[severity] = self.severity_counts.get(severity, 0) + 1
        self.total_mappings += 1

    def get_most_common_severity(self) -> Optional[SeverityLevel]:
        """Get the most common severity level."""
        if not self.severity_counts:
            return None
        return max(self.severity_counts, key=self.severity_counts.get)
