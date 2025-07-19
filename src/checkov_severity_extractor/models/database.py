"""
Database schema models for the Checkov severity database.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, validator

from .severity import SeverityLevel, SeverityStats


class DatabaseMetadata(BaseModel):
    """Metadata for the severity database."""

    version: str = Field(default="1.0", description="Database schema version")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Generation timestamp"
    )
    total_mappings: int = Field(..., ge=0, description="Total number of mappings")
    extraction_stats: Optional[SeverityStats] = Field(
        None, description="Extraction statistics"
    )
    generator_version: str = Field(default="1.0.0", description="Extractor version")

    @property
    def severity_distribution(self) -> dict[str, int]:
        """Get severity distribution as a string-keyed dictionary."""
        if self.extraction_stats and self.extraction_stats.severity_counts:
            return {
                severity.value: count
                for severity, count in self.extraction_stats.severity_counts.items()
            }
        return {}

    @property
    def last_updated(self) -> Optional[datetime]:
        """Alias for timestamp for backward compatibility."""
        return self.timestamp

    @validator("timestamp", pre=True)
    def parse_timestamp(cls, v):
        """Parse timestamp from various formats."""
        if isinstance(v, str):
            # Try to parse ISO format
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                pass
        return v

    def to_compact_dict(self) -> dict[str, Any]:
        """Convert to compact dictionary format for JSON output."""
        return {
            "v": self.version,
            "t": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "c": self.total_mappings,
            "g": self.generator_version,
        }


class SeverityDatabase(BaseModel):
    """Complete severity database model."""

    metadata: DatabaseMetadata = Field(..., description="Database metadata")
    mappings: dict[str, SeverityLevel] = Field(
        default_factory=dict, description="Checkov ID to severity mappings"
    )

    @validator("mappings")
    def validate_mappings(cls, v, values):
        """Validate that mappings count matches metadata."""
        metadata = values.get("metadata")
        if metadata and len(v) != metadata.total_mappings:
            # Update metadata count to match actual mappings
            metadata.total_mappings = len(v)
        return v

    def add_mapping(self, checkov_id: str, severity: SeverityLevel) -> bool:
        """Add a new mapping to the database."""
        if checkov_id in self.mappings:
            return False  # Already exists

        self.mappings[checkov_id] = severity
        self.metadata.total_mappings = len(self.mappings)

        # Update stats if available
        if self.metadata.extraction_stats:
            self.metadata.extraction_stats.add_severity(severity)

        return True

    def get_severity(self, checkov_id: str) -> Optional[SeverityLevel]:
        """Get severity for a Checkov ID."""
        return self.mappings.get(checkov_id)

    def remove_mapping(self, checkov_id: str) -> bool:
        """Remove a mapping from the database."""
        if checkov_id not in self.mappings:
            return False

        del self.mappings[checkov_id]
        self.metadata.total_mappings = len(self.mappings)
        return True

    def merge_with(self, other: "SeverityDatabase") -> int:
        """Merge another database into this one. Returns number of new mappings added."""
        added_count = 0
        for checkov_id, severity in other.mappings.items():
            if self.add_mapping(checkov_id, severity):
                added_count += 1
        return added_count

    def filter_by_severity(self, severity: SeverityLevel) -> dict[str, SeverityLevel]:
        """Get all mappings with a specific severity."""
        return {
            checkov_id: sev
            for checkov_id, sev in self.mappings.items()
            if sev == severity
        }

    def filter_by_provider(self, provider: str) -> dict[str, SeverityLevel]:
        """Get all mappings for a specific provider."""
        provider_upper = provider.upper()
        return {
            checkov_id: severity
            for checkov_id, severity in self.mappings.items()
            if f"_{provider_upper}_" in checkov_id
        }

    def get_statistics(self) -> SeverityStats:
        """Calculate current statistics."""
        stats = SeverityStats(total_mappings=len(self.mappings))
        for severity in self.mappings.values():
            stats.add_severity(severity)
        return stats

    def to_dict(self) -> dict[str, Any]:
        """Convert to standard dictionary format for JSON output."""
        return {
            "metadata": {
                "version": self.metadata.version,
                "timestamp": self.metadata.timestamp.isoformat() + "Z"
                if self.metadata.timestamp
                else None,
                "total_mappings": self.metadata.total_mappings,
                "generator_version": self.metadata.generator_version,
                "extraction_stats": self.metadata.extraction_stats.model_dump()
                if self.metadata.extraction_stats
                else None,
            },
            "mappings": {k: v.value for k, v in self.mappings.items()},
        }

    def to_optimized_dict(self) -> dict[str, Any]:
        """Convert to optimized dictionary format for compact JSON output."""
        return {
            **self.metadata.to_compact_dict(),
            "s": {k: v.value for k, v in self.mappings.items()},
        }

    @classmethod
    def from_optimized_dict(cls, data: dict[str, Any]) -> "SeverityDatabase":
        """Create database from optimized dictionary format."""
        # Extract metadata
        metadata = DatabaseMetadata(
            version=data.get("v", "1.0"),
            timestamp=data.get("t", datetime.utcnow()),
            total_mappings=data.get("c", 0),
            generator_version=data.get("g", "1.0.0"),
        )

        # Extract mappings
        mappings = {}
        severity_mappings = data.get("s", {})
        for checkov_id, severity_str in severity_mappings.items():
            try:
                severity = SeverityLevel(severity_str)
                mappings[checkov_id] = severity
            except ValueError:
                # Skip invalid severity levels
                continue

        # Update metadata with actual count
        metadata.total_mappings = len(mappings)

        return cls(metadata=metadata, mappings=mappings)

    def validate_integrity(self) -> bool:
        """Validate database integrity."""
        # Check metadata consistency
        if len(self.mappings) != self.metadata.total_mappings:
            return False

        # Check all severity values are valid
        for severity in self.mappings.values():
            if not isinstance(severity, SeverityLevel):
                return False

        return True

    def compact_size_bytes(self) -> int:
        """Estimate the size of the compact JSON representation."""
        import json

        compact_dict = self.to_optimized_dict()
        return len(json.dumps(compact_dict, separators=(",", ":")).encode("utf-8"))
