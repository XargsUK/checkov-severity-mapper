"""
Checkov ID models and validation.
"""

import re
from enum import Enum
from typing import Any, ClassVar, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .severity import SeverityLevel


class CheckovIdType(str, Enum):
    """Types of Checkov IDs."""

    CKV = "CKV"
    CKV2 = "CKV2"
    CKV3 = "CKV3"
    BC = "BC"


class CheckovProvider(str, Enum):
    """Supported cloud providers and platforms."""

    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    ALIBABA = "ALI"
    IBM = "IBM"
    OCI = "OCI"
    OPENSTACK = "OPENSTACK"
    KUBERNETES = "K8S"
    DOCKER = "DOCKER"
    TERRAFORM = "TF"
    ANSIBLE = "ANSIBLE"
    OPENAPI = "OPENAPI"
    GITHUB = "GITHUB"
    GITLAB = "GITLAB"
    BITBUCKET = "BITBUCKET"
    CIRCLECI = "CIRCLECI"
    JENKINS = "JENKINS"
    LICENSE = "LIC"
    SECRETS = "SECRETS"
    SAST = "SAST"
    GENERAL = "GENERAL"


class CheckovId(BaseModel):
    """Represents a validated Checkov ID."""

    full_id: str = Field(..., description="Complete Checkov ID (e.g., CKV_AWS_123)")
    type: CheckovIdType = Field(..., description="Type of Checkov ID")
    provider: str = Field(..., description="Cloud provider or platform")
    number: str = Field(..., description="Policy number or identifier")

    # Validation patterns for different Checkov ID formats
    PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"^(CKV)_([A-Z0-9]+)_(\d+)$"),  # CKV_AWS_123, CKV_K8S_40
        re.compile(r"^(CKV2)_([A-Z0-9]+)_(\d+)$"),  # CKV2_GCP_45
        re.compile(r"^(CKV3)_([A-Z0-9]+)_(\d+)$"),  # CKV3_SAST_96
        re.compile(r"^(CKV)_([A-Z0-9]+)_([A-Z0-9_]+)$"),  # CKV_OPENAPI_20
        re.compile(r"^(BC)_([A-Z0-9]+)_(\d+)$"),  # BC_LIC_3
    ]

    @classmethod
    def from_string(cls, checkov_id: str) -> Optional["CheckovId"]:
        """Parse and validate a Checkov ID string."""
        for pattern in cls.PATTERNS:
            match = pattern.match(checkov_id.strip().upper())
            if match:
                id_type, provider, number = match.groups()
                return cls(
                    full_id=checkov_id.upper(),
                    type=CheckovIdType(id_type),
                    provider=provider,
                    number=number,
                )
        return None

    @field_validator("full_id")
    @classmethod
    def validate_full_id(cls, v):
        """Validate the full Checkov ID format."""
        if not any(pattern.match(v.upper()) for pattern in cls.PATTERNS):
            raise ValueError(f"Invalid Checkov ID format: {v}")
        return v.upper()

    @model_validator(mode="after")
    def validate_consistency(self):
        """Ensure all fields are consistent with the full_id."""
        full_id = self.full_id.upper()

        # Parse manually to avoid recursion
        parsed_data = None
        for pattern in self.PATTERNS:
            match = pattern.match(full_id)
            if match:
                id_type, provider, number = match.groups()
                parsed_data = {
                    "type": CheckovIdType(id_type),
                    "provider": provider,
                    "number": number,
                }
                break

        if parsed_data is None:
            raise ValueError(f"Cannot parse Checkov ID: {full_id}")

        # Update fields with parsed data
        self.type = parsed_data["type"]
        self.provider = parsed_data["provider"]
        self.number = parsed_data["number"]
        return self

    def __str__(self) -> str:
        return self.full_id

    def __hash__(self) -> int:
        return hash(self.full_id)


class CheckovPattern(BaseModel):
    """Represents a regex pattern for finding Checkov IDs."""

    name: str = Field(..., description="Pattern name for identification")
    pattern: str = Field(..., description="Regex pattern string")
    priority: int = Field(
        default=1, description="Pattern priority (higher = checked first)"
    )
    description: str = Field(default="", description="Pattern description")

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v):
        """Ensure the pattern is a valid regex."""
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e
        return v

    def compile(self) -> re.Pattern:
        """Compile the pattern into a regex object."""
        return re.compile(self.pattern, re.MULTILINE | re.DOTALL)


class CheckovMatch(BaseModel):
    """Represents a pattern match result."""

    checkov_id: str = Field(..., description="Matched Checkov ID string")
    severity: Optional[str] = Field(None, description="Matched severity level string")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Match confidence score")
    start_position: int = Field(..., ge=0, description="Start position in text")
    end_position: int = Field(..., ge=0, description="End position in text")
    context: str = Field(default="", description="Surrounding text context")
    pattern_name: str = Field(default="", description="Name of pattern that matched")

    @model_validator(mode="after")
    def validate_positions(self):
        """Ensure end position is after start position."""
        if self.end_position < self.start_position:
            raise ValueError("End position must be >= start position")
        return self

    @property
    def length(self) -> int:
        """Get the length of the matched text."""
        return self.end_position - self.start_position


class ExtractionResult(BaseModel):
    """Result of processing a single file."""

    file_path: str = Field(..., description="Path to the processed file")
    checkov_id: Optional[CheckovId] = Field(None, description="Extracted Checkov ID")
    severity: Optional[SeverityLevel] = Field(
        None, description="Extracted severity level"
    )
    raw_checkov_id: Optional[str] = Field(
        None, description="Raw Checkov ID string before validation"
    )
    raw_severity: Optional[str] = Field(
        None, description="Raw severity string before validation"
    )
    matches: list[CheckovMatch] = Field(
        default_factory=list, description="All pattern matches found"
    )
    errors: list[str] = Field(default_factory=list, description="Processing errors")
    warnings: list[str] = Field(default_factory=list, description="Processing warnings")
    processing_time_ms: Optional[float] = Field(
        None, description="Processing time in milliseconds"
    )
    confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Overall confidence score for extraction"
    )
    content_hash: Optional[str] = Field(
        None, description="Hash of the processed content for caching"
    )
    validation_issues: list[str] = Field(
        default_factory=list, description="Validation issues found during processing"
    )

    @property
    def success(self) -> bool:
        """Check if extraction was successful."""
        return self.checkov_id is not None and self.severity is not None

    @property
    def has_errors(self) -> bool:
        """Check if there were any errors."""
        return len(self.errors) > 0

    @property
    def has_warnings(self) -> bool:
        """Check if there were any warnings."""
        return len(self.warnings) > 0

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_path": self.file_path,
            "checkov_id": str(self.checkov_id) if self.checkov_id else None,
            "severity": self.severity.value if self.severity else None,
            "success": self.success,
            "errors": self.errors,
            "warnings": self.warnings,
            "processing_time_ms": self.processing_time_ms,
        }


class CheckovMapping(BaseModel):
    """Represents a validated Checkov ID to severity mapping."""

    checkov_id: CheckovId = Field(..., description="Validated Checkov ID")
    severity: SeverityLevel = Field(..., description="Severity level")
    source_file: Optional[str] = Field(None, description="Source file path")

    def __hash__(self) -> int:
        return hash((self.checkov_id.full_id, self.severity))

    def __eq__(self, other) -> bool:
        if not isinstance(other, CheckovMapping):
            return False
        return (
            self.checkov_id.full_id == other.checkov_id.full_id
            and self.severity == other.severity
        )
