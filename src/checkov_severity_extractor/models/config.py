"""
Configuration models for the Checkov severity extractor.
"""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .checkov import CheckovPattern


class ProcessingConfig(BaseModel):
    """Configuration for file processing."""

    max_concurrent_files: int = Field(
        default=10, ge=1, le=100, description="Maximum concurrent file processing"
    )
    chunk_size: int = Field(
        default=100, ge=1, description="Number of files to process in each batch"
    )
    skip_index_files: bool = Field(
        default=True, description="Skip index and summary files"
    )
    file_extensions: list[str] = Field(
        default=[".adoc"], description="File extensions to process"
    )
    excluded_patterns: list[str] = Field(
        default=["*index*", "*policies.adoc"], description="File patterns to exclude"
    )
    max_file_size_mb: float = Field(
        default=10.0, ge=0.1, description="Maximum file size to process (MB)"
    )
    min_content_length: int = Field(
        default=50, ge=1, description="Minimum content length to process"
    )
    encoding: str = Field(default="utf-8", description="File encoding")
    timeout_seconds: float = Field(
        default=30.0, ge=1.0, description="Timeout for processing single file"
    )
    enable_validation: bool = Field(
        default=True, description="Enable extraction result validation"
    )

    @field_validator("file_extensions")
    @classmethod
    def validate_extensions(cls, v):
        """Ensure extensions start with a dot."""
        return [ext if ext.startswith(".") else f".{ext}" for ext in v]


class OutputConfig(BaseModel):
    """Configuration for output generation."""

    output_file: Path = Field(
        default=Path("checkov-severity.json"), description="Output JSON file path"
    )
    pretty_print: bool = Field(default=False, description="Pretty print JSON output")
    include_metadata: bool = Field(
        default=True, description="Include metadata in output"
    )

    @field_validator("output_file", mode="before")
    @classmethod
    def convert_to_path(cls, v):
        """Convert string paths to Path objects."""
        if v is None:
            return v
        return Path(v) if not isinstance(v, Path) else v


class ExtractionConfig(BaseModel):
    """Main configuration for the extraction process."""

    docs_directory: Path = Field(
        default=Path("docs"), description="Documentation directory to scan"
    )
    processing: ProcessingConfig = Field(
        default_factory=ProcessingConfig, description="Processing configuration"
    )
    output: OutputConfig = Field(
        default_factory=OutputConfig, description="Output configuration"
    )
    patterns: list[CheckovPattern] = Field(
        default_factory=list, description="Custom extraction patterns"
    )
    quiet: bool = Field(default=False, description="Suppress output messages")

    @field_validator("docs_directory", mode="before")
    @classmethod
    def convert_docs_directory(cls, v):
        """Convert string path to Path object."""
        return Path(v) if not isinstance(v, Path) else v

    @classmethod
    def create_default_patterns(cls) -> list[CheckovPattern]:
        """Create default extraction patterns."""
        return [
            CheckovPattern(
                name="github_link_with_checkov_id",
                pattern=r"\|Checkov ID\s*\n\s*\|\s*https?://.*?\[([A-Z0-9_]+)\]",
                priority=7,
                description="GitHub link with Checkov ID in square brackets",
            ),
            CheckovPattern(
                name="checkov_multiline_table",
                pattern=r"\|Checkov ID\s*\n\s*\|\s*([A-Z0-9_]+)",
                priority=6,
                description="Multi-line table format (SAST policies)",
            ),
            CheckovPattern(
                name="standard_table_format",
                pattern=r"\|Checkov ID\s*\n\s*\|\s*.*?\[([A-Z0-9_]+)\]",
                priority=5,
                description="Standard AsciiDoc table format with link",
            ),
            CheckovPattern(
                name="simple_table_format",
                pattern=r"\|Checkov ID\s*\|\s*([A-Z0-9_]+)",
                priority=4,
                description="Simple table format without link",
            ),
            CheckovPattern(
                name="checkov_field_multiline",
                pattern=r"Checkov ID\s*:?\s*\n\s*([A-Z0-9_]+)",
                priority=3,
                description="Checkov ID field on separate line",
            ),
            CheckovPattern(
                name="checkov_field_inline",
                pattern=r"Checkov ID\s*:?\s*([A-Z0-9_]+)",
                priority=2,
                description="Inline Checkov ID field",
            ),
            CheckovPattern(
                name="bracketed_id",
                pattern=r"\[([A-Z0-9_]+)\]",
                priority=1,
                description="Any bracketed ID (lowest priority)",
            ),
            CheckovPattern(
                name="severity_pattern",
                pattern=r"\|Severity\s*\n\s*\|\s*([A-Z]+)",
                priority=3,
                description="Severity extraction from table",
            ),
            CheckovPattern(
                name="simple_severity_pattern",
                pattern=r"\|Severity\s*\|\s*([A-Z]+)",
                priority=2,
                description="Simple severity table format",
            ),
        ]

    def model_post_init(self, __context):
        """Post-initialization setup."""
        if not self.patterns:
            self.patterns = self.create_default_patterns()

    @classmethod
    def from_cli_args(cls, args: dict[str, Any]) -> "ExtractionConfig":
        """Create configuration from CLI arguments."""
        processing_config = ProcessingConfig()
        output_config = OutputConfig()

        # Update from args
        if args.get("docs_dir"):
            docs_directory = Path(args["docs_dir"])
        else:
            docs_directory = Path("docs")

        if args.get("output"):
            output_config.output_file = Path(args["output"])

        if args.get("max_workers"):
            processing_config.max_concurrent_files = args["max_workers"]

        return cls(
            docs_directory=docs_directory,
            processing=processing_config,
            output=output_config,
            quiet=args.get("quiet", False),
        )

    def validate_paths(self) -> list[str]:
        """Validate that required paths exist and are accessible."""
        errors = []

        # Check docs directory
        if not self.docs_directory.exists():
            errors.append(
                f"Documentation directory does not exist: {self.docs_directory}"
            )
        elif not self.docs_directory.is_dir():
            errors.append(
                f"Documentation path is not a directory: {self.docs_directory}"
            )

        # Check output directory is writable
        output_parent = self.output.output_file.parent
        if not output_parent.exists():
            try:
                output_parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                errors.append(f"Cannot create output directory: {output_parent}")

        return errors

    def get_file_patterns(self) -> list[str]:
        """Get file patterns for scanning."""
        patterns = []
        for ext in self.processing.file_extensions:
            patterns.append(f"**/*{ext}")
        return patterns
