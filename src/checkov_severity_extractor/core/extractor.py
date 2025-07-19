"""
Main extraction orchestrator for Checkov severity mappings.
"""

import time
from pathlib import Path
from typing import Any

from ..io.file_scanner import FileScanner
from ..io.json_writer import JsonWriter
from ..models.checkov import CheckovMapping, ExtractionResult
from ..models.config import ExtractionConfig, OutputConfig
from ..models.database import DatabaseMetadata, SeverityDatabase
from ..models.severity import SeverityStats
from ..utils.exceptions import CheckovExtractionError, ConfigurationError
from ..utils.logging import LoggerMixin
from .patterns import RegexPatternMatcher
from .processor import FileProcessor
from .validator import DataValidator


class CheckovSeverityExtractor(LoggerMixin):
    """
    Main orchestrator for Checkov severity extraction.

    This class coordinates the entire extraction process:
    1. Scanning directories for documentation files
    2. Extracting Checkov IDs and severities using pattern matching
    3. Validating extracted data
    4. Generating optimized JSON database
    """

    def __init__(self):
        """Initialise the extractor with default components."""
        self.pattern_matcher = RegexPatternMatcher()
        self.validator = DataValidator()
        self.file_processor = FileProcessor(
            pattern_matcher=self.pattern_matcher, validator=self.validator
        )
        self.file_scanner = None  # Will be configured per extraction
        self.json_writer = JsonWriter()

        # Extraction state
        self.extracted_mappings: dict[str, CheckovMapping] = {}
        self.processing_errors: list[str] = []
        self.duplicate_conflicts: list[dict[str, Any]] = []

    def _configure_file_scanner(self, config: ExtractionConfig) -> FileScanner:
        """Configure file scanner based on processing config."""
        return FileScanner(
            extensions=set(config.processing.file_extensions),
            ignore_patterns=set(config.processing.excluded_patterns),
            max_file_size_mb=config.processing.max_file_size_mb,
            follow_symlinks=False,  # Always false for security
        )

    async def extract(self, config: ExtractionConfig) -> SeverityDatabase:
        """
        Perform complete extraction process.

        Args:
            config: Extraction configuration

        Returns:
            Generated severity database

        Raises:
            CheckovExtractionError: If extraction fails
            ConfigurationError: If configuration is invalid
        """
        self.log_operation("Checkov severity extraction", config=config.dict())
        start_time = time.time()

        try:
            # Validate configuration
            validation_errors = config.validate_paths()
            if validation_errors:
                raise ConfigurationError(
                    "Configuration validation failed",
                    config_field="paths",
                    config_value=validation_errors,
                )

            # Initialise pattern matcher with config patterns
            if config.patterns:
                self.pattern_matcher.load_patterns(config.patterns)

            # Configure file scanner for this extraction
            self.file_scanner = self._configure_file_scanner(config)

            # Scan for files
            self.logger.info("Scanning for documentation files")
            scan_result = await self.file_scanner.scan_directory(
                config.docs_directory,
                recursive=True,  # Always scan recursively
                max_depth=None,  # No depth limit
            )
            if not scan_result.files:
                raise CheckovExtractionError(
                    f"No files found in directory: {config.docs_directory}",
                    details={"directory": str(config.docs_directory)},
                )

            self.logger.info(f"Found {len(scan_result.files)} files to process")

            # Process files
            self.logger.info("Processing files for extraction")
            results = await self.file_processor.process_files_batch(
                scan_result.files, config.processing.max_concurrent_files
            )

            # Aggregate results
            database = await self._aggregate_results(results, config)

            processing_time = time.time() - start_time
            self.log_success(
                "Checkov severity extraction",
                total_mappings=len(database.mappings),
                processing_time_seconds=processing_time,
            )

            return database

        except Exception as e:
            processing_time = time.time() - start_time
            self.log_error(
                "Checkov severity extraction",
                e,
                processing_time_seconds=processing_time,
            )

            if isinstance(e, (CheckovExtractionError, ConfigurationError)):
                raise
            else:
                raise CheckovExtractionError(
                    f"Extraction failed: {str(e)}",
                    details={"error_type": type(e).__name__},
                ) from e

    # Method removed - use basic extract() method instead

    async def _aggregate_results(
        self, results: list[ExtractionResult], config: ExtractionConfig
    ) -> SeverityDatabase:
        """
        Aggregate extraction results into a severity database.

        Args:
            results: List of extraction results
            config: Extraction configuration

        Returns:
            Aggregated severity database
        """
        self.logger.info("Aggregating extraction results")

        # Collect successful mappings
        mappings: dict[str, str] = {}
        severity_stats = SeverityStats(total_mappings=0)

        for result in results:
            if result.success and result.checkov_id and result.severity:
                checkov_id_str = result.checkov_id.full_id
                severity_str = result.severity.value

                # Check for duplicates/conflicts
                if checkov_id_str in mappings:
                    existing_severity = mappings[checkov_id_str]
                    if existing_severity != severity_str:
                        conflict = {
                            "checkov_id": checkov_id_str,
                            "existing_severity": existing_severity,
                            "new_severity": severity_str,
                            "file_path": result.file_path,
                        }
                        self.duplicate_conflicts.append(conflict)
                        self.log_warning(
                            "Severity conflict detected",
                            checkov_id=checkov_id_str,
                            existing=existing_severity,
                            new=severity_str,
                            file=result.file_path,
                        )
                        continue  # Skip conflicting entry

                # Add mapping
                mappings[checkov_id_str] = severity_str
                severity_stats.add_severity(result.severity)

        # Create database metadata
        metadata = DatabaseMetadata(
            version="1.0",
            total_mappings=len(mappings),
            extraction_stats=severity_stats,
            generator_version=config.__class__.__module__.split(".")[0],
        )

        # Create database
        database = SeverityDatabase(metadata=metadata, mappings=dict(mappings.items()))

        self.logger.info(
            "Aggregation completed",
            total_mappings=len(mappings),
            conflicts=len(self.duplicate_conflicts),
            errors=len(self.processing_errors),
        )

        return database

    async def write_database(
        self, database: SeverityDatabase, output_config: OutputConfig
    ) -> Path:
        """
        Write database to output file.

        Args:
            database: Database to write
            output_config: Output configuration

        Returns:
            Path to written file
        """
        await self.json_writer.write_database(
            database,
            output_config.output_file,
            backup_existing=False,
        )
        return output_config.output_file

    def get_extraction_summary(self) -> dict[str, Any]:
        """
        Get summary of extraction results.

        Returns:
            Summary dictionary with key metrics
        """
        return {
            "total_mappings": len(self.extracted_mappings),
            "processing_errors": len(self.processing_errors),
            "duplicate_conflicts": len(self.duplicate_conflicts),
            "errors": self.processing_errors[:10],  # First 10 errors
            "conflicts": self.duplicate_conflicts[:10],  # First 10 conflicts
        }

    def reset_state(self) -> None:
        """Reset extractor state for new extraction."""
        self.extracted_mappings.clear()
        self.processing_errors.clear()
        self.duplicate_conflicts.clear()
