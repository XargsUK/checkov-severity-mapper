"""
Statistics calculation and reporting utilities.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from ..models.checkov import ExtractionResult
from ..models.severity import SeverityStats


@dataclass
class ExtractionStatistics:
    """Comprehensive extraction statistics."""

    # Basic counts
    total_files_found: int = 0
    total_files_processed: int = 0
    successful_extractions: int = 0
    failed_extractions: int = 0
    files_with_errors: int = 0
    files_with_warnings: int = 0

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_processing_time_ms: float = 0.0
    average_file_processing_time_ms: float = 0.0

    # Severity distribution
    severity_stats: Optional[SeverityStats] = None

    # Pattern statistics
    pattern_match_counts: dict[str, int] = None

    # Provider statistics
    provider_counts: dict[str, int] = None

    # Error categories
    error_categories: dict[str, int] = None

    # File size statistics
    total_bytes_processed: int = 0
    average_file_size_bytes: float = 0.0
    largest_file_bytes: int = 0
    smallest_file_bytes: int = 0

    def __post_init__(self):
        if self.pattern_match_counts is None:
            self.pattern_match_counts = defaultdict(int)
        if self.provider_counts is None:
            self.provider_counts = defaultdict(int)
        if self.error_categories is None:
            self.error_categories = defaultdict(int)
        if self.severity_stats is None:
            self.severity_stats = SeverityStats(total_mappings=0)

    @property
    def duration(self) -> Optional[timedelta]:
        """Get total processing duration."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_files_processed == 0:
            return 0.0
        return (self.successful_extractions / self.total_files_processed) * 100

    @property
    def error_rate(self) -> float:
        """Calculate error rate percentage."""
        if self.total_files_processed == 0:
            return 0.0
        return (self.failed_extractions / self.total_files_processed) * 100

    @property
    def processing_rate_files_per_second(self) -> float:
        """Calculate processing rate in files per second."""
        duration = self.duration
        if duration and duration.total_seconds() > 0:
            return self.total_files_processed / duration.total_seconds()
        return 0.0

    @property
    def throughput_mb_per_second(self) -> float:
        """Calculate throughput in MB per second."""
        duration = self.duration
        if duration and duration.total_seconds() > 0:
            return (
                self.total_bytes_processed / (1024 * 1024)
            ) / duration.total_seconds()
        return 0.0


class StatisticsCalculator:
    """Calculate and aggregate extraction statistics."""

    def __init__(self):
        self.stats = ExtractionStatistics()
        self._file_sizes: list[int] = []
        self._processing_times: list[float] = []

    def start_extraction(self) -> None:
        """Mark the start of extraction."""
        self.stats.start_time = datetime.utcnow()

    def end_extraction(self) -> None:
        """Mark the end of extraction and finalize statistics."""
        self.stats.end_time = datetime.utcnow()
        self._finalize_statistics()

    def add_file_found(self) -> None:
        """Increment files found counter."""
        self.stats.total_files_found += 1

    def add_file_processed(
        self, result: ExtractionResult, file_size_bytes: int = 0
    ) -> None:
        """Add a processed file result to statistics."""
        self.stats.total_files_processed += 1

        # Track file size
        if file_size_bytes > 0:
            self.stats.total_bytes_processed += file_size_bytes
            self._file_sizes.append(file_size_bytes)

        # Track processing time
        if result.processing_time_ms:
            self._processing_times.append(result.processing_time_ms)
            self.stats.total_processing_time_ms += result.processing_time_ms

        # Success/failure tracking
        if result.success:
            self.stats.successful_extractions += 1

            # Add to severity stats
            if result.severity:
                self.stats.severity_stats.add_severity(result.severity)

            # Track provider
            if result.checkov_id:
                self.stats.provider_counts[result.checkov_id.provider] += 1
        else:
            self.stats.failed_extractions += 1

        # Error and warning tracking
        if result.has_errors:
            self.stats.files_with_errors += 1
            for error in result.errors:
                category = self._categorize_error(error)
                self.stats.error_categories[category] += 1

        if result.has_warnings:
            self.stats.files_with_warnings += 1

        # Pattern match tracking
        for match in result.matches:
            if match.pattern_name:
                self.stats.pattern_match_counts[match.pattern_name] += 1

    def _categorize_error(self, error_message: str) -> str:
        """Categorize error messages for statistics."""
        error_lower = error_message.lower()

        if "checkov id" in error_lower and (
            "not found" in error_lower or "missing" in error_lower
        ):
            return "missing_checkov_id"
        elif "severity" in error_lower and (
            "not found" in error_lower or "missing" in error_lower
        ):
            return "missing_severity"
        elif "invalid" in error_lower and "checkov" in error_lower:
            return "invalid_checkov_id"
        elif "invalid" in error_lower and "severity" in error_lower:
            return "invalid_severity"
        elif "permission" in error_lower or "access" in error_lower:
            return "permission_error"
        elif "encoding" in error_lower or "unicode" in error_lower:
            return "encoding_error"
        elif "timeout" in error_lower:
            return "timeout_error"
        else:
            return "other_error"

    def _finalize_statistics(self) -> None:
        """Finalize calculated statistics."""
        # Average processing time
        if self._processing_times:
            self.stats.average_file_processing_time_ms = sum(
                self._processing_times
            ) / len(self._processing_times)

        # File size statistics
        if self._file_sizes:
            self.stats.average_file_size_bytes = sum(self._file_sizes) / len(
                self._file_sizes
            )
            self.stats.largest_file_bytes = max(self._file_sizes)
            self.stats.smallest_file_bytes = min(self._file_sizes)

    def get_summary_report(self) -> dict[str, Any]:
        """Generate a comprehensive summary report."""
        duration = self.stats.duration
        duration_str = str(duration).split(".")[0] if duration else "Unknown"

        return {
            "extraction_summary": {
                "total_files_found": self.stats.total_files_found,
                "total_files_processed": self.stats.total_files_processed,
                "successful_extractions": self.stats.successful_extractions,
                "failed_extractions": self.stats.failed_extractions,
                "success_rate_percent": round(self.stats.success_rate, 2),
                "error_rate_percent": round(self.stats.error_rate, 2),
            },
            "timing": {
                "duration": duration_str,
                "total_processing_time_ms": round(
                    self.stats.total_processing_time_ms, 2
                ),
                "average_file_processing_time_ms": round(
                    self.stats.average_file_processing_time_ms, 2
                ),
                "processing_rate_files_per_second": round(
                    self.stats.processing_rate_files_per_second, 2
                ),
                "throughput_mb_per_second": round(
                    self.stats.throughput_mb_per_second, 2
                ),
            },
            "data_summary": {
                "total_mappings_extracted": self.stats.severity_stats.total_mappings,
                "severity_distribution": dict(
                    self.stats.severity_stats.severity_counts
                ),
                "provider_distribution": dict(self.stats.provider_counts),
                "total_bytes_processed": self.stats.total_bytes_processed,
                "average_file_size_bytes": round(self.stats.average_file_size_bytes, 2),
            },
            "quality_metrics": {
                "files_with_errors": self.stats.files_with_errors,
                "files_with_warnings": self.stats.files_with_warnings,
                "error_categories": dict(self.stats.error_categories),
                "pattern_match_counts": dict(self.stats.pattern_match_counts),
            },
        }

    def print_summary(self, console_width: int = 80) -> None:
        """Print a formatted summary to console."""
        report = self.get_summary_report()

        print("=" * console_width)
        print("CHECKOV SEVERITY EXTRACTION STATISTICS".center(console_width))
        print("=" * console_width)

        # Extraction Summary
        summary = report["extraction_summary"]
        print(f"Files found: {summary['total_files_found']:,}")
        print(f"Files processed: {summary['total_files_processed']:,}")
        print(f"Successful extractions: {summary['successful_extractions']:,}")
        print(f"Failed extractions: {summary['failed_extractions']:,}")
        print(f"Success rate: {summary['success_rate_percent']:.1f}%")

        # Timing
        timing = report["timing"]
        print(f"\nProcessing time: {timing['duration']}")
        print(f"Average per file: {timing['average_file_processing_time_ms']:.1f}ms")
        print(
            f"Processing rate: {timing['processing_rate_files_per_second']:.1f} files/sec"
        )

        # Data Summary
        data = report["data_summary"]
        print(f"\nMappings extracted: {data['total_mappings_extracted']:,}")

        if data["severity_distribution"]:
            print("\nSeverity Distribution:")
            total_mappings = data["total_mappings_extracted"]
            for severity, count in sorted(data["severity_distribution"].items()):
                percentage = (count / total_mappings) * 100 if total_mappings > 0 else 0
                print(f"  {severity}: {count:,} ({percentage:.1f}%)")

        if data["provider_distribution"]:
            print("\nTop Providers:")
            provider_items = sorted(
                data["provider_distribution"].items(), key=lambda x: x[1], reverse=True
            )
            for provider, count in provider_items[:10]:  # Top 10
                total_mappings = data["total_mappings_extracted"]
                percentage = (count / total_mappings) * 100 if total_mappings > 0 else 0
                print(f"  {provider}: {count:,} ({percentage:.1f}%)")

        # Quality Metrics
        quality = report["quality_metrics"]
        if quality["files_with_errors"] > 0 or quality["files_with_warnings"] > 0:
            print("\nQuality Metrics:")
            print(f"Files with errors: {quality['files_with_errors']:,}")
            print(f"Files with warnings: {quality['files_with_warnings']:,}")

            if quality["error_categories"]:
                print("\nError Categories:")
                for category, count in sorted(
                    quality["error_categories"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                ):
                    print(f"  {category.replace('_', ' ').title()}: {count:,}")

        print("=" * console_width)
