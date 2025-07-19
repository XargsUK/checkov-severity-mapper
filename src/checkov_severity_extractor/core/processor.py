"""
File processing engine for handling individual AsciiDoc files.
"""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..models.checkov import CheckovMatch, ExtractionResult
from ..models.config import ProcessingConfig
from ..utils.exceptions import FileReadError, ProcessingError
from ..utils.logging import LoggerMixin
from .patterns import PatternMatcher, RegexPatternMatcher
from .validator import DataValidator


@dataclass
class ProcessingStats:
    """Statistics for file processing."""

    files_processed: int = 0
    successful_extractions: int = 0
    failed_extractions: int = 0
    total_matches: int = 0
    average_confidence: float = 0.0
    processing_time_ms: float = 0.0


class FileProcessor(LoggerMixin):
    """Processes individual files for Checkov ID and severity extraction."""

    def __init__(
        self,
        pattern_matcher: Optional[PatternMatcher] = None,
        validator: Optional[DataValidator] = None,
        config: Optional[ProcessingConfig] = None,
        log_successes: bool = True,
    ):
        """Initialise processor with dependencies."""
        self.pattern_matcher = pattern_matcher or RegexPatternMatcher()
        self.validator = validator or DataValidator()
        self.config = config or ProcessingConfig()
        self.stats = ProcessingStats()
        self.log_successes = log_successes

    async def process_file(self, file_path: Path) -> ExtractionResult:
        """Process a single file and extract Checkov mappings."""
        import time

        start_time = time.perf_counter()

        try:
            # Validate file exists and is readable
            if not file_path.exists():
                raise FileReadError(f"File not found: {file_path}")

            if not file_path.is_file():
                raise FileReadError(f"Not a regular file: {file_path}")

            # Read file content
            content = await self._read_file_content(file_path)

            # Skip empty files
            if not content.strip():
                self.log_warning("Empty file skipped", file_path=str(file_path))
                processing_time = (time.perf_counter() - start_time) * 1000
                return self._create_empty_result(str(file_path), processing_time)

            # Apply content filters
            if not self._should_process_content(content):
                self.log_info("File filtered out", file_path=str(file_path))
                processing_time = (time.perf_counter() - start_time) * 1000
                return self._create_empty_result(str(file_path), processing_time)

            # Extract patterns
            match_result = await self.pattern_matcher.extract_mappings(
                content, str(file_path)
            )

            # Convert to Checkov matches with severity mapping
            matches = await self._create_checkov_matches(
                match_result.checkov_matches, match_result.severity_matches, content
            )

            # Create extraction result
            processing_time = (time.perf_counter() - start_time) * 1000

            # Extract primary Checkov ID and severity from best match
            primary_checkov_id = None
            primary_severity = None
            raw_checkov_id = None
            raw_severity = None

            if matches:
                # Get the best match (highest confidence)
                best_match = max(matches, key=lambda m: m.confidence)
                raw_checkov_id = best_match.checkov_id
                raw_severity = best_match.severity

                # Parse CheckovId
                if raw_checkov_id:
                    from ..models.checkov import CheckovId

                    primary_checkov_id = CheckovId.from_string(raw_checkov_id)

                # Parse severity
                if raw_severity:
                    from ..models.severity import SeverityLevel

                    primary_severity = SeverityLevel.from_string(raw_severity)

            result = ExtractionResult(
                file_path=str(file_path),
                checkov_id=primary_checkov_id,
                severity=primary_severity,
                raw_checkov_id=raw_checkov_id,
                raw_severity=raw_severity,
                matches=matches,
                processing_time_ms=processing_time,
                confidence=match_result.confidence_score,
                content_hash=self._calculate_content_hash(content),
            )

            # Validate if enabled
            if self.config.enable_validation:
                validation_report = await self.validator.validate_extraction_result(
                    result
                )
                result.validation_issues = validation_report.issues

            # Update statistics
            self._update_stats(result, processing_time)

            # Only log successful processing if enabled
            if self.log_successes:
                self.log_info(
                    "File processed successfully",
                    file_path=str(file_path),
                    matches=len(matches),
                    confidence=result.confidence,
                    processing_time_ms=processing_time,
                )

            return result

        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000
            self.stats.failed_extractions += 1
            self.log_error(
                "File processing failed",
                file_path=str(file_path),
                error=str(e),
                processing_time_ms=processing_time,
            )

            if isinstance(e, (FileReadError, ProcessingError)):
                raise
            else:
                raise ProcessingError(
                    f"Unexpected error processing {file_path}: {str(e)}"
                ) from e

    async def process_files_batch(
        self, file_paths: list[Path], max_concurrent: int = 10
    ) -> list[ExtractionResult]:
        """Process multiple files concurrently."""
        if not file_paths:
            return []

        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_with_semaphore(file_path: Path) -> Optional[ExtractionResult]:
            async with semaphore:
                try:
                    return await self.process_file(file_path)
                except Exception as e:
                    self.log_error(
                        "Batch processing error", file_path=str(file_path), error=str(e)
                    )
                    return None

        # Process all files concurrently
        tasks = [process_with_semaphore(file_path) for file_path in file_paths]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        # Filter out None results (failed processing)
        valid_results = [result for result in results if result is not None]

        self.log_info(
            "Batch processing completed",
            total_files=len(file_paths),
            successful=len(valid_results),
            failed=len(file_paths) - len(valid_results),
        )

        return valid_results

    async def _read_file_content(self, file_path: Path) -> str:
        """Read file content with proper encoding handling."""
        try:
            # Try UTF-8 first
            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                # Fallback to latin-1 for problematic files
                self.log_warning(
                    "UTF-8 decode failed, trying latin-1", file_path=str(file_path)
                )
                content = file_path.read_text(encoding="latin-1")

            return content

        except OSError as e:
            raise FileReadError(f"Cannot read file {file_path}: {str(e)}") from e

    def _should_process_content(self, content: str) -> bool:
        """Check if content should be processed based on filters."""
        # Skip very small files
        if len(content) < self.config.min_content_length:
            return False

        # Skip files without expected keywords
        required_keywords = ["checkov", "severity"]
        content_lower = content.lower()

        if not any(keyword in content_lower for keyword in required_keywords):
            return False

        # Skip binary-like content
        if self._appears_binary(content):
            return False

        return True

    def _appears_binary(self, content: str) -> bool:
        """Check if content appears to be binary."""
        # Check for high ratio of non-printable characters
        printable_chars = sum(1 for c in content if c.isprintable() or c.isspace())
        if len(content) > 0:
            printable_ratio = printable_chars / len(content)
            return printable_ratio < 0.7
        return False

    async def _create_checkov_matches(
        self, checkov_matches: list, severity_matches: list[str], content: str
    ) -> list[CheckovMatch]:
        """Create CheckovMatch objects by associating IDs with severities."""
        matches = []

        # Import here to avoid circular imports
        from ..models.checkov import CheckovMatch

        for i, checkov_match in enumerate(checkov_matches):
            # Try to find the best severity match
            severity = None

            if severity_matches:
                # Simple heuristic: use severity in same order, or first/last
                if i < len(severity_matches):
                    severity = severity_matches[i]
                elif len(severity_matches) == 1:
                    severity = severity_matches[0]
                else:
                    # Try to find severity near the Checkov ID in content
                    severity = self._find_nearest_severity(
                        checkov_match, severity_matches, content
                    )

            # Create enhanced match
            enhanced_match = CheckovMatch(
                checkov_id=checkov_match.checkov_id,
                severity=severity,
                confidence=checkov_match.confidence,
                start_position=checkov_match.start_position,
                end_position=checkov_match.end_position,
                context=checkov_match.context,
                pattern_name=checkov_match.pattern_name,
            )

            matches.append(enhanced_match)

        return matches

    def _find_nearest_severity(
        self, checkov_match, severity_matches: list[str], content: str
    ) -> Optional[str]:
        """Find severity closest to the Checkov ID in the content."""
        if not severity_matches:
            return None

        # Simple heuristic: find severity keywords near the match position
        match_pos = checkov_match.start_position
        best_severity = None
        min_distance = float("inf")

        for severity in severity_matches:
            # Find all occurrences of this severity in content
            severity_pos = content.lower().find(severity.lower())
            while severity_pos != -1:
                distance = abs(severity_pos - match_pos)
                if distance < min_distance:
                    min_distance = distance
                    best_severity = severity

                # Look for next occurrence
                severity_pos = content.lower().find(severity.lower(), severity_pos + 1)

        return best_severity or severity_matches[0]

    def _calculate_content_hash(self, content: str) -> str:
        """Calculate hash of content for change detection."""
        import hashlib

        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def _update_stats(self, result: ExtractionResult, processing_time: float) -> None:
        """Update processing statistics."""
        self.stats.files_processed += 1

        if result.matches:
            self.stats.successful_extractions += 1
            self.stats.total_matches += len(result.matches)

        # Update average confidence
        if self.stats.successful_extractions > 0:
            old_avg = self.stats.average_confidence
            n = self.stats.successful_extractions
            self.stats.average_confidence = (old_avg * (n - 1) + result.confidence) / n

        # Update processing time
        if self.stats.files_processed > 0:
            old_avg = self.stats.processing_time_ms
            n = self.stats.files_processed
            self.stats.processing_time_ms = (old_avg * (n - 1) + processing_time) / n

    def get_processing_summary(self) -> dict[str, Any]:
        """Get summary of processing statistics."""
        success_rate = 0.0
        if self.stats.files_processed > 0:
            success_rate = (
                self.stats.successful_extractions / self.stats.files_processed
            )

        return {
            "files_processed": self.stats.files_processed,
            "successful_extractions": self.stats.successful_extractions,
            "failed_extractions": self.stats.failed_extractions,
            "success_rate": success_rate,
            "total_matches": self.stats.total_matches,
            "average_confidence": self.stats.average_confidence,
            "average_processing_time_ms": self.stats.processing_time_ms,
        }

    def reset_stats(self) -> None:
        """Reset processing statistics."""
        self.stats = ProcessingStats()

    def _create_empty_result(
        self, file_path: str, processing_time: float
    ) -> ExtractionResult:
        """Create an empty extraction result for skipped files."""
        return ExtractionResult(
            file_path=file_path,
            checkov_id=None,
            severity=None,
            raw_checkov_id=None,
            raw_severity=None,
            matches=[],
            processing_time_ms=processing_time,
            confidence=0.0,
            content_hash="",
        )
