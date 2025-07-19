"""
JSON output writer with formatting and validation options.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..models.checkov import ExtractionResult
from ..models.database import SeverityDatabase
from ..utils.exceptions import FileWriteError
from ..utils.logging import LoggerMixin


@dataclass
class JsonWriteOptions:
    """Options for JSON output formatting."""

    indent: Optional[int] = 2
    sort_keys: bool = True
    ensure_ascii: bool = False
    separators: Optional[tuple] = None
    include_metadata: bool = True
    include_statistics: bool = True
    include_timestamps: bool = True
    compact_format: bool = False


class JsonWriter(LoggerMixin):
    """Writes extraction results and databases to JSON format."""

    def __init__(self, options: Optional[JsonWriteOptions] = None):
        """Initialise JSON writer with formatting options."""
        self.options = options or JsonWriteOptions()

    async def write_database(
        self,
        database: SeverityDatabase,
        output_path: Path,
        backup_existing: bool = True,
    ) -> None:
        """Write severity database to JSON file."""
        try:
            # Create backup if requested and file exists
            if backup_existing and output_path.exists():
                await self._create_backup(output_path)

            # Prepare database data
            database_dict = self._prepare_database_dict(database)

            # Write to file
            await self._write_json_file(database_dict, output_path)

            self.log_info(
                "Database written to JSON",
                output_path=str(output_path),
                entries=len(database.mappings),
            )

        except Exception as e:
            raise FileWriteError(
                f"Failed to write database to {output_path}: {str(e)}"
            ) from e

    async def write_extraction_results(
        self,
        results: list[ExtractionResult],
        output_path: Path,
        include_raw_results: bool = False,
    ) -> None:
        """Write extraction results to JSON file."""
        try:
            # Prepare results data
            results_dict = self._prepare_results_dict(results, include_raw_results)

            # Write to file
            await self._write_json_file(results_dict, output_path)

            self.log_info(
                "Extraction results written to JSON",
                output_path=str(output_path),
                results_count=len(results),
            )

        except Exception as e:
            raise FileWriteError(
                f"Failed to write results to {output_path}: {str(e)}"
            ) from e

    async def write_summary_report(
        self,
        database: SeverityDatabase,
        results: list[ExtractionResult],
        output_path: Path,
        processing_stats: Optional[dict[str, Any]] = None,
    ) -> None:
        """Write comprehensive summary report to JSON."""
        try:
            # Prepare summary data
            summary_dict = self._prepare_summary_dict(
                database, results, processing_stats
            )

            # Write to file
            await self._write_json_file(summary_dict, output_path)

            self.log_info(
                "Summary report written to JSON", output_path=str(output_path)
            )

        except Exception as e:
            raise FileWriteError(
                f"Failed to write summary to {output_path}: {str(e)}"
            ) from e

    def _prepare_database_dict(self, database: SeverityDatabase) -> dict[str, Any]:
        """Prepare database for JSON serialization."""
        # Convert database to dictionary
        db_dict = database.to_dict()

        # Add metadata if enabled
        if self.options.include_metadata:
            db_dict["export_metadata"] = {
                "exported_at": datetime.utcnow().isoformat() + "Z",
                "format_version": "1.0",
                "exported_by": "checkov-severity-extractor",
            }

        # Add statistics if enabled
        if self.options.include_statistics:
            db_dict["statistics"] = {
                "total_mappings": len(database.mappings),
                "severity_breakdown": dict(database.metadata.severity_distribution),
                "confidence_metrics": self._calculate_database_confidence_metrics(
                    database
                ),
            }

        return db_dict

    def _prepare_results_dict(
        self, results: list[ExtractionResult], include_raw_results: bool
    ) -> dict[str, Any]:
        """Prepare extraction results for JSON serialization."""
        results_dict = {"extraction_results": []}

        # Add metadata
        if self.options.include_metadata:
            results_dict["metadata"] = {
                "total_files": len(results),
                "successful_extractions": len([r for r in results if r.matches]),
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "format_version": "1.0",
            }

        # Process each result
        for result in results:
            result_dict = {
                "file_path": result.file_path,
                "confidence": result.confidence,
                "processing_time_ms": result.processing_time_ms,
                "matches": [],
            }

            # Add matches
            for match in result.matches:
                match_dict = {
                    "checkov_id": match.checkov_id,
                    "severity": match.severity,
                    "confidence": match.confidence,
                    "pattern_name": match.pattern_name,
                }

                # Include detailed information if requested
                if include_raw_results:
                    match_dict.update(
                        {
                            "start_position": match.start_position,
                            "end_position": match.end_position,
                            "context": match.context,
                        }
                    )

                result_dict["matches"].append(match_dict)

            # Add validation issues if present
            if result.validation_issues:
                result_dict["validation_issues"] = [
                    {
                        "severity": issue.severity.value,
                        "code": issue.code,
                        "message": issue.message,
                        "checkov_id": issue.checkov_id,
                    }
                    for issue in result.validation_issues
                ]

            results_dict["extraction_results"].append(result_dict)

        # Add statistics
        if self.options.include_statistics:
            results_dict["statistics"] = self._calculate_results_statistics(results)

        return results_dict

    def _prepare_summary_dict(
        self,
        database: SeverityDatabase,
        results: list[ExtractionResult],
        processing_stats: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        """Prepare comprehensive summary for JSON serialization."""
        summary_dict = {
            "summary": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "database_entries": len(database.mappings),
                "processed_files": len(results),
                "total_matches": sum(len(r.matches) for r in results),
            }
        }

        # Add database summary
        summary_dict["database_summary"] = {
            "severity_distribution": dict(database.metadata.severity_distribution),
            "last_updated": database.metadata.last_updated.isoformat()
            if database.metadata.last_updated
            else None,
            "version": database.metadata.version,
        }

        # Add extraction summary
        successful_results = [r for r in results if r.matches]
        summary_dict["extraction_summary"] = {
            "success_rate": len(successful_results) / len(results) if results else 0,
            "average_confidence": sum(r.confidence for r in successful_results)
            / len(successful_results)
            if successful_results
            else 0,
            "new_mappings": self._identify_new_mappings(database, results),
            "validation_issues": self._summarize_validation_issues(results),
        }

        # Add processing statistics
        if processing_stats:
            summary_dict["processing_statistics"] = processing_stats

        return summary_dict

    def _calculate_database_confidence_metrics(
        self, database: SeverityDatabase
    ) -> dict[str, Any]:
        """Calculate confidence metrics for database."""
        # This would require additional confidence data in the database
        # For now, return basic metrics
        return {
            "has_metadata": bool(database.metadata.version),
            "has_timestamps": bool(database.metadata.last_updated),
            "completeness_score": 1.0 if len(database.mappings) > 0 else 0.0,
        }

    def _calculate_results_statistics(
        self, results: list[ExtractionResult]
    ) -> dict[str, Any]:
        """Calculate statistics for extraction results."""
        if not results:
            return {}

        matches = [match for result in results for match in result.matches]
        confidences = [result.confidence for result in results if result.confidence > 0]

        return {
            "total_files": len(results),
            "files_with_matches": len([r for r in results if r.matches]),
            "total_matches": len(matches),
            "unique_checkov_ids": len({match.checkov_id for match in matches}),
            "confidence_stats": {
                "average": sum(confidences) / len(confidences) if confidences else 0,
                "min": min(confidences) if confidences else 0,
                "max": max(confidences) if confidences else 0,
            },
            "processing_time_stats": {
                "total_ms": sum(r.processing_time_ms for r in results),
                "average_ms": sum(r.processing_time_ms for r in results) / len(results),
            },
        }

    def _identify_new_mappings(
        self, database: SeverityDatabase, results: list[ExtractionResult]
    ) -> list[dict[str, str]]:
        """Identify new mappings found in results."""
        existing_ids = set(database.mappings.keys())
        new_mappings = []

        for result in results:
            for match in result.matches:
                if match.checkov_id not in existing_ids and match.severity:
                    new_mappings.append(
                        {
                            "checkov_id": match.checkov_id,
                            "severity": match.severity,
                            "file_path": result.file_path,
                        }
                    )

        # Remove duplicates
        seen = set()
        unique_new_mappings = []
        for mapping in new_mappings:
            key = (mapping["checkov_id"], mapping["severity"])
            if key not in seen:
                seen.add(key)
                unique_new_mappings.append(mapping)

        return unique_new_mappings

    def _summarize_validation_issues(
        self, results: list[ExtractionResult]
    ) -> dict[str, int]:
        """Summarize validation issues across all results."""
        issue_counts = {}

        for result in results:
            if result.validation_issues:
                for issue in result.validation_issues:
                    severity = issue.severity.value
                    issue_counts[severity] = issue_counts.get(severity, 0) + 1

        return issue_counts

    async def _write_json_file(self, data: dict[str, Any], output_path: Path) -> None:
        """Write data to JSON file with configured formatting."""
        try:
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Configure JSON encoding parameters
            json_params = {
                "ensure_ascii": self.options.ensure_ascii,
                "sort_keys": self.options.sort_keys,
            }

            if self.options.compact_format:
                json_params["separators"] = (",", ":")
                json_params["indent"] = None
            else:
                json_params["indent"] = self.options.indent
                if self.options.separators:
                    json_params["separators"] = self.options.separators

            # Write to file
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, **json_params)
                f.write("\n")  # Add trailing newline

        except OSError as e:
            raise FileWriteError(
                f"OS error writing JSON file {output_path}: {str(e)}"
            ) from e
        except TypeError as e:
            raise FileWriteError(
                f"JSON serialization error for {output_path}: {str(e)}"
            ) from e

    async def _create_backup(self, file_path: Path) -> None:
        """Create backup of existing file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = file_path.with_suffix(f".{timestamp}.bak")

        try:
            backup_path.write_bytes(file_path.read_bytes())
            self.log_info(f"Created backup: {backup_path}")
        except OSError as e:
            self.log_warning(f"Failed to create backup: {e}")

    def get_writer_statistics(self) -> dict[str, Any]:
        """Get current writer configuration statistics."""
        return {"options": asdict(self.options), "format_version": "1.0"}
