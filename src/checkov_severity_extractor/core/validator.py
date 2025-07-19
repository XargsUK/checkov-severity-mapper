"""
Data validation and quality assurance for extracted mappings.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..models.checkov import CheckovId, CheckovMatch, ExtractionResult
from ..models.database import SeverityDatabase
from ..models.severity import SeverityLevel
from ..utils.logging import LoggerMixin


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class ValidationIssue:
    """Represents a validation issue."""

    severity: ValidationSeverity
    code: str
    message: str
    file_path: Optional[str] = None
    checkov_id: Optional[str] = None
    context: Optional[str] = None


@dataclass
class ValidationReport:
    """Comprehensive validation report."""

    is_valid: bool
    issues: list[ValidationIssue]
    error_count: int
    warning_count: int
    info_count: int
    confidence_score: float

    @classmethod
    def create(
        cls, issues: list[ValidationIssue], confidence_score: float = 0.0
    ) -> "ValidationReport":
        """Create a validation report from issues."""
        error_count = sum(
            1 for issue in issues if issue.severity == ValidationSeverity.ERROR
        )
        warning_count = sum(
            1 for issue in issues if issue.severity == ValidationSeverity.WARNING
        )
        info_count = sum(
            1 for issue in issues if issue.severity == ValidationSeverity.INFO
        )

        return cls(
            is_valid=error_count == 0,
            issues=issues,
            error_count=error_count,
            warning_count=warning_count,
            info_count=info_count,
            confidence_score=confidence_score,
        )


class DataValidator(LoggerMixin):
    """Validates extracted data for quality and consistency."""

    def __init__(self, existing_database: Optional[SeverityDatabase] = None):
        """Initialise validator with optional existing database for comparison."""
        self.existing_database = existing_database
        self._known_checkov_ids: set[str] = set()
        self._load_known_ids()

    def _load_known_ids(self) -> None:
        """Load known Checkov IDs from existing database."""
        if self.existing_database:
            self._known_checkov_ids = set(self.existing_database.mappings.keys())
            self.logger.info(
                "Loaded known Checkov IDs", count=len(self._known_checkov_ids)
            )

    async def validate_extraction_result(
        self, result: ExtractionResult
    ) -> ValidationReport:
        """Validate a complete extraction result."""
        issues = []

        # Basic validation
        issues.extend(await self._validate_basic_structure(result))

        # Individual match validation
        for match in result.matches:
            issues.extend(await self._validate_checkov_match(match, result.file_path))

        # Cross-validation between matches
        issues.extend(
            await self._validate_match_consistency(result.matches, result.file_path)
        )

        # Database consistency validation
        if self.existing_database:
            issues.extend(await self._validate_against_database(result))

        return ValidationReport.create(issues, result.confidence)

    async def validate_checkov_match(
        self, match: CheckovMatch, file_path: str = ""
    ) -> ValidationReport:
        """Validate a single Checkov match."""
        issues = await self._validate_checkov_match(match, file_path)
        return ValidationReport.create(issues, match.confidence)

    async def validate_severity_database(
        self, database: SeverityDatabase
    ) -> ValidationReport:
        """Validate an entire severity database."""
        issues = []

        # Validate database metadata
        issues.extend(await self._validate_database_metadata(database))

        # Validate each mapping
        for checkov_id, severity in database.mappings.items():
            issues.extend(await self._validate_mapping(checkov_id, severity))

        # Check for duplicate patterns
        issues.extend(await self._validate_database_consistency(database))

        confidence = self._calculate_database_confidence(database, issues)
        return ValidationReport.create(issues, confidence)

    async def _validate_basic_structure(
        self, result: ExtractionResult
    ) -> list[ValidationIssue]:
        """Validate basic structure of extraction result."""
        issues = []

        if not result.matches:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="NO_MATCHES",
                    message="No Checkov matches found in file",
                    file_path=result.file_path,
                )
            )

        if result.confidence < 0.3:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="LOW_CONFIDENCE",
                    message=f"Low confidence score: {result.confidence:.2f}",
                    file_path=result.file_path,
                )
            )

        if len(result.matches) > 5:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="TOO_MANY_MATCHES",
                    message=f"Unusually high number of matches: {len(result.matches)}",
                    file_path=result.file_path,
                )
            )

        return issues

    async def _validate_checkov_match(
        self, match: CheckovMatch, file_path: str
    ) -> list[ValidationIssue]:
        """Validate individual Checkov match."""
        issues = []

        # Validate Checkov ID format
        checkov_id = CheckovId.from_string(match.checkov_id)
        if not checkov_id:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_CHECKOV_ID",
                    message=f"Invalid Checkov ID format: {match.checkov_id}",
                    file_path=file_path,
                    checkov_id=match.checkov_id,
                )
            )

        # Validate severity if present
        if match.severity:
            if not SeverityLevel.from_string(match.severity):
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="INVALID_SEVERITY",
                        message=f"Invalid severity level: {match.severity}",
                        file_path=file_path,
                        checkov_id=match.checkov_id,
                    )
                )
        else:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="MISSING_SEVERITY",
                    message="No severity found for Checkov ID",
                    file_path=file_path,
                    checkov_id=match.checkov_id,
                )
            )

        # Validate confidence
        if match.confidence < 0.2:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="LOW_MATCH_CONFIDENCE",
                    message=f"Low match confidence: {match.confidence:.2f}",
                    file_path=file_path,
                    checkov_id=match.checkov_id,
                )
            )

        # Check against known IDs
        if self._known_checkov_ids and match.checkov_id not in self._known_checkov_ids:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    code="NEW_CHECKOV_ID",
                    message="New Checkov ID not in existing database",
                    file_path=file_path,
                    checkov_id=match.checkov_id,
                )
            )

        return issues

    async def _validate_match_consistency(
        self, matches: list[CheckovMatch], file_path: str
    ) -> list[ValidationIssue]:
        """Validate consistency between multiple matches."""
        issues = []

        if not matches:
            return issues

        # Check for duplicate Checkov IDs
        checkov_ids = [match.checkov_id for match in matches]
        duplicates = [id for id in set(checkov_ids) if checkov_ids.count(id) > 1]

        for duplicate_id in duplicates:
            duplicate_matches = [m for m in matches if m.checkov_id == duplicate_id]
            severities = {m.severity for m in duplicate_matches if m.severity}

            if len(severities) > 1:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        code="CONFLICTING_SEVERITIES",
                        message=f"Conflicting severities for {duplicate_id}: {', '.join(severities)}",
                        file_path=file_path,
                        checkov_id=duplicate_id,
                    )
                )
            else:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="DUPLICATE_CHECKOV_ID",
                        message=f"Duplicate Checkov ID found: {duplicate_id}",
                        file_path=file_path,
                        checkov_id=duplicate_id,
                    )
                )

        # Check confidence variation
        confidences = [match.confidence for match in matches]
        if len(confidences) > 1:
            confidence_range = max(confidences) - min(confidences)
            if confidence_range > 0.5:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        code="HIGH_CONFIDENCE_VARIATION",
                        message=f"High confidence variation: {confidence_range:.2f}",
                        file_path=file_path,
                    )
                )

        return issues

    async def _validate_against_database(
        self, result: ExtractionResult
    ) -> list[ValidationIssue]:
        """Validate extraction result against existing database."""
        issues = []

        if not self.existing_database:
            return issues

        for match in result.matches:
            if match.checkov_id in self.existing_database.mappings:
                existing_severity = self.existing_database.mappings[match.checkov_id]

                if match.severity and match.severity != existing_severity.value:
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            code="SEVERITY_MISMATCH",
                            message=f"Severity mismatch: found {match.severity}, database has {existing_severity.value}",
                            file_path=result.file_path,
                            checkov_id=match.checkov_id,
                        )
                    )

        return issues

    async def _validate_database_metadata(
        self, database: SeverityDatabase
    ) -> list[ValidationIssue]:
        """Validate database metadata."""
        issues = []

        if not database.metadata.version:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="MISSING_VERSION",
                    message="Database missing version information",
                )
            )

        if database.metadata.total_entries != len(database.mappings):
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="COUNT_MISMATCH",
                    message=f"Metadata count mismatch: {database.metadata.total_entries} vs {len(database.mappings)}",
                )
            )

        return issues

    async def _validate_mapping(
        self, checkov_id: str, severity: SeverityLevel
    ) -> list[ValidationIssue]:
        """Validate individual mapping."""
        issues = []

        # Validate Checkov ID
        if not CheckovId.from_string(checkov_id):
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_DB_CHECKOV_ID",
                    message=f"Invalid Checkov ID in database: {checkov_id}",
                    checkov_id=checkov_id,
                )
            )

        # Validate severity
        try:
            SeverityLevel(severity.value)
        except ValueError:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="INVALID_DB_SEVERITY",
                    message=f"Invalid severity in database: {severity}",
                    checkov_id=checkov_id,
                )
            )

        return issues

    async def _validate_database_consistency(
        self, database: SeverityDatabase
    ) -> list[ValidationIssue]:
        """Validate overall database consistency."""
        issues = []

        # Check for unusual patterns
        severity_counts = database.metadata.severity_distribution
        total = sum(severity_counts.values())

        if total > 0:
            # Check if any severity is disproportionately high
            for severity, count in severity_counts.items():
                percentage = count / total
                if percentage > 0.8:
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.INFO,
                            code="SKEWED_DISTRIBUTION",
                            message=f"Severity {severity} represents {percentage:.1%} of all entries",
                        )
                    )

        return issues

    def _calculate_database_confidence(
        self, database: SeverityDatabase, issues: list[ValidationIssue]
    ) -> float:
        """Calculate confidence score for database."""
        base_confidence = 1.0

        # Reduce confidence based on issues
        for issue in issues:
            if issue.severity == ValidationSeverity.ERROR:
                base_confidence -= 0.2
            elif issue.severity == ValidationSeverity.WARNING:
                base_confidence -= 0.1
            elif issue.severity == ValidationSeverity.INFO:
                base_confidence -= 0.05

        # Boost confidence for complete metadata
        if database.metadata.version and database.metadata.last_updated:
            base_confidence += 0.1

        return max(0.0, min(1.0, base_confidence))

    async def generate_quality_report(self, database: SeverityDatabase) -> dict:
        """Generate comprehensive quality report."""
        validation_report = await self.validate_severity_database(database)

        return {
            "validation_summary": {
                "is_valid": validation_report.is_valid,
                "confidence_score": validation_report.confidence_score,
                "total_issues": len(validation_report.issues),
                "errors": validation_report.error_count,
                "warnings": validation_report.warning_count,
                "info": validation_report.info_count,
            },
            "database_stats": {
                "total_mappings": len(database.mappings),
                "severity_distribution": dict(database.metadata.severity_distribution),
                "last_updated": database.metadata.last_updated.isoformat()
                if database.metadata.last_updated
                else None,
            },
            "issues": [
                {
                    "severity": issue.severity.value,
                    "code": issue.code,
                    "message": issue.message,
                    "checkov_id": issue.checkov_id,
                    "file_path": issue.file_path,
                }
                for issue in validation_report.issues
            ],
        }
