"""
Custom exceptions for the Checkov severity extractor.
"""

from typing import Any, Optional


class CheckovExtractionError(Exception):
    """Base exception for Checkov extraction errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({detail_str})"
        return self.message


class ValidationError(CheckovExtractionError):
    """Exception raised when data validation fails."""

    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        super().__init__(message, details)
        self.field = field
        self.value = value


class DataQualityError(ValidationError):
    """Exception raised when data quality issues are detected."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        quality_issue: Optional[str] = None,
    ):
        details = {}
        if field:
            details["field"] = field
        if quality_issue:
            details["quality_issue"] = quality_issue
        super().__init__(message, field)
        self.quality_issue = quality_issue


class FileProcessingError(CheckovExtractionError):
    """Exception raised when file processing fails."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
    ):
        details = {}
        if file_path:
            details["file_path"] = file_path
        if line_number:
            details["line_number"] = line_number
        super().__init__(message, details)
        self.file_path = file_path
        self.line_number = line_number


class ProcessingError(CheckovExtractionError):
    """Exception raised when general processing fails."""

    def __init__(
        self,
        message: str,
        component: Optional[str] = None,
        operation: Optional[str] = None,
    ):
        details = {}
        if component:
            details["component"] = component
        if operation:
            details["operation"] = operation
        super().__init__(message, details)
        self.component = component
        self.operation = operation


class PatternMatchError(CheckovExtractionError):
    """Exception raised when pattern matching fails."""

    def __init__(
        self,
        message: str,
        pattern_name: Optional[str] = None,
        content_snippet: Optional[str] = None,
    ):
        details = {}
        if pattern_name:
            details["pattern_name"] = pattern_name
        if content_snippet:
            # Truncate content snippet for readability
            snippet = (
                content_snippet[:100] + "..."
                if len(content_snippet) > 100
                else content_snippet
            )
            details["content_snippet"] = snippet
        super().__init__(message, details)
        self.pattern_name = pattern_name
        self.content_snippet = content_snippet


class ConfigurationError(CheckovExtractionError):
    """Exception raised when configuration is invalid."""

    def __init__(
        self, message: str, config_field: Optional[str] = None, config_value: Any = None
    ):
        details = {}
        if config_field:
            details["config_field"] = config_field
        if config_value is not None:
            details["config_value"] = str(config_value)
        super().__init__(message, details)
        self.config_field = config_field
        self.config_value = config_value


class TimeoutError(CheckovExtractionError):
    """Exception raised when an operation times out."""

    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[float] = None,
        operation: Optional[str] = None,
    ):
        details = {}
        if timeout_seconds:
            details["timeout_seconds"] = timeout_seconds
        if operation:
            details["operation"] = operation
        super().__init__(message, details)
        self.timeout_seconds = timeout_seconds
        self.operation = operation


class OutputError(CheckovExtractionError):
    """Exception raised when output generation fails."""

    def __init__(
        self,
        message: str,
        output_path: Optional[str] = None,
        output_format: Optional[str] = None,
    ):
        details = {}
        if output_path:
            details["output_path"] = output_path
        if output_format:
            details["output_format"] = output_format
        super().__init__(message, details)
        self.output_path = output_path
        self.output_format = output_format


class FileSystemError(CheckovExtractionError):
    """Exception raised when file system operations fail."""

    def __init__(
        self, message: str, path: Optional[str] = None, operation: Optional[str] = None
    ):
        details = {}
        if path:
            details["path"] = path
        if operation:
            details["operation"] = operation
        super().__init__(message, details)
        self.path = path
        self.operation = operation


class FileReadError(FileProcessingError):
    """Exception raised when file reading fails."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        encoding: Optional[str] = None,
    ):
        details = {}
        if file_path:
            details["file_path"] = file_path
        if encoding:
            details["encoding"] = encoding
        super().__init__(message, file_path)
        self.encoding = encoding


class FileWriteError(FileProcessingError):
    """Exception raised when file writing fails."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        output_format: Optional[str] = None,
    ):
        details = {}
        if file_path:
            details["file_path"] = file_path
        if output_format:
            details["output_format"] = output_format
        super().__init__(message, file_path)
        self.output_format = output_format


class DependencyError(CheckovExtractionError):
    """Exception raised when required dependencies are missing or incompatible."""

    def __init__(
        self,
        message: str,
        dependency: Optional[str] = None,
        required_version: Optional[str] = None,
    ):
        details = {}
        if dependency:
            details["dependency"] = dependency
        if required_version:
            details["required_version"] = required_version
        super().__init__(message, details)
        self.dependency = dependency
        self.required_version = required_version


class ExtractionWarning(UserWarning):
    """Warning for non-critical extraction issues."""

    def __init__(self, message: str, context: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.context = context or {}


def handle_extraction_error(
    error: Exception, context: Optional[dict] = None
) -> CheckovExtractionError:
    """Convert generic exceptions to CheckovExtractionError with context."""
    if isinstance(error, CheckovExtractionError):
        return error

    error_context = context or {}
    error_context["original_error"] = str(error)
    error_context["error_type"] = type(error).__name__

    if isinstance(error, FileNotFoundError):
        return FileProcessingError(
            f"File not found: {error}", file_path=error_context.get("file_path")
        )
    elif isinstance(error, PermissionError):
        return FileProcessingError(
            f"Permission denied: {error}", file_path=error_context.get("file_path")
        )
    elif isinstance(error, UnicodeDecodeError):
        return FileProcessingError(
            f"Encoding error: {error}", file_path=error_context.get("file_path")
        )
    elif isinstance(error, TimeoutError):
        return TimeoutError(
            f"Operation timed out: {error}",
            timeout_seconds=error_context.get("timeout_seconds"),
            operation=error_context.get("operation"),
        )
    else:
        return CheckovExtractionError(
            f"Unexpected error: {error}", details=error_context
        )
