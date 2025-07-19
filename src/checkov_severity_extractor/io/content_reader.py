"""
Content reading utilities with encoding detection and preprocessing.
"""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import chardet

from ..utils.exceptions import FileReadError
from ..utils.logging import LoggerMixin


@dataclass
class ReadResult:
    """Result of content reading operation."""

    content: str
    encoding: str
    file_size: int
    read_time_ms: float
    preprocessing_applied: list[str]


class ContentReader(LoggerMixin):
    """Reads and preprocesses file content with encoding detection."""

    def __init__(
        self,
        fallback_encoding: str = "utf-8",
        detect_encoding: bool = True,
        max_detection_bytes: int = 10000,
        enable_preprocessing: bool = True,
    ):
        """Initialise content reader with configuration."""
        self.fallback_encoding = fallback_encoding
        self.detect_encoding = detect_encoding
        self.max_detection_bytes = max_detection_bytes
        self.enable_preprocessing = enable_preprocessing

    async def read_file(self, file_path: Path) -> ReadResult:
        """Read file content with encoding detection and preprocessing."""
        import time

        start_time = time.perf_counter()

        if not file_path.exists():
            raise FileReadError(f"File not found: {file_path}")

        if not file_path.is_file():
            raise FileReadError(f"Not a regular file: {file_path}")

        try:
            # Get file size
            file_size = file_path.stat().st_size

            # Detect encoding
            encoding = (
                await self._detect_encoding(file_path)
                if self.detect_encoding
                else self.fallback_encoding
            )

            # Read content
            content = await self._read_with_encoding(file_path, encoding)

            # Apply preprocessing
            preprocessing_applied = []
            if self.enable_preprocessing:
                content, preprocessing_applied = await self._preprocess_content(content)

            read_time = (time.perf_counter() - start_time) * 1000

            self.log_debug(
                "File read successfully",
                file_path=str(file_path),
                encoding=encoding,
                size_bytes=file_size,
                read_time_ms=read_time,
            )

            return ReadResult(
                content=content,
                encoding=encoding,
                file_size=file_size,
                read_time_ms=read_time,
                preprocessing_applied=preprocessing_applied,
            )

        except UnicodeDecodeError as e:
            raise FileReadError(f"Encoding error reading {file_path}: {str(e)}") from e
        except OSError as e:
            raise FileReadError(f"OS error reading {file_path}: {str(e)}") from e
        except Exception as e:
            raise FileReadError(
                f"Unexpected error reading {file_path}: {str(e)}"
            ) from e

    async def read_files_batch(
        self, file_paths: list[Path], max_concurrent: int = 10
    ) -> dict[Path, ReadResult]:
        """Read multiple files concurrently."""
        if not file_paths:
            return {}

        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(max_concurrent)

        async def read_with_semaphore(
            file_path: Path,
        ) -> tuple[Path, Optional[ReadResult]]:
            async with semaphore:
                try:
                    result = await self.read_file(file_path)
                    return file_path, result
                except Exception as e:
                    self.log_error(
                        "Batch read error", file_path=str(file_path), error=str(e)
                    )
                    return file_path, None

        # Read all files concurrently
        tasks = [read_with_semaphore(file_path) for file_path in file_paths]
        results = await asyncio.gather(*tasks)

        # Filter out failed reads
        successful_results = {
            file_path: result for file_path, result in results if result is not None
        }

        self.log_info(
            "Batch read completed",
            total_files=len(file_paths),
            successful=len(successful_results),
            failed=len(file_paths) - len(successful_results),
        )

        return successful_results

    async def _detect_encoding(self, file_path: Path) -> str:
        """Detect file encoding using chardet."""
        try:
            # Read a sample of the file for detection
            with file_path.open("rb") as f:
                raw_data = f.read(self.max_detection_bytes)

            if not raw_data:
                return self.fallback_encoding

            # Use chardet to detect encoding
            detection_result = chardet.detect(raw_data)
            detected_encoding = detection_result.get("encoding")
            confidence = detection_result.get("confidence", 0.0)

            # Use detected encoding if confidence is high enough
            if detected_encoding and confidence > 0.7:
                self.log_debug(
                    "Encoding detected",
                    file_path=str(file_path),
                    encoding=detected_encoding,
                    confidence=confidence,
                )
                return detected_encoding
            else:
                self.log_debug(
                    "Low confidence encoding detection, using fallback",
                    file_path=str(file_path),
                    detected=detected_encoding,
                    confidence=confidence,
                    fallback=self.fallback_encoding,
                )
                return self.fallback_encoding

        except Exception as e:
            self.log_warning(
                "Encoding detection failed, using fallback",
                file_path=str(file_path),
                error=str(e),
                fallback=self.fallback_encoding,
            )
            return self.fallback_encoding

    async def _read_with_encoding(self, file_path: Path, encoding: str) -> str:
        """Read file content with specified encoding."""
        try:
            return file_path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            # Try with fallback encoding
            if encoding != self.fallback_encoding:
                self.log_warning(
                    "Primary encoding failed, trying fallback",
                    file_path=str(file_path),
                    primary=encoding,
                    fallback=self.fallback_encoding,
                )
                return file_path.read_text(encoding=self.fallback_encoding)
            else:
                # Try with error handling
                return file_path.read_text(encoding=encoding, errors="replace")

    async def _preprocess_content(self, content: str) -> tuple[str, list[str]]:
        """Preprocess content for better extraction."""
        preprocessing_applied = []
        original_content = content

        # Normalize line endings
        if "\r\n" in content or "\r" in content:
            content = content.replace("\r\n", "\n").replace("\r", "\n")
            preprocessing_applied.append("normalized_line_endings")

        # Remove excessive whitespace while preserving structure
        lines = content.split("\n")
        processed_lines = []

        for line in lines:
            # Remove trailing whitespace
            processed_line = line.rstrip()
            processed_lines.append(processed_line)

        # Join lines back
        processed_content = "\n".join(processed_lines)

        # Remove excessive blank lines (more than 2 consecutive)
        import re

        if re.search(r"\n\s*\n\s*\n\s*\n", processed_content):
            processed_content = re.sub(r"\n(\s*\n){3,}", "\n\n\n", processed_content)
            preprocessing_applied.append("reduced_excessive_blank_lines")

        # Normalize Unicode characters
        try:
            import unicodedata

            normalized_content = unicodedata.normalize("NFKC", processed_content)
            if normalized_content != processed_content:
                processed_content = normalized_content
                preprocessing_applied.append("unicode_normalization")
        except Exception:
            pass  # Skip if unicodedata not available

        # Remove BOM if present
        if processed_content.startswith("\ufeff"):
            processed_content = processed_content[1:]
            preprocessing_applied.append("removed_bom")

        # Log significant changes
        if len(preprocessing_applied) > 0:
            original_lines = len(original_content.split("\n"))
            processed_lines = len(processed_content.split("\n"))

            self.log_debug(
                "Content preprocessing applied",
                changes=preprocessing_applied,
                original_lines=original_lines,
                processed_lines=processed_lines,
            )

        return processed_content, preprocessing_applied

    async def validate_content(self, content: str) -> dict[str, Any]:
        """Validate content for extraction suitability."""
        validation_results = {
            "is_valid": True,
            "issues": [],
            "stats": {
                "length": len(content),
                "lines": len(content.split("\n")),
                "non_ascii_chars": sum(1 for c in content if ord(c) > 127),
                "control_chars": sum(
                    1 for c in content if ord(c) < 32 and c not in "\n\r\t"
                ),
            },
        }

        # Check minimum length
        if len(content) < 50:
            validation_results["issues"].append("Content too short")
            validation_results["is_valid"] = False

        # Check for binary content indicators
        control_char_ratio = (
            validation_results["stats"]["control_chars"] / len(content)
            if content
            else 0
        )
        if control_char_ratio > 0.1:
            validation_results["issues"].append(
                "High ratio of control characters (possible binary content)"
            )
            validation_results["is_valid"] = False

        # Check for relevant keywords
        content_lower = content.lower()
        relevant_keywords = ["checkov", "severity", "policy", "rule", "check"]
        found_keywords = [kw for kw in relevant_keywords if kw in content_lower]

        if not found_keywords:
            validation_results["issues"].append("No relevant keywords found")
            # Don't mark as invalid, just note the issue

        validation_results["stats"]["relevant_keywords"] = found_keywords

        return validation_results

    def get_reader_statistics(self) -> dict[str, Any]:
        """Get current reader configuration statistics."""
        return {
            "fallback_encoding": self.fallback_encoding,
            "detect_encoding": self.detect_encoding,
            "max_detection_bytes": self.max_detection_bytes,
            "enable_preprocessing": self.enable_preprocessing,
        }
