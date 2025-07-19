"""
File scanning and discovery utilities for AsciiDoc files.
"""

import asyncio
import fnmatch
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from re import Pattern
from typing import Optional

from ..utils.exceptions import FileSystemError
from ..utils.logging import LoggerMixin


@dataclass
class ScanResult:
    """Result of file scanning operation."""

    files: list[Path]
    total_scanned: int
    filtered_out: int
    scan_time_ms: float
    errors: list[str]


class FileScanner(LoggerMixin):
    """Scans directories for AsciiDoc files with filtering capabilities."""

    DEFAULT_EXTENSIONS = {".adoc", ".asciidoc", ".asc", ".txt"}
    DEFAULT_IGNORE_PATTERNS = {
        # Common directories to ignore
        ".*",  # Hidden directories
        "__pycache__",
        "node_modules",
        ".git",
        ".svn",
        "venv",
        "env",
        "dist",
        "build",
        "target",
        # Common files to ignore
        "*.pyc",
        "*.pyo",
        "*.pyd",
        "*.so",
        "*.dll",
        "*.exe",
        "Thumbs.db",
        ".DS_Store",
    }

    def __init__(
        self,
        extensions: Optional[set[str]] = None,
        ignore_patterns: Optional[set[str]] = None,
        max_file_size_mb: float = 100.0,
        follow_symlinks: bool = False,
    ):
        """Initialise file scanner with configuration."""
        self.extensions = extensions or self.DEFAULT_EXTENSIONS
        self.ignore_patterns = ignore_patterns or self.DEFAULT_IGNORE_PATTERNS
        self.max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)
        self.follow_symlinks = follow_symlinks

        # Compile ignore patterns for efficiency
        self._compiled_patterns: list[Pattern] = []
        for pattern in self.ignore_patterns:
            try:
                # Convert glob pattern to regex
                regex_pattern = fnmatch.translate(pattern)
                self._compiled_patterns.append(re.compile(regex_pattern))
            except re.error as e:
                self.log_warning(f"Invalid ignore pattern '{pattern}': {e}")

    async def scan_directory(
        self, directory: Path, recursive: bool = True, max_depth: Optional[int] = None
    ) -> ScanResult:
        """Scan directory for AsciiDoc files."""
        import time

        start_time = time.perf_counter()

        if not directory.exists():
            raise FileSystemError(f"Directory does not exist: {directory}")

        if not directory.is_dir():
            raise FileSystemError(f"Path is not a directory: {directory}")

        files = []
        total_scanned = 0
        filtered_out = 0
        errors = []

        try:
            if recursive:
                iterator = self._recursive_scan(directory, max_depth or 50)
            else:
                iterator = self._single_level_scan(directory)

            for file_path in iterator:
                total_scanned += 1

                try:
                    if await self._should_include_file(file_path):
                        files.append(file_path)
                    else:
                        filtered_out += 1

                except Exception as e:
                    error_msg = f"Error processing {file_path}: {str(e)}"
                    errors.append(error_msg)
                    self.log_warning(error_msg)
                    filtered_out += 1

        except Exception as e:
            scan_time = (time.perf_counter() - start_time) * 1000
            raise FileSystemError(
                f"Error scanning directory {directory}: {str(e)}"
            ) from e

        scan_time = (time.perf_counter() - start_time) * 1000

        self.log_info(
            "Directory scan completed",
            directory=str(directory),
            files_found=len(files),
            total_scanned=total_scanned,
            filtered_out=filtered_out,
            scan_time_ms=scan_time,
        )

        return ScanResult(
            files=sorted(files),  # Sort for consistent ordering
            total_scanned=total_scanned,
            filtered_out=filtered_out,
            scan_time_ms=scan_time,
            errors=errors,
        )

    async def scan_multiple_directories(
        self,
        directories: list[Path],
        recursive: bool = True,
        max_depth: Optional[int] = None,
    ) -> ScanResult:
        """Scan multiple directories concurrently."""
        if not directories:
            return ScanResult([], 0, 0, 0.0, [])

        # Scan directories concurrently
        tasks = [
            self.scan_directory(directory, recursive, max_depth)
            for directory in directories
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine results
        all_files = []
        total_scanned = 0
        filtered_out = 0
        all_errors = []
        total_time = 0.0

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                error_msg = f"Failed to scan {directories[i]}: {str(result)}"
                all_errors.append(error_msg)
                self.log_error(error_msg)
            else:
                all_files.extend(result.files)
                total_scanned += result.total_scanned
                filtered_out += result.filtered_out
                all_errors.extend(result.errors)
                total_time = max(total_time, result.scan_time_ms)

        # Remove duplicates while preserving order
        unique_files = []
        seen = set()
        for file_path in all_files:
            if file_path not in seen:
                unique_files.append(file_path)
                seen.add(file_path)

        return ScanResult(
            files=unique_files,
            total_scanned=total_scanned,
            filtered_out=filtered_out,
            scan_time_ms=total_time,
            errors=all_errors,
        )

    def _recursive_scan(self, directory: Path, max_depth: int) -> Iterator[Path]:
        """Recursively scan directory with depth limit."""

        def _scan_recursive(current_dir: Path, current_depth: int) -> Iterator[Path]:
            if current_depth > max_depth:
                return

            try:
                for item in current_dir.iterdir():
                    # Skip if matches ignore patterns
                    if self._should_ignore(item):
                        continue

                    if item.is_file():
                        yield item
                    elif item.is_dir() and current_depth < max_depth:
                        yield from _scan_recursive(item, current_depth + 1)

            except (PermissionError, OSError) as e:
                self.log_warning(f"Cannot access directory {current_dir}: {e}")

        yield from _scan_recursive(directory, 0)

    def _single_level_scan(self, directory: Path) -> Iterator[Path]:
        """Scan single directory level."""
        try:
            for item in directory.iterdir():
                if item.is_file() and not self._should_ignore(item):
                    yield item
        except (PermissionError, OSError) as e:
            self.log_warning(f"Cannot access directory {directory}: {e}")

    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored based on patterns."""
        name = path.name

        # Check against compiled patterns
        for pattern in self._compiled_patterns:
            if pattern.match(name):
                return True

        return False

    async def _should_include_file(self, file_path: Path) -> bool:
        """Check if file should be included in results."""
        # Check extension
        if not self._has_valid_extension(file_path):
            return False

        # Check file size
        try:
            stat = file_path.stat()
            if stat.st_size > self.max_file_size_bytes:
                self.log_warning(
                    f"File too large: {file_path} ({stat.st_size / 1024 / 1024:.1f} MB)"
                )
                return False
        except OSError:
            return False

        # Check if file is readable
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                # Try to read first few bytes to ensure it's a text file
                f.read(100)
            return True
        except (OSError, UnicodeError):
            return False

    def _has_valid_extension(self, file_path: Path) -> bool:
        """Check if file has a valid extension."""
        extension = file_path.suffix.lower()
        return extension in self.extensions

    def add_extension(self, extension: str) -> None:
        """Add a new file extension to scan for."""
        if not extension.startswith("."):
            extension = "." + extension
        self.extensions.add(extension.lower())

    def remove_extension(self, extension: str) -> None:
        """Remove a file extension from scanning."""
        if not extension.startswith("."):
            extension = "." + extension
        self.extensions.discard(extension.lower())

    def add_ignore_pattern(self, pattern: str) -> None:
        """Add a new ignore pattern."""
        self.ignore_patterns.add(pattern)
        try:
            regex_pattern = fnmatch.translate(pattern)
            self._compiled_patterns.append(re.compile(regex_pattern))
        except re.error as e:
            self.log_warning(f"Invalid ignore pattern '{pattern}': {e}")

    def get_scan_statistics(self) -> dict:
        """Get current scanner configuration statistics."""
        return {
            "extensions": list(self.extensions),
            "ignore_patterns": list(self.ignore_patterns),
            "max_file_size_mb": self.max_file_size_bytes / 1024 / 1024,
            "follow_symlinks": self.follow_symlinks,
        }
