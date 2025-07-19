"""
Input/Output modules for file operations and data persistence.

This package handles all file I/O operations including scanning, reading,
and writing various output formats.
"""

from .content_reader import ContentReader, ReadResult
from .file_scanner import FileScanner, ScanResult
from .json_writer import JsonWriteOptions, JsonWriter

__all__ = [
    # File scanning
    "FileScanner",
    "ScanResult",
    # Content reading
    "ContentReader",
    "ReadResult",
    # JSON output
    "JsonWriter",
    "JsonWriteOptions",
]
