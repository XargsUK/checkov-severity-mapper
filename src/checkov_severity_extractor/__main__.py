#!/usr/bin/env python3
"""
Simple Checkov severity extractor - extracts ID to severity mappings from documentation.
"""

import argparse
import asyncio
import sys
from pathlib import Path

from .core.extractor import CheckovSeverityExtractor
from .models.config import ExtractionConfig, OutputConfig, ProcessingConfig


def main() -> None:
    """Simple main entry point."""
    parser = argparse.ArgumentParser(
        description="Extract Checkov ID to severity mappings from documentation"
    )
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=Path("docs"),
        help="Documentation directory to scan (default: docs)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("checkov-severity.json"),
        help="Output JSON file (default: checkov-severity.json)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=4,
        help="Maximum concurrent workers (default: 4)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress output messages",
    )

    args = parser.parse_args()

    # Check Python version

    # Validate paths
    if not args.docs_dir.exists():
        print(
            f"Error: Documentation directory '{args.docs_dir}' does not exist.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.docs_dir.is_dir():
        print(f"Error: '{args.docs_dir}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    # Check if output file exists
    if args.output.exists():
        response = input(
            f"Output file '{args.output}' already exists. Overwrite? (y/N): "
        )
        if response.lower() not in ["y", "yes"]:
            print("Operation cancelled.")
            sys.exit(0)

    try:
        # Create configuration
        config = ExtractionConfig(
            docs_directory=args.docs_dir,
            processing=ProcessingConfig(
                max_concurrent_files=args.max_workers,
                file_extensions=[".adoc"],
                excluded_patterns=["*index*", "*policies.adoc"],
                max_file_size_mb=10.0,
                timeout_seconds=30.0,
            ),
            output=OutputConfig(
                output_file=args.output,
                pretty_print=False,
            ),
            quiet=args.quiet,
        )

        if not args.quiet:
            print(f"Scanning: {args.docs_dir}")
            print(f"Output: {args.output}")

        # Run extraction
        extractor = CheckovSeverityExtractor()
        database = asyncio.run(extractor.extract(config))

        # Write output
        asyncio.run(extractor.write_database(database, config.output))

        if not args.quiet:
            print(f"✓ Extracted {len(database.mappings):,} mappings")
            print(f"✓ Database written to: {args.output}")

    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
