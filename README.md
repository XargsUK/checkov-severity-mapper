# Checkov Severity Extractor

Automated extraction of Checkov ID to severity mappings from Prisma Cloud documentation for VSCode extension integration.

## Overview

This repository contains:

- A Python package that extracts Checkov severity mappings from documentation
- A GitHub Actions workflow that automates the extraction process

The system automatically clones the [Prisma Cloud docs repository](https://github.com/hlxsites/prisma-cloud-docs), extracts severity mappings from policy documentation, and publishes them as GitHub releases for easy consumption by VSCode extensions.

## Quick Start

### Manual Extraction

```bash
# Install dependencies
uv sync

# Extract mappings from local docs
uv run python -m checkov_severity_extractor \
  --docs-dir path/to/docs/en/enterprise-edition/policy-reference \
  --output checkov_severity_mappings.json \
  --max-workers 2 \
  --quiet
```

## Workflow Details

The GitHub Action:

1. **Clones External Docs** - Shallow clone of https://github.com/hlxsites/prisma-cloud-docs
2. **Extracts Mappings** - Runs the Python extractor on policy documentation
3. **Generates Metadata** - Creates version info, timestamps, and file hashes
4. **Creates Release** - Publishes versioned JSON files to GitHub Releases
