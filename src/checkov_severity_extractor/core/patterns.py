"""
Pattern matching engine for extracting Checkov IDs and severities.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..models.checkov import CheckovId, CheckovMatch, CheckovPattern
from ..models.severity import SeverityLevel
from ..utils.exceptions import PatternMatchError
from ..utils.logging import LoggerMixin


@dataclass
class MatchResult:
    """Result of pattern matching operation."""

    checkov_matches: list[CheckovMatch]
    severity_matches: list[str]
    confidence_score: float
    processing_time_ms: float


class PatternMatcher(ABC, LoggerMixin):
    """Abstract base class for pattern matching."""

    @abstractmethod
    async def find_checkov_ids(
        self, content: str, file_path: str = ""
    ) -> list[CheckovMatch]:
        """Find Checkov IDs in content."""
        pass

    @abstractmethod
    async def find_severities(self, content: str, file_path: str = "") -> list[str]:
        """Find severity levels in content."""
        pass

    @abstractmethod
    async def extract_mappings(self, content: str, file_path: str = "") -> MatchResult:
        """Extract both Checkov IDs and severities from content."""
        pass


class RegexPatternMatcher(PatternMatcher):
    """Regex-based pattern matching implementation."""

    def __init__(self):
        """Initialise with default patterns."""
        self.checkov_patterns: list[CheckovPattern] = []
        self.severity_patterns: list[CheckovPattern] = []
        self._compiled_checkov_patterns: list[re.Pattern] = []
        self._compiled_severity_patterns: list[re.Pattern] = []

        # Load default patterns
        self._load_default_patterns()

    def _load_default_patterns(self) -> None:
        """Load default extraction patterns."""
        # Checkov ID patterns (ordered by priority)
        default_checkov_patterns = [
            CheckovPattern(
                name="github_link_with_checkov_id",
                pattern=r"\|Checkov ID\s*\n\s*\|\s*https?://.*?\[([A-Z0-9_]+)\]",
                priority=7,
                description="GitHub link with Checkov ID in square brackets",
            ),
            CheckovPattern(
                name="checkov_multiline_table",
                pattern=r"\|Checkov ID\s*\n\s*\|\s*([A-Z0-9_]+)",
                priority=6,
                description="Multi-line table format (SAST policies)",
            ),
            CheckovPattern(
                name="standard_table_link",
                pattern=r"\|Checkov ID\s*\n\s*\|\s*.*?\[([A-Z0-9_]+)\]",
                priority=5,
                description="Standard AsciiDoc table format with link",
            ),
            CheckovPattern(
                name="simple_table_format",
                pattern=r"\|Checkov ID\s*\|\s*([A-Z0-9_]+)",
                priority=4,
                description="Simple table format without link",
            ),
            CheckovPattern(
                name="checkov_field_multiline",
                pattern=r"Checkov ID\s*:?\s*\n\s*([A-Z0-9_]+)",
                priority=3,
                description="Checkov ID field on separate line",
            ),
            CheckovPattern(
                name="checkov_field_inline",
                pattern=r"Checkov ID\s*:?\s*([A-Z0-9_]+)",
                priority=2,
                description="Inline Checkov ID field",
            ),
            CheckovPattern(
                name="bracketed_id_generic",
                pattern=r"\[([A-Z0-9_]+)\]",
                priority=1,
                description="Any bracketed ID (lowest priority)",
            ),
        ]

        # Severity patterns
        default_severity_patterns = [
            CheckovPattern(
                name="severity_table_multiline",
                pattern=r"\|Severity\s*\n\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)",
                priority=5,
                description="Severity in multiline table format",
            ),
            CheckovPattern(
                name="severity_table_simple",
                pattern=r"\|Severity\s*\|\s*([A-Z]+)",
                priority=4,
                description="Severity in simple table format",
            ),
            CheckovPattern(
                name="severity_field_multiline",
                pattern=r"Severity\s*:?\s*\n\s*([A-Z]+)",
                priority=3,
                description="Severity field on separate line",
            ),
            CheckovPattern(
                name="severity_field_inline",
                pattern=r"Severity\s*:?\s*([A-Z]+)",
                priority=2,
                description="Inline severity field",
            ),
            CheckovPattern(
                name="severity_generic",
                pattern=r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b",
                priority=1,
                description="Generic severity level detection",
            ),
        ]

        self.load_patterns(default_checkov_patterns + default_severity_patterns)

    def load_patterns(self, patterns: list[CheckovPattern]) -> None:
        """Load and compile patterns."""
        # Separate Checkov and severity patterns
        checkov_patterns = []
        severity_patterns = []

        for pattern in patterns:
            if any(
                keyword in pattern.name.lower()
                for keyword in ["checkov", "id", "bracketed"]
            ):
                checkov_patterns.append(pattern)
            elif any(keyword in pattern.name.lower() for keyword in ["severity"]):
                severity_patterns.append(pattern)

        # Sort by priority (highest first)
        self.checkov_patterns = sorted(
            checkov_patterns, key=lambda p: p.priority, reverse=True
        )
        self.severity_patterns = sorted(
            severity_patterns, key=lambda p: p.priority, reverse=True
        )

        # Compile patterns
        self._compiled_checkov_patterns = [p.compile() for p in self.checkov_patterns]
        self._compiled_severity_patterns = [p.compile() for p in self.severity_patterns]

        self.logger.info(
            "Patterns loaded",
            checkov_patterns=len(self.checkov_patterns),
            severity_patterns=len(self.severity_patterns),
        )

    async def find_checkov_ids(
        self, content: str, file_path: str = ""
    ) -> list[CheckovMatch]:
        """Find Checkov IDs using compiled patterns."""
        matches = []

        for _i, (pattern, compiled_pattern) in enumerate(
            zip(self.checkov_patterns, self._compiled_checkov_patterns)
        ):
            try:
                for match in compiled_pattern.finditer(content):
                    # Extract the captured group
                    checkov_id_candidate = match.group(1)

                    # Basic validation - ensure it looks like a Checkov ID
                    if self._is_valid_checkov_id_format(checkov_id_candidate):
                        # Calculate confidence based on pattern priority and context
                        confidence = self._calculate_confidence(
                            pattern, match, content, checkov_id_candidate
                        )

                        # Extract context around the match
                        context = self._extract_context(
                            content, match.start(), match.end()
                        )

                        checkov_match = CheckovMatch(
                            checkov_id=checkov_id_candidate,
                            confidence=confidence,
                            start_position=match.start(),
                            end_position=match.end(),
                            context=context,
                            pattern_name=pattern.name,
                        )
                        matches.append(checkov_match)

                        # If we found a high-confidence match, we can stop looking
                        if confidence > 0.8:
                            break

            except re.error as e:
                self.log_warning(
                    "Pattern matching error",
                    pattern_name=pattern.name,
                    error=str(e),
                    file_path=file_path,
                )

        # Sort by confidence and remove duplicates
        matches = self._deduplicate_matches(matches)
        return sorted(matches, key=lambda m: m.confidence, reverse=True)

    async def find_severities(self, content: str, file_path: str = "") -> list[str]:
        """Find severity levels using compiled patterns."""
        severities = []

        for pattern, compiled_pattern in zip(
            self.severity_patterns, self._compiled_severity_patterns
        ):
            try:
                for match in compiled_pattern.finditer(content):
                    severity_candidate = match.group(1).upper()

                    # Validate severity
                    if SeverityLevel.from_string(severity_candidate):
                        severities.append(severity_candidate)

                        # High-priority patterns should take precedence
                        if pattern.priority >= 4:
                            break

            except re.error as e:
                self.log_warning(
                    "Severity pattern error",
                    pattern_name=pattern.name,
                    error=str(e),
                    file_path=file_path,
                )

        # Remove duplicates while preserving order
        return list(dict.fromkeys(severities))

    async def extract_mappings(self, content: str, file_path: str = "") -> MatchResult:
        """Extract both Checkov IDs and severities with timing."""
        import time

        start_time = time.perf_counter()

        try:
            # Find Checkov IDs and severities
            checkov_matches = await self.find_checkov_ids(content, file_path)
            severity_matches = await self.find_severities(content, file_path)

            # Calculate overall confidence
            confidence_score = self._calculate_overall_confidence(
                checkov_matches, severity_matches, content
            )

            processing_time = (time.perf_counter() - start_time) * 1000  # ms

            return MatchResult(
                checkov_matches=checkov_matches,
                severity_matches=severity_matches,
                confidence_score=confidence_score,
                processing_time_ms=processing_time,
            )

        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000
            raise PatternMatchError(
                f"Pattern matching failed: {str(e)}", content_snippet=content[:200]
            ) from e

    def _is_valid_checkov_id_format(self, candidate: str) -> bool:
        """Check if candidate looks like a valid Checkov ID."""
        # More flexible validation for table-based extraction
        # Accept any reasonable ID format found in tables, not just hardcoded prefixes

        # Basic format checks
        if not candidate or len(candidate) < 3:
            return False

        # Remove common noise characters
        candidate = candidate.strip().upper()

        # Accept common Checkov ID patterns - much more flexible
        flexible_patterns = [
            # Standard patterns: PREFIX_PROVIDER_NUMBER
            re.compile(
                r"^[A-Z][A-Z0-9]*_[A-Z][A-Z0-9]*_\d+$"
            ),  # CKV_AWS_123, CKV3_SAST_96
            # Standard patterns: PREFIX_PROVIDER_ALPHANUMERIC
            re.compile(r"^[A-Z][A-Z0-9]*_[A-Z][A-Z0-9]*_[A-Z0-9_]+$"),  # CKV_OPENAPI_20
            # BC patterns
            re.compile(r"^BC_[A-Z][A-Z0-9]*_\d+$"),  # BC_LIC_3
            # Future-proof: any reasonable ID with underscores
            re.compile(
                r"^[A-Z][A-Z0-9]+_[A-Z][A-Z0-9]+_[A-Z0-9_]+$"
            ),  # Catch future formats
        ]

        # If found via CheckovId model validation, definitely accept
        if CheckovId.from_string(candidate) is not None:
            return True

        # Otherwise, use flexible patterns for table-based extraction
        return any(pattern.match(candidate) for pattern in flexible_patterns)

    def _calculate_confidence(
        self, pattern: CheckovPattern, match: re.Match, content: str, checkov_id: str
    ) -> float:
        """Calculate confidence score for a match."""
        base_confidence = pattern.priority / 5.0  # Normalize to 0-1

        # Boost confidence for valid Checkov ID format
        if self._is_valid_checkov_id_format(checkov_id):
            base_confidence *= 1.2

        # Boost confidence if found in a table context
        context = content[max(0, match.start() - 100) : match.end() + 100]
        if "|" in context or "table" in context.lower():
            base_confidence *= 1.1

        # Reduce confidence for very common patterns
        if pattern.name == "bracketed_id_generic":
            base_confidence *= 0.7

        return min(1.0, base_confidence)

    def _extract_context(
        self, content: str, start: int, end: int, window: int = 50
    ) -> str:
        """Extract context around a match."""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        context = content[context_start:context_end]

        # Clean up context
        context = " ".join(context.split())  # Normalize whitespace
        if len(context) > 100:
            context = context[:100] + "..."

        return context

    def _deduplicate_matches(self, matches: list[CheckovMatch]) -> list[CheckovMatch]:
        """Remove duplicate matches, keeping the highest confidence."""
        seen_ids = {}
        for match in matches:
            if match.checkov_id not in seen_ids:
                seen_ids[match.checkov_id] = match
            elif match.confidence > seen_ids[match.checkov_id].confidence:
                seen_ids[match.checkov_id] = match

        return list(seen_ids.values())

    def _calculate_overall_confidence(
        self,
        checkov_matches: list[CheckovMatch],
        severity_matches: list[str],
        content: str,
    ) -> float:
        """Calculate overall confidence for the extraction."""
        if not checkov_matches or not severity_matches:
            return 0.0

        # Base confidence from best Checkov match
        best_checkov_confidence = max(m.confidence for m in checkov_matches)

        # Boost if we have exactly one of each
        if len(checkov_matches) == 1 and len(severity_matches) == 1:
            return min(1.0, best_checkov_confidence * 1.2)

        # Reduce if we have multiple matches (ambiguous)
        ambiguity_penalty = 1.0 - (len(checkov_matches) - 1) * 0.1
        ambiguity_penalty *= 1.0 - (len(severity_matches) - 1) * 0.1

        return max(0.0, best_checkov_confidence * ambiguity_penalty)
