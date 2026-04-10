from __future__ import annotations

from .patterns import Finding, SecretPattern, BUILTIN_PATTERNS


def _deoverlap(findings: list[Finding]) -> list[Finding]:
    """Remove overlapping findings, preferring the earlier-starting and longer match."""
    sorted_findings = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    result: list[Finding] = []
    last_end = -1
    for f in sorted_findings:
        if f.start >= last_end:
            result.append(f)
            last_end = f.end
    return result


class Scanner:
    def __init__(self, patterns: list[SecretPattern] | None = None) -> None:
        self._patterns: list[SecretPattern] = list(patterns) if patterns is not None else list(BUILTIN_PATTERNS)

    def add_pattern(self, pattern: SecretPattern) -> None:
        self._patterns.append(pattern)

    def scan(self, text: str, direction: str = "unknown") -> list[Finding]:
        """Return de-overlapped findings sorted by start position."""
        raw: list[Finding] = []
        for pattern in self._patterns:
            for match in pattern.regex.finditer(text):
                raw.append(
                    Finding(
                        data_class=pattern.data_class,
                        severity=pattern.severity,
                        compliance_tags=list(pattern.compliance_tags),
                        start=match.start(),
                        end=match.end(),
                        matched_value=match.group(0),
                        placeholder=pattern.placeholder,
                        pattern_name=pattern.name,
                        direction=direction,
                    )
                )
        return _deoverlap(raw)
