from __future__ import annotations

from .patterns import Finding


class Redactor:
    def redact(self, text: str, findings: list[Finding]) -> str:
        """Replace each finding span with its placeholder. Findings must be sorted by start."""
        if not findings:
            return text
        parts: list[str] = []
        last_end = 0
        for finding in findings:
            parts.append(text[last_end : finding.start])
            parts.append(finding.placeholder)
            last_end = finding.end
        parts.append(text[last_end:])
        return "".join(parts)
