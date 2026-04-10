from __future__ import annotations

import pytest

from promptsanitizer import Redactor, Scanner, DataClass


def redact(text: str) -> str:
    scanner = Scanner()
    findings = scanner.scan(text)
    return Redactor().redact(text, findings)


class TestRedactor:
    def test_single_redaction(self):
        result = redact("my key is sk-abcdefghijklmnopqrstuvwxyz123456")
        assert "[REDACTED:openai_key]" in result
        assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in result

    def test_multiple_redactions(self):
        text = "key sk-abcdefghijklmnopqrstuvwxyz123456 and email user@test.com"
        result = redact(text)
        assert "[REDACTED:openai_key]" in result
        assert "[REDACTED:email]" in result
        assert "sk-abcdef" not in result
        assert "user@test.com" not in result

    def test_text_outside_matches_preserved(self):
        text = "Hello, user@example.com — welcome!"
        result = redact(text)
        assert result.startswith("Hello, ")
        assert result.endswith("— welcome!")

    def test_no_findings_returns_original(self):
        text = "No secrets here, just plain text."
        assert redact(text) == text

    def test_placeholder_format(self):
        text = "email: alice@corp.com"
        result = redact(text)
        assert result == "email: [REDACTED:email]"

    def test_redact_called_directly(self):
        from promptsanitizer.patterns import Finding, DataClass, Severity, ComplianceTag

        finding = Finding(
            data_class=DataClass.EMAIL,
            severity=Severity.MEDIUM,
            compliance_tags=[ComplianceTag.GDPR],
            start=7,
            end=22,
            matched_value="alice@corp.com",
            placeholder="[REDACTED:email]",
            pattern_name="Email Address",
        )
        result = Redactor().redact("email: alice@corp.com", [finding])
        assert result == "email: [REDACTED:email]"

    def test_adjacent_findings(self):
        """Two findings back-to-back with no gap."""
        text = "4111111111111111user@test.com"
        result = redact(text)
        assert "4111111111111111" not in result
        assert "user@test.com" not in result
