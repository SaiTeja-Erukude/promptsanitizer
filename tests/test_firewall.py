from __future__ import annotations

import re

import pytest

from promptsanitizer import (
    BlockedError,
    DataClass,
    Direction,
    Firewall,
    Policy,
    SecretPattern,
    Severity,
    ComplianceTag,
)


class TestFirewallClean:
    def test_redacts_openai_key(self, fw: Firewall):
        result = fw.clean("key: sk-abcdefghijklmnopqrstuvwxyz123456")
        assert "[REDACTED:openai_key]" in result
        assert "sk-abcdef" not in result

    def test_redacts_email(self, fw: Firewall):
        result = fw.clean("Contact me at bob@example.com please.")
        assert "[REDACTED:email]" in result

    def test_clean_text_unchanged(self, fw: Firewall):
        text = "This text has no secrets."
        assert fw.clean(text) == text

    def test_strict_policy_blocks_on_credential(self, strict_fw: Firewall):
        with pytest.raises(BlockedError) as exc_info:
            strict_fw.clean("key: sk-abcdefghijklmnopqrstuvwxyz123456")
        assert DataClass.OPENAI_KEY in {f.data_class for f in exc_info.value.findings}

    def test_audit_policy_allows_all(self, audit_fw: Firewall):
        text = "key: sk-abcdefghijklmnopqrstuvwxyz123456, email: a@b.com"
        result = audit_fw.clean(text)
        assert result == text

    def test_direction_stored(self, fw: Firewall):
        fw.clean("ip: 10.0.0.1", direction=Direction.OUTBOUND)
        assert all(f.direction == "outbound" for f in fw.findings)

    def test_multiple_findings_in_one_call(self, fw: Firewall):
        text = "key sk-abcdefghijklmnopqrstuvwxyz123456 email user@test.com card 4111111111111111"
        result = fw.clean(text)
        assert "[REDACTED:openai_key]" in result
        assert "[REDACTED:email]" in result
        assert "[REDACTED:credit_card]" in result


class TestFirewallScan:
    def test_scan_does_not_modify_text(self, fw: Firewall):
        text = "key: sk-abcdefghijklmnopqrstuvwxyz123456"
        findings = fw.scan(text)
        assert findings[0].data_class == DataClass.OPENAI_KEY

    def test_scan_accumulates_findings(self, fw: Firewall):
        fw.scan("email: a@b.com")
        fw.scan("email: c@d.com")
        assert len(fw.findings) == 2

    def test_reset_clears_findings(self, fw: Firewall):
        fw.scan("email: a@b.com")
        fw.reset()
        assert fw.findings == []


class TestFirewallReport:
    def test_report_counts_by_class(self, fw: Firewall):
        fw.scan("a@b.com and c@d.com")
        report = fw.report()
        assert report.by_data_class.get("email", 0) == 2

    def test_report_counts_by_severity(self, fw: Firewall):
        fw.scan("sk-abcdefghijklmnopqrstuvwxyz123456")
        report = fw.report()
        assert report.by_severity.get("critical", 0) >= 1

    def test_report_compliance_tags(self, fw: Firewall):
        fw.scan("4111111111111111")
        report = fw.report()
        assert report.by_compliance_tag.get("pci_dss", 0) >= 1

    def test_report_summary_output(self, fw: Firewall):
        fw.scan("a@b.com sk-abcdefghijklmnopqrstuvwxyz123456")
        summary = fw.report().summary()
        assert "Findings" in summary
        assert "email" in summary

    def test_report_to_dict(self, fw: Firewall):
        fw.scan("a@b.com")
        d = fw.report().to_dict()
        assert "total_findings" in d
        assert "by_data_class" in d

    def test_empty_report(self, fw: Firewall):
        report = fw.report()
        assert report.total_findings == 0


class TestFirewallCustomPattern:
    def test_add_custom_pattern(self):
        custom = SecretPattern(
            name="Internal Token",
            data_class=DataClass.GENERIC_API_KEY,
            regex=re.compile(r"INT-[A-Z0-9]{8}"),
            severity=Severity.HIGH,
            compliance_tags=[ComplianceTag.SOC2],
            placeholder="[REDACTED:api_key]",
        )
        fw = Firewall()
        fw.add_pattern(custom)
        result = fw.clean("token: INT-ABCD1234")
        assert "[REDACTED:api_key]" in result
        assert "INT-ABCD1234" not in result
