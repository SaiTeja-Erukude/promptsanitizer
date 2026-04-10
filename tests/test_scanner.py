from __future__ import annotations

import pytest

from llm_promptguard import DataClass, Scanner
from llm_promptguard.patterns import BUILTIN_PATTERNS, SecretPattern, Severity, ComplianceTag
import re


def scan(text: str) -> list:
    return Scanner().scan(text)


class TestCredentialPatterns:
    def test_openai_key(self):
        findings = scan("Use sk-abcdefghijklmnopqrstuvwxyz123456 in your config.")
        assert any(f.data_class == DataClass.OPENAI_KEY for f in findings)

    def test_openai_proj_key(self):
        findings = scan("key=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcd")
        assert any(f.data_class == DataClass.OPENAI_KEY for f in findings)

    def test_anthropic_key(self):
        findings = scan("export ANTHROPIC_KEY=sk-ant-api03-abcdefghijklmnop")
        assert any(f.data_class == DataClass.ANTHROPIC_KEY for f in findings)

    def test_aws_access_key(self):
        findings = scan("Access key: AKIAIOSFODNN7EXAMPLE")
        assert any(f.data_class == DataClass.AWS_ACCESS_KEY for f in findings)

    def test_github_pat(self):
        findings = scan("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        assert any(f.data_class == DataClass.GITHUB_TOKEN for f in findings)

    def test_stripe_live_key(self):
        findings = scan("STRIPE=" + "sk_live_" + "abcdefghijklmnopqrstuvwx")
        assert any(f.data_class == DataClass.STRIPE_KEY for f in findings)

    def test_stripe_test_key(self):
        findings = scan("STRIPE=" + "sk_test_" + "abcdefghijklmnopqrstuvwx")
        assert any(f.data_class == DataClass.STRIPE_KEY for f in findings)

    def test_private_key_header(self):
        findings = scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEo...")
        assert any(f.data_class == DataClass.PRIVATE_KEY for f in findings)

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = scan(jwt)
        assert any(f.data_class == DataClass.JWT_TOKEN for f in findings)

    def test_db_connection_string(self):
        findings = scan("postgres://user:s3cr3t@db.host.com:5432/mydb")
        assert any(f.data_class == DataClass.CONNECTION_STRING for f in findings)

    def test_password_assignment(self):
        findings = scan("password=SuperSecret123!")
        assert any(f.data_class == DataClass.PASSWORD for f in findings)

    def test_generic_api_key(self):
        findings = scan("api_key=abcdefghijklmnopqrstuvwxyz12345")
        assert any(f.data_class == DataClass.GENERIC_API_KEY for f in findings)


class TestPIIPatterns:
    def test_email(self):
        findings = scan("Contact alice@example.com for support.")
        assert any(f.data_class == DataClass.EMAIL for f in findings)

    def test_ssn(self):
        findings = scan("SSN: 123-45-6789")
        assert any(f.data_class == DataClass.SSN for f in findings)

    def test_phone(self):
        findings = scan("Call us at 555-867-5309.")
        assert any(f.data_class == DataClass.PHONE for f in findings)

    def test_credit_card_visa(self):
        findings = scan("Card: 4111111111111111")
        assert any(f.data_class == DataClass.CREDIT_CARD for f in findings)

    def test_ipv4(self):
        findings = scan("Server at 192.168.0.1")
        assert any(f.data_class == DataClass.IP_ADDRESS for f in findings)


class TestScannerBehavior:
    def test_no_findings_clean_text(self):
        assert scan("Hello, world! This is a clean message.") == []

    def test_direction_stored_in_finding(self):
        s = Scanner()
        findings = s.scan("my email is foo@bar.com", direction="inbound")
        assert all(f.direction == "inbound" for f in findings)

    def test_deoverlap_keeps_longer_match(self):
        """A connection string contains a password; only the conn string should be found."""
        text = "postgres://alice:hunter2@localhost/db"
        findings = scan(text)
        # Should find connection string, not overlap with password
        classes = {f.data_class for f in findings}
        assert DataClass.CONNECTION_STRING in classes
        # password should not create a separate overlapping finding
        for f in findings:
            if f.data_class == DataClass.PASSWORD:
                # if it is found, it must not overlap with the conn string finding
                conn = next(x for x in findings if x.data_class == DataClass.CONNECTION_STRING)
                assert f.end <= conn.start or f.start >= conn.end

    def test_multiple_secrets_in_text(self):
        text = "key: sk-abcdefghijklmnopqrstuvwxyz123456, email: user@test.com"
        findings = scan(text)
        classes = {f.data_class for f in findings}
        assert DataClass.OPENAI_KEY in classes
        assert DataClass.EMAIL in classes

    def test_custom_pattern(self):
        custom = SecretPattern(
            name="Internal Token",
            data_class=DataClass.GENERIC_API_KEY,
            regex=re.compile(r"INT-[A-Z0-9]{16}"),
            severity=Severity.HIGH,
            compliance_tags=[ComplianceTag.SOC2],
            placeholder="[REDACTED:api_key]",
        )
        s = Scanner(patterns=[custom])
        findings = s.scan("token: INT-ABCDEFGHIJ123456")
        assert len(findings) == 1
        assert findings[0].pattern_name == "Internal Token"

    def test_add_pattern(self):
        custom = SecretPattern(
            name="Custom Secret",
            data_class=DataClass.GENERIC_API_KEY,
            regex=re.compile(r"MY-SECRET-[0-9]{8}"),
            severity=Severity.HIGH,
            compliance_tags=[],
            placeholder="[REDACTED:api_key]",
        )
        s = Scanner()
        s.add_pattern(custom)
        findings = s.scan("value: MY-SECRET-12345678")
        assert any(f.pattern_name == "Custom Secret" for f in findings)
