from __future__ import annotations

import pytest

from promptsanitizer import Action, DataClass, Direction, Policy  # noqa: F401
from promptsanitizer.patterns import Finding, Severity, ComplianceTag


def _finding(data_class: DataClass) -> Finding:
    return Finding(
        data_class=data_class,
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2],
        start=0,
        end=10,
        matched_value="secret123",
        placeholder="[REDACTED:placeholder]",
        pattern_name="Test",
        direction="inbound",
    )


class TestDefaultPolicy:
    def test_redacts_everything(self):
        policy = Policy.default()
        for dc in DataClass:
            assert policy.evaluate(_finding(dc), Direction.INBOUND) == Action.REDACT

    def test_default_action_overridable(self):
        policy = Policy(default_action=Action.ALLOW)
        assert policy.evaluate(_finding(DataClass.EMAIL), Direction.INBOUND) == Action.ALLOW


class TestStrictPolicy:
    def test_blocks_credentials(self):
        policy = Policy.strict()
        for dc in (
            DataClass.OPENAI_KEY,
            DataClass.ANTHROPIC_KEY,
            DataClass.AWS_ACCESS_KEY,
            DataClass.GITHUB_TOKEN,
            DataClass.PRIVATE_KEY,
            DataClass.CONNECTION_STRING,
            DataClass.PASSWORD,
        ):
            assert policy.evaluate(_finding(dc), Direction.INBOUND) == Action.BLOCK

    def test_redacts_pii_under_strict(self):
        policy = Policy.strict()
        assert policy.evaluate(_finding(DataClass.EMAIL), Direction.INBOUND) == Action.REDACT
        assert policy.evaluate(_finding(DataClass.SSN), Direction.INBOUND) == Action.REDACT


class TestAuditPolicy:
    def test_allows_everything(self):
        policy = Policy.audit()
        for dc in DataClass:
            assert policy.evaluate(_finding(dc), Direction.INBOUND) == Action.ALLOW


class TestCustomPolicy:
    def test_custom_rules(self):
        policy = Policy.custom(
            rules={DataClass.EMAIL: Action.BLOCK, DataClass.PHONE: Action.ALLOW},
            default=Action.REDACT,
        )
        assert policy.evaluate(_finding(DataClass.EMAIL), Direction.INBOUND) == Action.BLOCK
        assert policy.evaluate(_finding(DataClass.PHONE), Direction.INBOUND) == Action.ALLOW
        assert policy.evaluate(_finding(DataClass.SSN), Direction.INBOUND) == Action.REDACT

    def test_direction_overrides(self):
        policy = Policy(
            rules={DataClass.EMAIL: Action.REDACT},
            direction_overrides={
                Direction.OUTBOUND: {DataClass.EMAIL: Action.ALLOW}
            },
        )
        assert policy.evaluate(_finding(DataClass.EMAIL), Direction.INBOUND) == Action.REDACT
        assert policy.evaluate(_finding(DataClass.EMAIL), Direction.OUTBOUND) == Action.ALLOW
