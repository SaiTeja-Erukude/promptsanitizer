from __future__ import annotations

from enum import Enum

from .patterns import DataClass, Finding


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class Direction(str, Enum):
    INBOUND = "inbound"    # text sent TO the LLM
    OUTBOUND = "outbound"  # text received FROM the LLM
    BOTH = "both"


class BlockedError(Exception):
    """Raised when a BLOCK policy is triggered."""

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        classes = sorted({f.data_class.value for f in findings})
        super().__init__(f"Blocked: detected {', '.join(classes)} in text")


_CREDENTIAL_CLASSES = {
    DataClass.OPENAI_KEY,
    DataClass.ANTHROPIC_KEY,
    DataClass.GOOGLE_AI_KEY,
    DataClass.AWS_ACCESS_KEY,
    DataClass.AWS_SECRET_KEY,
    DataClass.GITHUB_TOKEN,
    DataClass.GITLAB_TOKEN,
    DataClass.STRIPE_KEY,
    DataClass.PRIVATE_KEY,
    DataClass.JWT_TOKEN,
    DataClass.CONNECTION_STRING,
    DataClass.PASSWORD,
    DataClass.SENDGRID_KEY,
}


class Policy:
    def __init__(
        self,
        rules: dict[DataClass, Action] | None = None,
        default_action: Action = Action.REDACT,
        direction_overrides: dict[Direction, dict[DataClass, Action]] | None = None,
    ) -> None:
        self._rules: dict[DataClass, Action] = rules or {}
        self._default = default_action
        self._direction_overrides: dict[Direction, dict[DataClass, Action]] = direction_overrides or {}

    def evaluate(self, finding: Finding, direction: Direction) -> Action:
        dir_rules = self._direction_overrides.get(direction, {})
        if finding.data_class in dir_rules:
            return dir_rules[finding.data_class]
        if finding.data_class in self._rules:
            return self._rules[finding.data_class]
        return self._default

    @classmethod
    def default(cls) -> "Policy":
        """Redact all findings."""
        return cls(default_action=Action.REDACT)

    @classmethod
    def strict(cls) -> "Policy":
        """Block on any credential; redact PII."""
        return cls(
            rules={dc: Action.BLOCK for dc in _CREDENTIAL_CLASSES},
            default_action=Action.REDACT,
        )

    @classmethod
    def audit(cls) -> "Policy":
        """Allow everything through; only record findings."""
        return cls(default_action=Action.ALLOW)

    @classmethod
    def custom(cls, rules: dict[DataClass, Action], default: Action = Action.REDACT) -> "Policy":
        return cls(rules=rules, default_action=default)
