from __future__ import annotations

from .patterns import Finding, SecretPattern
from .scanner import Scanner
from .redactor import Redactor
from .policies import Action, Direction, Policy, BlockedError


class Firewall:
    """
    Central object for scanning and cleaning text that passes through an AI pipeline.

    Usage::

        fw = Firewall()
        safe = fw.clean("My key is sk-abc123...")

        fw = Firewall(policy=Policy.strict())
        try:
            safe = fw.clean(prompt, direction=Direction.INBOUND)
        except BlockedError as e:
            ...

        report = fw.report()
        print(report.summary())
    """

    def __init__(
        self,
        policy: Policy | None = None,
        patterns: list[SecretPattern] | None = None,
    ) -> None:
        self._policy = policy or Policy.default()
        self._scanner = Scanner(patterns)
        self._redactor = Redactor()
        self._findings: list[Finding] = []

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def scan(self, text: str, direction: Direction = Direction.INBOUND) -> list[Finding]:
        """Scan without modifying text. Findings are appended to history."""
        findings = self._scanner.scan(text, direction.value)
        self._findings.extend(findings)
        return findings

    def clean(self, text: str, direction: Direction = Direction.INBOUND) -> str:
        """
        Scan text and apply policy rules.

        - REDACT → replaces the sensitive span with a placeholder token.
        - BLOCK  → raises BlockedError before any modification.
        - ALLOW  → passes text through unchanged.
        """
        findings = self._scanner.scan(text, direction.value)
        self._findings.extend(findings)

        to_redact: list[Finding] = []
        to_block: list[Finding] = []

        for finding in findings:
            action = self._policy.evaluate(finding, direction)
            if action == Action.BLOCK:
                to_block.append(finding)
            elif action == Action.REDACT:
                to_redact.append(finding)

        if to_block:
            raise BlockedError(to_block)

        return self._redactor.redact(text, to_redact)

    def add_pattern(self, pattern: SecretPattern) -> None:
        self._scanner.add_pattern(pattern)

    def reset(self) -> None:
        """Clear accumulated findings history."""
        self._findings.clear()

    def report(self) -> "ComplianceReport":  # noqa: F821
        from .compliance.reporter import generate_report

        return generate_report(self._findings)
