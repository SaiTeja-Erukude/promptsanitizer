from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..patterns import Finding, DataClass, Severity, ComplianceTag


@dataclass
class ComplianceReport:
    generated_at: str
    total_findings: int
    by_data_class: dict[str, int]
    by_severity: dict[str, int]
    by_compliance_tag: dict[str, int]
    by_direction: dict[str, int]

    def to_dict(self) -> dict:  # type: ignore[type-arg]
        return {
            "generated_at": self.generated_at,
            "total_findings": self.total_findings,
            "by_data_class": self.by_data_class,
            "by_severity": self.by_severity,
            "by_compliance_tag": self.by_compliance_tag,
            "by_direction": self.by_direction,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def summary(self) -> str:
        lines = [
            f"Generated : {self.generated_at}",
            f"Findings  : {self.total_findings}",
        ]

        if self.by_severity:
            lines.append("\nSeverity breakdown:")
            severity_order = [s.value for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)]
            for sev in severity_order:
                count = self.by_severity.get(sev, 0)
                if count:
                    lines.append(f"  {sev:<10} {count}")

        if self.by_data_class:
            lines.append("\nData class breakdown:")
            for k, v in sorted(self.by_data_class.items(), key=lambda x: -x[1]):
                lines.append(f"  {k:<30} {v}")

        if self.by_compliance_tag:
            lines.append("\nCompliance framework exposure:")
            tag_order = [t.value for t in (ComplianceTag.PCI_DSS, ComplianceTag.HIPAA, ComplianceTag.GDPR, ComplianceTag.SOC2)]
            for tag in tag_order:
                count = self.by_compliance_tag.get(tag, 0)
                lines.append(f"  {tag:<10} {count}")

        if self.by_direction:
            lines.append("\nDirection:")
            for k, v in sorted(self.by_direction.items()):
                lines.append(f"  {k:<10} {v}")

        return "\n".join(lines)


def generate_report(findings: list[Finding]) -> ComplianceReport:
    by_data_class: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    by_compliance_tag: dict[str, int] = defaultdict(int)
    by_direction: dict[str, int] = defaultdict(int)

    for finding in findings:
        by_data_class[finding.data_class.value] += 1
        by_severity[finding.severity.value] += 1
        for tag in finding.compliance_tags:
            by_compliance_tag[tag.value] += 1
        by_direction[finding.direction] += 1

    return ComplianceReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        total_findings=len(findings),
        by_data_class=dict(by_data_class),
        by_severity=dict(by_severity),
        by_compliance_tag=dict(by_compliance_tag),
        by_direction=dict(by_direction),
    )
