"""
promptguard — Secrets Firewall for AI Pipelines
================================================

Scan, redact, or block credentials and PII before they reach (or leave) an LLM.

Quick start::

    from llm_promptguard import Firewall, Policy

    fw = Firewall()
    safe = fw.clean("My OpenAI key is sk-abc123xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    # → "My OpenAI key is [REDACTED:openai_key]"

    fw = Firewall(policy=Policy.strict())
    # raises BlockedError on any credential

    report = fw.report()
    print(report.summary())
"""

from .firewall import Firewall
from .policies import Action, BlockedError, Direction, Policy
from .patterns import (
    BUILTIN_PATTERNS,
    ComplianceTag,
    DataClass,
    Finding,
    SecretPattern,
    Severity,
)
from .scanner import Scanner
from .redactor import Redactor
from .compliance.reporter import ComplianceReport, generate_report

__all__ = [
    # Primary API
    "Firewall",
    "Policy",
    "Action",
    "Direction",
    "BlockedError",
    # Patterns & findings
    "DataClass",
    "Severity",
    "ComplianceTag",
    "SecretPattern",
    "Finding",
    "BUILTIN_PATTERNS",
    # Low-level
    "Scanner",
    "Redactor",
    # Compliance
    "ComplianceReport",
    "generate_report",
]

__version__ = "1.0.0"
