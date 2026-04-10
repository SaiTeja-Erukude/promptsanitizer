from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class DataClass(str, Enum):
    OPENAI_KEY = "openai_key"
    ANTHROPIC_KEY = "anthropic_key"
    GOOGLE_AI_KEY = "google_ai_key"
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    STRIPE_KEY = "stripe_key"
    TWILIO_TOKEN = "twilio_token"
    SENDGRID_KEY = "sendgrid_key"
    GENERIC_API_KEY = "generic_api_key"
    PRIVATE_KEY = "private_key"
    JWT_TOKEN = "jwt_token"
    CONNECTION_STRING = "connection_string"
    PASSWORD = "password"
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceTag(str, Enum):
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"


@dataclass
class SecretPattern:
    name: str
    data_class: DataClass
    regex: re.Pattern  # type: ignore[type-arg]
    severity: Severity
    compliance_tags: list[ComplianceTag]
    placeholder: str


@dataclass
class Finding:
    data_class: DataClass
    severity: Severity
    compliance_tags: list[ComplianceTag]
    start: int
    end: int
    matched_value: str
    placeholder: str
    pattern_name: str
    direction: str = "unknown"


def _p(pattern: str) -> re.Pattern:  # type: ignore[type-arg]
    return re.compile(pattern)


BUILTIN_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="OpenAI API Key",
        data_class=DataClass.OPENAI_KEY,
        regex=_p(r"sk-(?!ant-)(?:proj-)?[a-zA-Z0-9_\-]{20,}"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:openai_key]",
    ),
    SecretPattern(
        name="Anthropic API Key",
        data_class=DataClass.ANTHROPIC_KEY,
        regex=_p(r"sk-ant-[a-zA-Z0-9_\-]{10,}"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:anthropic_key]",
    ),
    SecretPattern(
        name="Google AI API Key",
        data_class=DataClass.GOOGLE_AI_KEY,
        regex=_p(r"AIza[0-9A-Za-z\-_]{35}"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:google_ai_key]",
    ),
    SecretPattern(
        name="AWS Access Key ID",
        data_class=DataClass.AWS_ACCESS_KEY,
        regex=_p(r"AKIA[0-9A-Z]{16}"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:aws_access_key]",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        data_class=DataClass.AWS_SECRET_KEY,
        regex=_p(r"(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?secret)\s*[=:]\s*([a-zA-Z0-9/+]{40})"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:aws_secret_key]",
    ),
    SecretPattern(
        name="GitHub Classic PAT",
        data_class=DataClass.GITHUB_TOKEN,
        regex=_p(r"ghp_[a-zA-Z0-9]{36}"),
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:github_token]",
    ),
    SecretPattern(
        name="GitHub Fine-Grained PAT",
        data_class=DataClass.GITHUB_TOKEN,
        regex=_p(r"github_pat_[a-zA-Z0-9_]{82}"),
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:github_token]",
    ),
    SecretPattern(
        name="GitLab Token",
        data_class=DataClass.GITLAB_TOKEN,
        regex=_p(r"glpat-[a-zA-Z0-9\-_]{20}"),
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:gitlab_token]",
    ),
    SecretPattern(
        name="Stripe Live Secret Key",
        data_class=DataClass.STRIPE_KEY,
        regex=_p(r"sk_live_[0-9a-zA-Z]{24,}"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2, ComplianceTag.PCI_DSS],
        placeholder="[REDACTED:stripe_key]",
    ),
    SecretPattern(
        name="Stripe Test Secret Key",
        data_class=DataClass.STRIPE_KEY,
        regex=_p(r"sk_test_[0-9a-zA-Z]{24,}"),
        severity=Severity.MEDIUM,
        compliance_tags=[ComplianceTag.SOC2, ComplianceTag.PCI_DSS],
        placeholder="[REDACTED:stripe_key]",
    ),
    SecretPattern(
        name="SendGrid API Key",
        data_class=DataClass.SENDGRID_KEY,
        regex=_p(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:sendgrid_key]",
    ),
    SecretPattern(
        name="RSA/EC/OpenSSH Private Key Header",
        data_class=DataClass.PRIVATE_KEY,
        regex=_p(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2, ComplianceTag.GDPR],
        placeholder="[REDACTED:private_key]",
    ),
    SecretPattern(
        name="JWT Token",
        data_class=DataClass.JWT_TOKEN,
        regex=_p(r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2, ComplianceTag.GDPR],
        placeholder="[REDACTED:jwt_token]",
    ),
    SecretPattern(
        name="Database Connection String",
        data_class=DataClass.CONNECTION_STRING,
        regex=_p(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlite)\+?[a-z]*://[^:\s]+:[^@\s]+@[^\s'\"<>]+"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.SOC2, ComplianceTag.GDPR],
        placeholder="[REDACTED:connection_string]",
    ),
    SecretPattern(
        name="Password in Assignment",
        data_class=DataClass.PASSWORD,
        regex=_p(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?"),
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2, ComplianceTag.GDPR, ComplianceTag.HIPAA],
        placeholder="[REDACTED:password]",
    ),
    SecretPattern(
        name="Generic API Key",
        data_class=DataClass.GENERIC_API_KEY,
        regex=_p(r"(?:api[_\-\s]?key|api[_\-\s]?token|api[_\-\s]?secret)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"),
        severity=Severity.HIGH,
        compliance_tags=[ComplianceTag.SOC2],
        placeholder="[REDACTED:api_key]",
    ),
    SecretPattern(
        name="Email Address",
        data_class=DataClass.EMAIL,
        regex=_p(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        severity=Severity.MEDIUM,
        compliance_tags=[ComplianceTag.GDPR, ComplianceTag.HIPAA, ComplianceTag.SOC2],
        placeholder="[REDACTED:email]",
    ),
    SecretPattern(
        name="US Social Security Number",
        data_class=DataClass.SSN,
        regex=_p(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.HIPAA, ComplianceTag.GDPR, ComplianceTag.SOC2],
        placeholder="[REDACTED:ssn]",
    ),
    SecretPattern(
        name="US Phone Number",
        data_class=DataClass.PHONE,
        regex=_p(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
        severity=Severity.MEDIUM,
        compliance_tags=[ComplianceTag.HIPAA, ComplianceTag.GDPR],
        placeholder="[REDACTED:phone]",
    ),
    SecretPattern(
        name="Credit Card Number",
        data_class=DataClass.CREDIT_CARD,
        regex=_p(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
            r"3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|"
            r"6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
        severity=Severity.CRITICAL,
        compliance_tags=[ComplianceTag.PCI_DSS, ComplianceTag.GDPR, ComplianceTag.SOC2],
        placeholder="[REDACTED:credit_card]",
    ),
    SecretPattern(
        name="IPv4 Address",
        data_class=DataClass.IP_ADDRESS,
        regex=_p(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        severity=Severity.LOW,
        compliance_tags=[ComplianceTag.GDPR, ComplianceTag.HIPAA],
        placeholder="[REDACTED:ip_address]",
    ),
]
