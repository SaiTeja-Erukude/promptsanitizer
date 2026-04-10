# promptsanitizer

Secrets firewall for AI pipelines — redact credentials and PII before they reach (or leave) LLMs.

## Install

```bash
pip install promptsanitizer
# with LLM middleware
pip install "promptsanitizer[openai]"
pip install "promptsanitizer[anthropic]"
pip install "promptsanitizer[all]"
```

## Quick start

```python
from promptsanitizer import Firewall

fw = Firewall()
safe = fw.clean("My key is sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx and email is dev@example.com")
print(safe)
# My key is [REDACTED:openai_key] and email is [REDACTED:email]
```

## Policies

| Policy | Behaviour |
|---|---|
| `Policy.default()` | Redact all findings (default) |
| `Policy.strict()` | Block on any credential, redact PII |
| `Policy.audit()` | Allow everything through, only record findings |
| `Policy.custom(rules)` | Per-`DataClass` action map |

```python
from promptsanitizer import Firewall, Policy, BlockedError

# Block on credentials
fw = Firewall(policy=Policy.strict())
try:
    fw.clean("token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
except BlockedError as e:
    print(e)
    # Blocked: detected github_token in text

# Audit mode — nothing redacted, everything logged
fw = Firewall(policy=Policy.audit())
out = fw.clean("SSN: 123-45-6789")
print(out)
# SSN: 123-45-6789

print(fw.findings)
# [Finding(data_class=<DataClass.SSN: 'ssn'>, severity=<Severity.CRITICAL: 'critical'>,
#          compliance_tags=[HIPAA, GDPR, SOC2], start=5, end=16,
#          matched_value='123-45-6789', placeholder='[REDACTED:ssn]', direction='inbound')]
```

## Custom patterns

```python
import re
from promptsanitizer import Firewall, SecretPattern, DataClass, Severity, ComplianceTag

pattern = SecretPattern(
    name="internal_token",
    data_class=DataClass.GENERIC_API_KEY,
    regex=re.compile(r"INTERNAL-[A-Z0-9]{16}"),
    severity=Severity.HIGH,
    compliance_tags=[ComplianceTag.SOC2],
    placeholder="[REDACTED:internal_token]",
)
fw = Firewall()
fw.add_pattern(pattern)
print(fw.clean("Use token INTERNAL-ABCDEF1234567890 for staging"))
# Use token [REDACTED:internal_token] for staging
```

## Directions

```python
from promptsanitizer import Firewall, Direction

fw = Firewall()
print(fw.clean("key sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", direction=Direction.INBOUND))
# key [REDACTED:openai_key]

print(fw.clean("token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", direction=Direction.OUTBOUND))
# token [REDACTED:github_token]

# Direction is recorded on each Finding and appears in the compliance report
print({f.direction for f in fw.findings})
# {'inbound', 'outbound'}
```

## Compliance report

```python
fw = Firewall()
fw.clean("card: 4111111111111111")
fw.clean("ssn: 123-45-6789")
print(fw.report().summary())
# Generated : 2026-04-10T21:36:30.895934+00:00
# Findings  : 2
#
# Severity breakdown:
#   critical   2
#
# Data class breakdown:
#   credit_card                    1
#   ssn                            1
#
# Compliance framework exposure:
#   pci_dss    1
#   hipaa      1
#   gdpr       2
#   soc2       2
#
# Direction:
#   inbound    2
```

## OpenAI middleware

```python
import openai
from promptsanitizer.middleware import PromptGuardOpenAI

client = PromptGuardOpenAI(openai.OpenAI())
# Prompts are automatically cleaned before sending; responses are scanned on return
```

## Anthropic middleware

```python
import anthropic
from promptsanitizer.middleware import PromptGuardAnthropic

client = PromptGuardAnthropic(anthropic.Anthropic())
```

## CLI

```bash
$ echo "My key sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | promptguard clean
My key [REDACTED:openai_key]

$ promptguard scan "email: user@corp.com"
[MEDIUM  ] Email Address                       pos 7:20  (gdpr, hipaa, soc2)

1 finding(s) total.
```

## Detected data classes

`openai_key` · `anthropic_key` · `google_ai_key` · `aws_access_key` · `aws_secret_key` · `github_token` · `gitlab_token` · `stripe_key` · `twilio_token` · `sendgrid_key` · `generic_api_key` · `private_key` · `jwt_token` · `connection_string` · `password` · `email` · `phone` · `ssn` · `credit_card` · `ip_address`

## Compliance frameworks

`HIPAA` · `GDPR` · `SOC2` · `PCI-DSS`

## Development

```bash
pip install -e ".[dev]"
pytest
```
