from __future__ import annotations

import json
import sys

import click

from .firewall import Firewall
from .policies import Direction, Policy


@click.group()
@click.version_option()
def cli() -> None:
    """promptguard — Secrets Firewall for AI Pipelines."""


@cli.command()
@click.argument("text", required=False)
@click.option("-f", "--file", "filepath", type=click.Path(exists=True), help="File to scan.")
@click.option(
    "--direction",
    type=click.Choice(["inbound", "outbound"]),
    default="inbound",
    show_default=True,
    help="Scanning direction.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
)
def scan(text: str | None, filepath: str | None, direction: str, fmt: str) -> None:
    """Scan TEXT or a file for secrets and PII."""
    content = _read_input(text, filepath)
    fw = Firewall(policy=Policy.audit())
    findings = fw.scan(content, Direction(direction))

    if fmt == "json":
        click.echo(
            json.dumps(
                [
                    {
                        "pattern": f.pattern_name,
                        "data_class": f.data_class.value,
                        "severity": f.severity.value,
                        "compliance_tags": [t.value for t in f.compliance_tags],
                        "start": f.start,
                        "end": f.end,
                    }
                    for f in findings
                ],
                indent=2,
            )
        )
        return

    if not findings:
        click.echo("No findings.")
        return

    for f in findings:
        tags = ", ".join(t.value for t in f.compliance_tags)
        click.echo(
            f"[{f.severity.value.upper():<8}] {f.pattern_name:<35} "
            f"pos {f.start}:{f.end}  ({tags})"
        )
    click.echo(f"\n{len(findings)} finding(s) total.")


@cli.command()
@click.argument("text", required=False)
@click.option("-f", "--file", "filepath", type=click.Path(exists=True), help="File to clean.")
@click.option(
    "--direction",
    type=click.Choice(["inbound", "outbound"]),
    default="inbound",
    show_default=True,
)
@click.option(
    "--policy",
    type=click.Choice(["default", "strict", "audit"]),
    default="default",
    show_default=True,
    help="Redaction policy to apply.",
)
def clean(text: str | None, filepath: str | None, direction: str, policy: str) -> None:
    """Redact secrets from TEXT or a file and print the result."""
    content = _read_input(text, filepath)
    policy_map = {"default": Policy.default(), "strict": Policy.strict(), "audit": Policy.audit()}
    fw = Firewall(policy=policy_map[policy])

    from .policies import BlockedError

    try:
        result = fw.clean(content, Direction(direction))
        click.echo(result)
    except BlockedError as exc:
        click.echo(f"BLOCKED: {exc}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("text", required=False)
@click.option("-f", "--file", "filepath", type=click.Path(exists=True), help="File to report on.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
)
def report(text: str | None, filepath: str | None, fmt: str) -> None:
    """Scan TEXT or a file and print a compliance report."""
    content = _read_input(text, filepath)
    fw = Firewall(policy=Policy.audit())
    fw.scan(content)
    rpt = fw.report()

    if fmt == "json":
        click.echo(rpt.to_json())
    else:
        click.echo(rpt.summary())


def _read_input(text: str | None, filepath: str | None) -> str:
    if filepath:
        with open(filepath, encoding="utf-8") as fh:
            return fh.read()
    if text:
        return text
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise click.UsageError("Provide TEXT argument, --file, or pipe content via stdin.")
