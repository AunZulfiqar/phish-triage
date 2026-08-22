"""Rich terminal report.

Laid out the way an analyst reads a triage: verdict first, then the identities
that disagree, then the evidence grouped by category, then the IOCs ready to
copy. Everything that could be clicked is defanged before it is printed.
"""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ..catalog import CATEGORY_TITLES
from ..models import Report, Severity
from ..scoring import explain
from ..utils import defang

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

# Re-exported for the HTML renderer, which shares these section names.
_CATEGORY_TITLE = CATEGORY_TITLES


def _glyphs(console: Console) -> dict[str, str]:
    """Pick drawing characters the destination console can actually encode.

    The Windows legacy console defaults to cp1252, which cannot represent block
    elements or an em dash. Writing them raises UnicodeEncodeError mid-render and
    takes the whole report with it, so the charset is chosen up front rather than
    hoped for.
    """
    unicode_set = {"full": "█", "empty": "░", "dash": "—"}
    ascii_set = {"full": "#", "empty": ".", "dash": "-"}
    if console.legacy_windows:
        return ascii_set
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        "".join(unicode_set.values()).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return ascii_set
    return unicode_set


def _verdict_panel(report: Report, glyphs: dict[str, str]) -> Panel:
    bar_width = 40
    filled = round(report.score / 100 * bar_width)
    bar = Text(glyphs["full"] * filled, style=report.verdict.colour)
    bar.append(glyphs["empty"] * (bar_width - filled), style="dim")

    heading = Text(report.verdict.value.upper(), style=f"bold {report.verdict.colour}")
    heading.append(f"   {report.score}/100", style="bold white")

    return Panel(
        Group(heading, Text(""), bar, Text(""),
              Text(explain(report.score, report.verdict, report.breakdown), style="dim")),
        title="[bold]VERDICT[/bold]",
        border_style=report.verdict.colour,
        padding=(1, 2),
    )


def _summary_table(report: Report) -> Table:
    msg = report.email
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(overflow="fold")

    def row(label: str, value: str, style: str = "") -> None:
        # Always Text(), never a bare string. Rich parses square-bracket markup
        # in plain strings, and defanged output is full of brackets -- "[@]"
        # matches Rich's tag syntax and was being swallowed, silently printing
        # a sender address with no @ in it. Everything here is also
        # attacker-controlled, so markup must never be interpreted.
        if value:
            table.add_row(label, Text(value, style=style))

    row("Subject", defang.defang_text(msg.subject) or "(none)")
    display = f"{msg.from_display} " if msg.from_display else ""
    row("From", f"{display}<{defang.defang_email(msg.from_address)}>")
    row("Reply-To", defang.defang_email(msg.reply_to), "yellow")
    row("Return-Path", defang.defang_domain(msg.return_path))
    row("To", ", ".join(defang.defang_email(a) for a in msg.to[:4]))
    row("Date", msg.date_header)
    row("Message-ID", msg.message_id)
    row("Relay hops", str(len(msg.hops)))
    row("URLs", str(len(msg.urls)))
    row("Attachments", str(len(msg.attachments)))
    row("Size", f"{msg.raw_size:,} bytes")
    return table


def _findings_table(report: Report, glyphs: dict[str, str]) -> Group:
    if not report.findings:
        return Group(Text("No indicators fired.", style="green"))

    blocks: list[object] = []
    for category, findings in report.by_category().items():
        table = Table(box=None, padding=(0, 1, 0, 0), show_edge=False)
        table.add_column("ID", style="dim", no_wrap=True, width=9)
        table.add_column("Sev", no_wrap=True, width=8)
        table.add_column("Wt", justify="right", no_wrap=True, width=3)
        table.add_column("Indicator", no_wrap=False, width=34)
        table.add_column("Evidence", overflow="fold")

        for f in findings:
            style = _SEVERITY_STYLE[f.indicator.severity]
            table.add_row(
                Text(f.id),
                Text(f.indicator.severity.value.upper(), style=style),
                Text(str(f.indicator.weight)),
                Text(f.indicator.name, style=style),
                Text(defang.defang_text(f.evidence)),
            )
        blocks.append(Rule(_CATEGORY_TITLE.get(category, category), style="dim"))
        blocks.append(table)
        blocks.append(Text(""))
    return Group(*blocks)


def _ioc_table(report: Report, glyphs: dict[str, str]) -> Table | Text:
    iocs = report.iocs()
    rows: list[tuple[str, str]] = []
    for url in iocs["urls"][:15]:
        rows.append(("url", defang.defang_url(url)))
    for domain in iocs["domains"][:15]:
        rows.append(("domain", defang.defang_domain(domain)))
    for ip in iocs["sender_ips"][:10]:
        rows.append(("sender-ip", defang.defang_ip(ip)))
    for sha in iocs["attachment_sha256"]:
        rows.append(("sha256", sha))
    if not rows:
        return Text("No observables extracted.", style="dim")

    table = Table(box=None, padding=(0, 2, 0, 0), show_edge=False)
    table.add_column("Type", style="bold cyan", no_wrap=True)
    table.add_column("Observable", overflow="fold")
    for kind, value in rows:
        table.add_row(Text(kind), Text(value))
    return table


def _attack_line(report: Report) -> Text:
    techniques = report.attack_techniques
    if not techniques:
        return Text("No techniques mapped.", style="dim")
    return Text("  ".join(techniques), style="bold magenta")


def render(report: Report, console: Console | None = None, show_iocs: bool = True) -> None:
    console = console or Console()
    glyphs = _glyphs(console)
    console.print()
    console.print(_verdict_panel(report, glyphs))
    console.print()
    console.print(Panel(_summary_table(report), title="[bold]MESSAGE[/bold]",
                        border_style="dim", padding=(1, 2)))
    console.print()
    console.print(Panel(_findings_table(report, glyphs), title="[bold]INDICATORS[/bold]",
                        border_style="dim", padding=(1, 2)))
    if report.attack_techniques:
        console.print()
        console.print(Panel(_attack_line(report), title="[bold]MITRE ATT&CK[/bold]",
                            border_style="dim", padding=(1, 2)))
    if show_iocs:
        console.print()
        console.print(Panel(
            _ioc_table(report, glyphs),
            title="[bold]OBSERVABLES[/bold] [dim](defanged)[/dim]",
            border_style="dim", padding=(1, 2),
        ))
    console.print()
