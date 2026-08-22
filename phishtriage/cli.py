"""Command-line interface.

Exit codes are chosen so the tool composes into a mail-gateway pipeline or a
CI check:

===  ==========================================================
  0  analysed; verdict Benign
  1  analysed; verdict Suspicious or worse (use --fail-on to tune)
  2  usage error
  3  the message could not be parsed
===  ==========================================================
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from . import __version__, catalog
from .analyzers import Context, analyze_file
from .models import Report, Verdict
from .reporting import html_out, json_out, terminal

_VERDICT_ORDER = [Verdict.BENIGN, Verdict.SUSPICIOUS, Verdict.LIKELY_PHISHING, Verdict.MALICIOUS]
_FAIL_CHOICES = {
    "benign": Verdict.BENIGN,
    "suspicious": Verdict.SUSPICIOUS,
    "likely": Verdict.LIKELY_PHISHING,
    "malicious": Verdict.MALICIOUS,
    "never": None,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phish-triage",
        description="Offline-first phishing email triage for SOC analysts.",
        epilog="No URL is resolved and no attachment is executed. Analysis is static.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"phish-triage {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = sub.add_parser("analyze", help="analyse one or more .eml files")
    analyze_cmd.add_argument("paths", nargs="+", type=Path,
                             help="paths to .eml files, or directories to scan")
    analyze_cmd.add_argument("-f", "--format", default="terminal",
                             choices=("terminal", "json", "html", "iocs", "summary"),
                             help="output format (default: terminal)")
    analyze_cmd.add_argument("-o", "--output", type=Path,
                             help="write to a file or, for multiple inputs, a directory")
    analyze_cmd.add_argument("--online", action="store_true",
                             help="allow DNS lookups of SPF/DMARC records (requires dnspython)")
    analyze_cmd.add_argument("--org-domain", action="append", default=[], metavar="DOMAIN",
                             help="a domain your organisation owns; repeatable. "
                                  "Improves impersonation and recipient checks.")
    analyze_cmd.add_argument("--no-defang", action="store_true",
                             help="emit live URLs in JSON output (default: defanged)")
    analyze_cmd.add_argument("--fail-on", default="suspicious", choices=sorted(_FAIL_CHOICES),
                             help="minimum verdict that yields a non-zero exit "
                                  "(default: suspicious)")
    analyze_cmd.add_argument("-q", "--quiet", action="store_true",
                             help="suppress the terminal report; exit code only")

    indicators_cmd = sub.add_parser("indicators", help="list the detection catalogue")
    indicators_cmd.add_argument("-f", "--format", default="table",
                                choices=("table", "json", "markdown"))

    return parser


def _collect_paths(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(sorted(
                p for p in path.rglob("*")
                if p.is_file() and p.suffix.lower() in (".eml", ".msg", ".txt")
            ))
        elif path.is_file():
            found.append(path)
    return found


def _emit_single(report: Report, args, console: Console) -> None:
    defanged = not args.no_defang
    if args.format == "terminal":
        if not args.quiet:
            terminal.render(report, console)
        return
    if args.format == "html":
        target = args.output or Path(f"{Path(report.email.source_path).stem}.report.html")
        html_out.write(report, target)
        console.print(f"[green]wrote[/green] {target}")
        return

    payload = {
        "json": lambda: json_out.dumps(report, defanged=defanged),
        "iocs": lambda: json_out.dumps_iocs(report, defanged=defanged),
        "summary": lambda: json_out.dumps_summary([report], defanged=defanged),
    }[args.format]()

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        console.print(f"[green]wrote[/green] {args.output}")
    else:
        print(payload)


def _emit_batch(reports: list[Report], args, console: Console) -> None:
    defanged = not args.no_defang

    if args.format == "html":
        out_dir = args.output or Path("out")
        out_dir.mkdir(parents=True, exist_ok=True)
        for report in reports:
            target = out_dir / f"{Path(report.email.source_path).stem}.report.html"
            html_out.write(report, target)
        console.print(f"[green]wrote[/green] {len(reports)} report(s) to {out_dir}/")
        return

    if args.format == "terminal":
        if args.quiet:
            return
        for report in reports:
            terminal.render(report, console)
        _print_batch_table(reports, console)
        return

    if args.format == "summary":
        payload = json_out.dumps_summary(reports, defanged=defanged)
    elif args.format == "iocs":
        merged = [ioc for r in reports for ioc in json_out.to_iocs(r, defanged=defanged)]
        seen: set[tuple[str, str]] = set()
        unique = [i for i in merged
                  if (i["type"], i["value"]) not in seen and not seen.add((i["type"], i["value"]))]
        import json as _json
        payload = _json.dumps(unique, indent=2, ensure_ascii=False)
    else:
        import json as _json
        payload = _json.dumps(
            [json_out.to_dict(r, defanged=defanged) for r in reports],
            indent=2, ensure_ascii=False,
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        console.print(f"[green]wrote[/green] {args.output}")
    else:
        print(payload)


def _print_batch_table(reports: list[Report], console: Console) -> None:
    from rich.table import Table
    from rich.text import Text

    table = Table(title=f"Batch summary: {len(reports)} message(s)", title_justify="left")
    table.add_column("File", overflow="fold")
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Top indicators", overflow="fold")
    for report in sorted(reports, key=lambda r: -r.score):
        # Filenames are untrusted; only the verdict cell uses markup, and its
        # content comes from a closed enum rather than the message.
        table.add_row(
            Text(Path(report.email.source_path).name),
            f"[{report.verdict.colour}]{report.verdict.value}[/{report.verdict.colour}]",
            Text(str(report.score)),
            Text(", ".join(f.id for f in report.findings[:5]) or "-"),
        )
    console.print(table)


def _cmd_indicators(args) -> int:
    console = Console()
    indicators = catalog.all_indicators()

    if args.format == "json":
        import json as _json
        print(_json.dumps([{
            "id": i.id, "name": i.name, "category": i.category,
            "severity": i.severity.value, "weight": i.weight,
            "description": i.description, "attack": list(i.attack),
        } for i in indicators], indent=2))
        return 0

    if args.format == "markdown":
        for category in catalog.CATEGORIES:
            rows = [i for i in indicators if i.category == category]
            print(f"\n### {category.title()}\n")
            print("| ID | Indicator | Severity | Weight | ATT&CK | Description |")
            print("|----|-----------|----------|--------|--------|-------------|")
            for i in rows:
                attack = ", ".join(i.attack) or "-"
                print(f"| `{i.id}` | {i.name} | {i.severity.value} | {i.weight} | "
                      f"{attack} | {i.description} |")
        return 0

    from rich.table import Table
    for category in catalog.CATEGORIES:
        rows = [i for i in indicators if i.category == category]
        table = Table(title=category.upper(), title_justify="left")
        table.add_column("ID", no_wrap=True, style="dim")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Wt", justify="right", no_wrap=True)
        table.add_column("Indicator", overflow="fold")
        table.add_column("ATT&CK", no_wrap=True, style="magenta")
        for i in rows:
            table.add_row(i.id, i.severity.value, str(i.weight), i.name,
                          ", ".join(i.attack) or "-")
        console.print(table)
        console.print()
    console.print(f"[dim]{len(indicators)} indicators across "
                  f"{len(catalog.CATEGORIES)} categories[/dim]")
    return 0


def _cmd_analyze(args) -> int:
    console = Console(stderr=args.format not in ("terminal",))
    paths = _collect_paths(args.paths)
    if not paths:
        console.print("[red]error:[/red] no .eml files found in the given paths")
        return 2

    ctx = Context(online=args.online, org_domains=tuple(args.org_domain))
    reports: list[Report] = []
    failed = 0
    for path in paths:
        try:
            reports.append(analyze_file(path, ctx))
        except Exception as exc:
            console.print(f"[red]failed to parse[/red] {path}: {exc}")
            failed += 1

    if not reports:
        return 3

    if len(reports) == 1 and len(paths) == 1:
        _emit_single(reports[0], args, console)
    else:
        _emit_batch(reports, args, console)

    threshold = _FAIL_CHOICES[args.fail_on]
    if threshold is None:
        return 0
    worst = max(_VERDICT_ORDER.index(r.verdict) for r in reports)
    return 1 if worst >= _VERDICT_ORDER.index(threshold) and threshold != Verdict.BENIGN else 0


def _force_utf8_stdio() -> None:
    """JSON output can contain any Unicode the attacker chose to put in a header.

    Windows still defaults stdout to the ANSI code page, so writing that JSON
    raises UnicodeEncodeError instead of producing output. Reconfiguring is
    harmless everywhere else.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - detached stream
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdio()
    args = build_parser().parse_args(argv)
    if args.command == "indicators":
        return _cmd_indicators(args)
    return _cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
