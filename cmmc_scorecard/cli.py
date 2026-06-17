"""Rich-powered command line interface for cmmc-scorecard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cmmc_scorecard import __version__
from cmmc_scorecard.loaders import LoaderError, load_findings_file
from cmmc_scorecard.models import Scorecard, Status
from cmmc_scorecard.oscal import OSCAL_VERSION, to_oscal
from cmmc_scorecard.scoring import score_findings

# Color/glyph styling per status, shared across the CLI views.
_STATUS_STYLE: dict[Status, str] = {
    Status.PASS: "bold green",
    Status.FAIL: "bold red",
    Status.PARTIAL: "bold yellow",
    Status.NOT_ASSESSED: "dim white",
}
_STATUS_GLYPH: dict[Status, str] = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.PARTIAL: "PARTIAL",
    Status.NOT_ASSESSED: "N/A",
}


def _score_style(score: float) -> str:
    if score >= 80.0:
        return "green"
    if score < 50.0:
        return "red"
    return "yellow"


def _bar(score: float, console: Console, width: int = 20) -> Text:
    filled = int(round(score / 100.0 * width))
    style = _score_style(score)
    # Block glyphs render best, but legacy Windows consoles (cp1252) can't
    # encode them — fall back to ASCII there.
    fill_char, empty_char = ("#", "-") if console.legacy_windows else ("█", "░")
    bar = Text(fill_char * filled, style=style)
    bar.append(empty_char * (width - filled), style="dim")
    return bar


def render_scorecard(console: Console, scorecard: Scorecard) -> None:
    rating = scorecard.overall_rating
    header = Text()
    header.append("CMMC 2.0 Level 2 Scorecard\n", style="bold white")
    header.append(f"Overall: {scorecard.overall_score:.1f}/100  ", style="bold")
    header.append(
        _STATUS_GLYPH[rating], style=_STATUS_STYLE[rating]
    )
    header.append(
        f"   Practices satisfied: {scorecard.passed_controls}/{scorecard.total_controls}",
        style="white",
    )
    header.append(f"\nGenerated: {scorecard.generated_at}", style="dim")
    console.print(Panel(header, border_style="cyan", title="[bold]cmmc-scorecard[/]"))

    table = Table(
        title="Domain Coverage",
        title_style="bold cyan",
        header_style="bold white on grey15",
        caption="Breakdown = pass / partial / fail / not-assessed",
        caption_style="dim",
    )
    table.add_column("Domain", style="white", ratio=3)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Coverage", justify="left", no_wrap=True)
    table.add_column("Rating", justify="center", no_wrap=True)
    table.add_column("Breakdown", justify="center", no_wrap=True)

    for ds in scorecard.domain_scores:
        rating = ds.rating
        breakdown = Text()
        breakdown.append(str(ds.passed), style="green")
        breakdown.append("/")
        breakdown.append(str(ds.partial), style="yellow")
        breakdown.append("/")
        breakdown.append(str(ds.failed), style="red")
        breakdown.append("/")
        breakdown.append(str(ds.not_assessed), style="dim")
        table.add_row(
            f"{ds.domain} · {ds.name}",
            Text(f"{ds.score:.0f}", style=_score_style(ds.score)),
            _bar(ds.score, console, width=10),
            Text(_STATUS_GLYPH[rating], style=_STATUS_STYLE[rating]),
            breakdown,
        )
    console.print(table)


def render_gaps(console: Console, scorecard: Scorecard, limit: int | None = None) -> None:
    gaps = scorecard.gaps[:limit] if limit else scorecard.gaps
    if not gaps:
        console.print("[bold green]No gaps — all assessed practices pass.[/]")
        return
    table = Table(
        title=f"Gap Analysis ({len(scorecard.gaps)} gap(s))",
        title_style="bold red",
        header_style="bold white on grey15",
        expand=True,
    )
    table.add_column("Practice", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Detail / Description")
    for gap in gaps:
        table.add_row(
            gap.practice_id,
            Text(_STATUS_GLYPH[gap.status], style=_STATUS_STYLE[gap.status]),
            Text(gap.severity.value, style=_score_style(100 - gap.severity.weight * 20)),
            f"{gap.description}\n[dim]{gap.detail}[/]",
        )
    console.print(table)


def render_remediation(console: Console, scorecard: Scorecard, limit: int = 10) -> None:
    items = scorecard.remediation[:limit]
    if not items:
        console.print("[bold green]Nothing to remediate.[/]")
        return
    table = Table(
        title=f"Top {len(items)} Remediation Priorities",
        title_style="bold magenta",
        header_style="bold white on grey15",
        expand=True,
    )
    table.add_column("#", justify="right", style="bold")
    table.add_column("Practice", style="cyan", no_wrap=True)
    table.add_column("Priority", justify="right")
    table.add_column("Severity", justify="center")
    table.add_column("Action")
    for item in items:
        table.add_row(
            str(item.rank),
            item.practice_id,
            Text(f"{item.priority_score:.1f}", style="bold magenta"),
            item.severity.value,
            f"{item.description}\n[dim]{item.rationale}[/]",
        )
    console.print(table)


def _load_scorecard(console: Console, path: str, source: str | None) -> Scorecard:
    try:
        findings = load_findings_file(path, source)
    except LoaderError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise SystemExit(2)
    if not findings:
        console.print(
            "[bold yellow]Warning:[/] no findings mapped to CMMC practices."
        )
    return score_findings(findings)


def _cmd_score(args: argparse.Namespace, console: Console) -> int:
    scorecard = _load_scorecard(console, args.findings, args.source)
    if args.json:
        console.print_json(data=_scorecard_summary(scorecard))
        return 0
    render_scorecard(console, scorecard)
    if not args.no_gaps:
        render_gaps(console, scorecard, limit=args.gap_limit)
        render_remediation(console, scorecard, limit=args.rem_limit)
    if args.oscal:
        _write_oscal(console, scorecard, args.oscal)
    return 0


def _cmd_gaps(args: argparse.Namespace, console: Console) -> int:
    scorecard = _load_scorecard(console, args.findings, args.source)
    render_gaps(console, scorecard, limit=args.gap_limit)
    render_remediation(console, scorecard, limit=args.rem_limit)
    return 0


def _cmd_oscal(args: argparse.Namespace, console: Console) -> int:
    scorecard = _load_scorecard(console, args.findings, args.source)
    _write_oscal(console, scorecard, args.output)
    return 0


def _write_oscal(console: Console, scorecard: Scorecard, output: str) -> None:
    doc = to_oscal(scorecard)
    Path(output).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    console.print(f"[green]OSCAL {OSCAL_VERSION} Assessment Results written to[/] {output}")


def _scorecard_summary(scorecard: Scorecard) -> dict:
    return {
        "generated_at": scorecard.generated_at,
        "overall_score": round(scorecard.overall_score, 2),
        "overall_rating": scorecard.overall_rating.value,
        "total_controls": scorecard.total_controls,
        "passed_controls": scorecard.passed_controls,
        "domains": [
            {
                "domain": ds.domain,
                "name": ds.name,
                "score": round(ds.score, 2),
                "rating": ds.rating.value,
                "passed": ds.passed,
                "partial": ds.partial,
                "failed": ds.failed,
                "not_assessed": ds.not_assessed,
            }
            for ds in scorecard.domain_scores
        ],
        "gaps": [
            {
                "practice_id": g.practice_id,
                "domain": g.domain,
                "status": g.status.value,
                "severity": g.severity.value,
            }
            for g in scorecard.gaps
        ],
        "remediation": [
            {
                "rank": r.rank,
                "practice_id": r.practice_id,
                "priority_score": r.priority_score,
                "severity": r.severity.value,
            }
            for r in scorecard.remediation
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cmmc-scorecard",
        description="Generate a CMMC 2.0 Level 2 scorecard from security findings.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("findings", help="Path to a findings JSON file.")
        p.add_argument(
            "--source",
            choices=["prowler", "securityhub", "manual"],
            help="Force the input source format (default: auto-detect).",
        )

    p_score = sub.add_parser("score", help="Render the full scorecard.")
    add_common(p_score)
    p_score.add_argument("--oscal", metavar="PATH", help="Also write OSCAL results to PATH.")
    p_score.add_argument("--json", action="store_true", help="Emit JSON summary instead of tables.")
    p_score.add_argument("--no-gaps", action="store_true", help="Show only the domain table.")
    p_score.add_argument("--gap-limit", type=int, default=None, help="Limit gaps shown.")
    p_score.add_argument("--rem-limit", type=int, default=10, help="Limit remediation items shown.")
    p_score.set_defaults(func=_cmd_score)

    p_gaps = sub.add_parser("gaps", help="Show gap analysis and remediation priorities.")
    add_common(p_gaps)
    p_gaps.add_argument("--gap-limit", type=int, default=None, help="Limit gaps shown.")
    p_gaps.add_argument("--rem-limit", type=int, default=10, help="Limit remediation items shown.")
    p_gaps.set_defaults(func=_cmd_gaps)

    p_oscal = sub.add_parser("oscal", help="Export OSCAL 1.1.2 Assessment Results.")
    add_common(p_oscal)
    p_oscal.add_argument("-o", "--output", default="oscal-results.json", help="Output path.")
    p_oscal.set_defaults(func=_cmd_oscal)

    return parser


def _force_utf8() -> None:
    """Best-effort UTF-8 stdout/stderr so rich output renders on any console."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    return args.func(args, console)


if __name__ == "__main__":
    sys.exit(main())
