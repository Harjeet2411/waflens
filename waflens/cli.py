"""Command-line entry point: ``waflens audit.log``."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyze import summarize
from .parser import iter_events
from .report import RENDERERS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="waflens",
        description="Summarize ModSecurity / Coraza JSON audit logs and flag likely false positives.",
    )
    p.add_argument("logs", nargs="*", default=["-"], help="audit log files (JSON lines); '-' reads stdin")
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("-n", "--top", type=int, default=10, help="rows per section (default 10)")
    p.add_argument(
        "--fp-min-ips",
        type=int,
        default=5,
        help="distinct clients a rule/path pair needs to be flagged as a possible false positive",
    )
    p.add_argument(
        "--include-summary-rules",
        action="store_true",
        help="keep CRS anomaly-score rules such as 949110 in the counts",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _events(paths, errors):
    for path in paths:
        if path == "-":
            yield from iter_events(sys.stdin, errors)
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                yield from iter_events(fh, errors)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors: list[int] = []
    try:
        summary = summarize(
            _events(args.logs, errors),
            include_summary_rules=args.include_summary_rules,
            fp_min_ips=args.fp_min_ips,
        )
    except OSError as exc:
        print(f"waflens: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(RENDERERS[args.format](summary, args.top))
    if errors:
        print(f"waflens: skipped {len(errors)} malformed line(s)", file=sys.stderr)
    return 0
