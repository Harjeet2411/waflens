"""Render a Summary as text, Markdown or JSON."""

from __future__ import annotations

import json

from .analyze import Summary


def _rows(counter, top):
    return counter.most_common(top)


def _cell(value) -> str:
    # URIs and rule messages can contain pipes, which would split a Markdown table cell.
    return str(value).replace("|", "\\|")


def to_dict(s: Summary, top: int = 10) -> dict:
    return {
        "total_events": s.total_events,
        "blocked_events": s.blocked_events,
        "block_rate": round(s.block_rate, 4),
        "top_rules": [
            {"rule_id": r, "hits": n, "message": s.rule_messages.get(r, "")}
            for r, n in _rows(s.rules, top)
        ],
        "attack_types": dict(_rows(s.attack_types, top)),
        "top_client_ips": dict(_rows(s.client_ips, top)),
        "top_paths": dict(_rows(s.paths, top)),
        "events_per_hour": dict(sorted(s.hours.items())),
        "false_positive_candidates": [vars(c) for c in s.fp_candidates[:top]],
    }


def to_json(s: Summary, top: int = 10) -> str:
    return json.dumps(to_dict(s, top), indent=2)


def _bar(n: int, peak: int, width: int = 24) -> str:
    return "█" * max(1, round(width * n / peak)) if peak else ""


def to_text(s: Summary, top: int = 10) -> str:
    out = [
        f"Events: {s.total_events}   Blocked: {s.blocked_events} ({s.block_rate:.1%})",
        "",
    ]

    def section(title, rows, label=lambda k: k):
        out.append(title)
        if not rows:
            out.append("  (none)")
        peak = rows[0][1] if rows else 0
        width = max((len(label(k)) for k, _ in rows), default=0)
        for k, n in rows:
            out.append(f"  {label(k):<{width}}  {n:>6}  {_bar(n, peak)}")
        out.append("")

    section(
        "Top rules",
        _rows(s.rules, top),
        lambda r: f"{r} {s.rule_messages.get(r, '')[:48]}".rstrip(),
    )
    section("Attack types", _rows(s.attack_types, top))
    section("Top client IPs", _rows(s.client_ips, top))
    section("Top paths", _rows(s.paths, top))

    out.append("Possible false positives (one rule, one path, many clients)")
    if not s.fp_candidates:
        out.append("  (none)")
    for c in s.fp_candidates[:top]:
        out.append(f"  rule {c.rule_id} on {c.path}: {c.hits} hits from {c.distinct_ips} IPs")
    return "\n".join(out).rstrip() + "\n"


def to_markdown(s: Summary, top: int = 10) -> str:
    md = [
        "# WAF log report",
        "",
        f"**{s.total_events}** events, **{s.blocked_events}** blocked ({s.block_rate:.1%}).",
        "",
        "## Top rules",
        "",
        "| Rule | Hits | Message |",
        "|---|---:|---|",
    ]
    md += [f"| {r} | {n} | {_cell(s.rule_messages.get(r, ''))} |" for r, n in _rows(s.rules, top)]
    for title, counter in (
        ("Attack types", s.attack_types),
        ("Top client IPs", s.client_ips),
        ("Top paths", s.paths),
    ):
        md += ["", f"## {title}", "", "| Value | Count |", "|---|---:|"]
        md += [f"| `{_cell(k)}` | {n} |" for k, n in _rows(counter, top)]
    md += ["", "## Possible false positives", ""]
    if s.fp_candidates:
        md += ["| Rule | Path | Hits | Distinct IPs |", "|---|---|---:|---:|"]
        md += [
            f"| {c.rule_id} | `{_cell(c.path)}` | {c.hits} | {c.distinct_ips} |"
            for c in s.fp_candidates[:top]
        ]
    else:
        md.append("None found.")
    return "\n".join(md) + "\n"


RENDERERS = {"text": to_text, "markdown": to_markdown, "json": to_json}
