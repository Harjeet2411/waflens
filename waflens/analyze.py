"""Aggregate WAF events into a summary with tuning hints."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .parser import Event

# CRS bookkeeping rules: they fire whenever the anomaly score crosses a threshold,
# so they say nothing about *what* was detected and would top every chart.
CRS_SUMMARY_RULES = frozenset({"949110", "949111", "959100", "980130", "980140", "980170"})


@dataclass
class FalsePositiveCandidate:
    rule_id: str
    path: str
    hits: int
    distinct_ips: int
    message: str


@dataclass
class Summary:
    total_events: int = 0
    blocked_events: int = 0
    rules: Counter = field(default_factory=Counter)
    rule_messages: dict[str, str] = field(default_factory=dict)
    attack_types: Counter = field(default_factory=Counter)
    client_ips: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    hours: Counter = field(default_factory=Counter)
    fp_candidates: list[FalsePositiveCandidate] = field(default_factory=list)

    @property
    def block_rate(self) -> float:
        return self.blocked_events / self.total_events if self.total_events else 0.0


def summarize(
    events: Iterable[Event],
    *,
    include_summary_rules: bool = False,
    fp_min_ips: int = 5,
) -> Summary:
    s = Summary()
    # (rule, path) -> set of client IPs, used for the false-positive heuristic
    spread: dict[tuple[str, str], set[str]] = defaultdict(set)
    spread_hits: Counter = Counter()

    for ev in events:
        s.total_events += 1
        if ev.blocked:
            s.blocked_events += 1
        s.client_ips[ev.client_ip] += 1
        s.paths[ev.path] += 1
        if ev.timestamp:
            s.hours[ev.timestamp.strftime("%Y-%m-%d %H:00")] += 1

        seen_types = set()
        for hit in ev.hits:
            if not include_summary_rules and hit.rule_id in CRS_SUMMARY_RULES:
                continue
            s.rules[hit.rule_id] += 1
            s.rule_messages.setdefault(hit.rule_id, hit.message)
            seen_types.update(hit.attack_types)
            key = (hit.rule_id, ev.path)
            spread[key].add(ev.client_ip)
            spread_hits[key] += 1
        s.attack_types.update(seen_types)

    # A single rule firing on one path for many unrelated clients is usually
    # legitimate traffic tripping a generic signature, not a coordinated attack.
    for (rule_id, path), ips in spread.items():
        if len(ips) >= fp_min_ips:
            s.fp_candidates.append(
                FalsePositiveCandidate(
                    rule_id=rule_id,
                    path=path,
                    hits=spread_hits[(rule_id, path)],
                    distinct_ips=len(ips),
                    message=s.rule_messages.get(rule_id, ""),
                )
            )
    s.fp_candidates.sort(key=lambda c: (-c.distinct_ips, -c.hits, c.rule_id))
    return s
