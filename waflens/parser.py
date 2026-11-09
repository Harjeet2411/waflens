"""Parse ModSecurity v3 / Coraza JSON audit logs into flat events."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import IO, Iterator

# ModSecurity v3 writes time_stamp like "Mon Oct 19 00:12:03 2026".
_TS_FORMATS = ("%a %b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S%z", "%Y/%m/%d %H:%M:%S")


@dataclass
class RuleHit:
    rule_id: str
    message: str
    severity: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def attack_types(self) -> list[str]:
        return [t[len("attack-"):] for t in self.tags if t.startswith("attack-")]


@dataclass
class Event:
    unique_id: str
    client_ip: str
    timestamp: datetime | None
    method: str
    uri: str
    status: int
    hits: list[RuleHit]

    @property
    def blocked(self) -> bool:
        # CRS anomaly blocking answers 403 by default; 406/429 are common custom choices.
        return self.status in (403, 406, 429)

    @property
    def path(self) -> str:
        return self.uri.split("?", 1)[0] or "/"


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def parse_record(record: dict) -> Event:
    tx = record.get("transaction", record)
    request = tx.get("request") or {}
    response = tx.get("response") or {}
    hits = []
    for msg in tx.get("messages") or []:
        details = msg.get("details") or {}
        hits.append(
            RuleHit(
                rule_id=str(details.get("ruleId", "")),
                message=msg.get("message", ""),
                severity=str(details.get("severity", "")),
                tags=list(details.get("tags") or []),
            )
        )
    try:
        status = int(response.get("http_code", 0))
    except (TypeError, ValueError):
        status = 0
    return Event(
        unique_id=str(tx.get("unique_id", "")),
        client_ip=str(tx.get("client_ip", "")),
        timestamp=_parse_ts(tx.get("time_stamp")),
        method=str(request.get("method", "")),
        uri=str(request.get("uri", "")),
        status=status,
        hits=hits,
    )


def iter_events(stream: IO[str], errors: list[int] | None = None) -> Iterator[Event]:
    """Yield events from a JSON-lines audit log, skipping malformed lines.

    Line numbers of skipped lines are appended to ``errors`` when given.
    """
    for lineno, line in enumerate(stream, 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            if errors is not None:
                errors.append(lineno)
            continue
        if isinstance(record, dict):
            yield parse_record(record)
        elif errors is not None:
            errors.append(lineno)
