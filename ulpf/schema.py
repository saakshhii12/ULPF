from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any

SYSLOG_CLOCK = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})$"
)
DATED_CLOCK = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})$")
HAS_REAL_ZONE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def assume_utc_iso(raw: str, default_year: int | str | None = None) -> str | None:
    text = (raw or "").strip()
    if not text or HAS_REAL_ZONE.search(text):
        return None
    syslog = SYSLOG_CLOCK.match(text)
    if syslog:
        if default_year is None:
            return None
        month = MONTHS.get(syslog.group("mon"))
        if month is None:
            return None
        hour, minute, second = (int(part) for part in syslog.group("clock").split(":"))
        parsed = datetime(int(default_year), month, int(syslog.group("day")), hour, minute, second)
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    dated = DATED_CLOCK.match(text)
    if dated:
        parsed = datetime.strptime(f"{dated.group(1)} {dated.group(2)}", "%Y-%m-%d %H:%M:%S")
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None

EVENT_KEYS = (
    "event_id",
    "timestamp",
    "observer.vendor",
    "observer.product",
    "observer.name",
    "network.src_ip",
    "network.src_port",
    "network.dst_ip",
    "network.dst_port",
    "network.transport",
    "user.name",
    "event.action",
    "event.category",
    "event.outcome",
    "event.severity",
    "event.description",
    "parse.status",
    "parse.format",
    "parse.parser",
    "parse.confidence",
    "provenance.raw_event_id",
    "provenance.raw_text",
    "provenance.raw_hash",
    "provenance.mapping_version",
    "provenance.ingest_time",
    "unmapped",
)

VALID_OUTCOMES = frozenset({"success", "failure", "unknown"})


def empty_event() -> dict[str, Any]:
    return {
        "event_id": "",
        "timestamp": "",
        "observer.vendor": "",
        "observer.product": "",
        "observer.name": "",
        "network.src_ip": "",
        "network.src_port": "",
        "network.dst_ip": "",
        "network.dst_port": "",
        "network.transport": "",
        "user.name": "",
        "event.action": "",
        "event.category": "",
        "event.outcome": "unknown",
        "event.severity": "",
        "event.description": "",
        "parse.status": "failed",
        "parse.format": "",
        "parse.parser": "",
        "parse.confidence": 0,
        "provenance.raw_event_id": "",
        "provenance.raw_text": "",
        "provenance.raw_hash": "",
        "provenance.mapping_version": "",
        "provenance.ingest_time": "",
        "unmapped": {},
    }


def raw_hash(raw_text: str) -> str:
    return hashlib.sha256(raw_text.encode("utf-8")).hexdigest()


def finalize_event(event: dict[str, Any]) -> dict[str, Any]:
    record = empty_event()
    for key in EVENT_KEYS:
        if key in event:
            record[key] = event[key]
    if record["event.outcome"] not in VALID_OUTCOMES:
        record["event.outcome"] = "unknown"
    if record["unmapped"] is None:
        record["unmapped"] = {}
    return record
