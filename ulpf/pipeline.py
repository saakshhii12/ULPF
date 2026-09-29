from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from ulpf import detect as detect_mod
from ulpf.detect import detect, parsers_for
from ulpf.parsers import register_all
from ulpf.schema import finalize_event, raw_hash

PACKAGE_DIR = Path(__file__).resolve().parent


def _load_mappings() -> dict[str, dict[str, Any]]:
    register_all(detect_mod)
    mappings: dict[str, dict[str, Any]] = {}
    mappings_dir = PACKAGE_DIR / "mappings"
    for mapping_path in mappings_dir.glob("*.yaml"):
        mappings[mapping_path.stem] = yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or {}
    return mappings


def _mapping_for(parse: Callable[..., Any], mappings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    stem = parse.__module__.rsplit(".", 1)[-1]
    return mappings.get(stem, {})


def _iter_input_files(input_dir: Path) -> Iterable[Path]:
    for path in sorted(input_dir.iterdir()):
        if path.is_file():
            yield path


def _failed_event(raw_text: str, raw_event_id: str, digest: str, ingest_time: str) -> dict[str, Any]:
    event = finalize_event(
        {
            "event_id": raw_event_id,
            "parse.status": "failed",
            "parse.confidence": 0,
            "provenance.raw_event_id": raw_event_id,
            "provenance.raw_text": raw_text,
            "provenance.raw_hash": digest,
            "provenance.ingest_time": ingest_time,
        }
    )
    return event


def run(input_dir: str | Path, output_dir: str | Path) -> None:
    source = Path(input_dir)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    mappings = _load_mappings()
    raw_path = destination / "raw.jsonl"
    events_path = destination / "events.jsonl"
    report: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    with raw_path.open("w", encoding="utf-8") as raw_out, events_path.open(
        "w", encoding="utf-8"
    ) as events_out:
        for source_file in _iter_input_files(source):
            file_row: dict[str, Any] = {
                "file": source_file.name,
                "lines": 0,
                "parsed": 0,
                "failed": 0,
                "duplicates": 0,
                "formats": [],
            }
            formats: list[str] = []
            for line in source_file.read_text(encoding="utf-8").splitlines():
                raw_text = line
                if raw_text == "":
                    continue
                file_row["lines"] += 1
                raw_event_id = str(uuid.uuid4())
                digest = raw_hash(raw_text)
                ingest_time = datetime.now(timezone.utc).isoformat()
                raw_record = {
                    "raw_event_id": raw_event_id,
                    "raw_text": raw_text,
                    "raw_hash": digest,
                    "source_file": source_file.name,
                    "ingest_time": ingest_time,
                }
                raw_out.write(json.dumps(raw_record, ensure_ascii=False) + "\n")

                parsed = None
                mapping_version = ""
                detected = detect(raw_text)
                for parse in parsers_for(detected):
                    mapping = _mapping_for(parse, mappings)
                    parsed = parse(raw_text, mapping)
                    if parsed is not None:
                        mapping_version = str(mapping.get("mapping_version") or "")
                        break

                if parsed is None:
                    event = _failed_event(raw_text, raw_event_id, digest, ingest_time)
                    file_row["failed"] += 1
                else:
                    parsed["event_id"] = raw_event_id
                    parsed["provenance.raw_event_id"] = raw_event_id
                    parsed["provenance.raw_text"] = raw_text
                    parsed["provenance.raw_hash"] = digest
                    parsed["provenance.mapping_version"] = mapping_version
                    parsed["provenance.ingest_time"] = ingest_time
                    event = finalize_event(parsed)
                    file_row["parsed"] += 1

                if digest in seen_hashes:
                    unmapped = dict(event.get("unmapped") or {})
                    unmapped["duplicate"] = True
                    event["unmapped"] = unmapped
                    file_row["duplicates"] += 1
                else:
                    seen_hashes.add(digest)

                fmt = event.get("parse.format") or detected
                if fmt and fmt not in formats:
                    formats.append(fmt)

                events_out.write(json.dumps(event, ensure_ascii=False) + "\n")
            file_row["formats"] = formats
            report.append(file_row)

    (destination / "ingest_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        sys.stderr.write("usage: python -m ulpf.pipeline <input_dir> <output_dir>\n")
        sys.exit(2)
    run(args[0], args[1])


if __name__ == "__main__":
    main()
