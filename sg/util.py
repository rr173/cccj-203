"""Shared primitives: canonical bytes, time handling, JSON IO.

Canonical JSON = RFC 8785 style (object keys sorted, compact separators,
ensure_ascii False). It is only used for *identity* comparisons and digests,
never as output formatting.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


class SGError(Exception):
    """Error whose message must never embed restricted object content."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message}


CANON_KWARGS = dict(sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canon(obj) -> bytes:
    return json.dumps(obj, **CANON_KWARGS).encode("utf-8")


def parse_time(value):
    """Parse an STIX timestamp to an aware UTC datetime, or raise SGError."""
    if not isinstance(value, str):
        raise SGError("invalid_time", "timestamp must be a string")
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SGError("invalid_time", f"unparseable timestamp: {type(exc).__name__}")
    if dt.tzinfo is None:
        raise SGError("invalid_time", "timestamp must carry a timezone offset")
    return dt.astimezone(timezone.utc)


def dt_to_key(dt: datetime) -> int:
    """Monotonic integer key (microseconds since epoch)."""
    return int(dt.astimezone(timezone.utc).timestamp() * 1_000_000)


def time_key(value) -> int:
    return dt_to_key(parse_time(value))


def json_dump_lines(rows, fp) -> None:
    for row in rows:
        fp.write(json.dumps(row, ensure_ascii=False))
        fp.write("\n")


def read_bundle(path: str):
    """Read one .json STIX bundle (whole document) into a list of objects.

    Bundle *containers* are untrusted input; callers run with ``python -I`` so
    no local modules are importable from the data directory.
    """
    if path.endswith(".ndjson"):
        return list(iter_ndjson(path))
    with open(path, "r", encoding="utf-8") as fh:
        try:
            doc = json.load(fh)
        except json.JSONDecodeError:
            raise SGError("bundle_parse_error", "invalid JSON document")
    if not isinstance(doc, dict) or doc.get("type") != "bundle":
        raise SGError("bundle_parse_error", "document is not a STIX bundle")
    items = doc.get("objects", [])
    if not isinstance(items, list):
        raise SGError("bundle_parse_error", "bundle objects must be an array")
    return items


def iter_bundle_objects(path: str):
    """Stream objects: line-by-line for NDJSON, once for a single bundle.

    NDJSON keeps memory bounded regardless of corpus size; a .json bundle is
    necessarily one JSON document and is read as such.
    """
    if path.endswith(".ndjson"):
        yield from iter_ndjson(path)
        return
    for obj in read_bundle(path):
        yield obj


def iter_ndjson(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                raise SGError("bundle_parse_error",
                              f"invalid NDJSON on line {line_no}")
            yield obj
