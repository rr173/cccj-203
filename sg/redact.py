"""Build the visible projection of an object from blocked selector paths.

Rules:
  * a blocked property is deleted from the projected document;
  * a blocked *array element* is replaced by None so original indices stay
    stable, and its path is listed in ``redacted``;
  * blocked parent paths cover the whole subtree regardless of the order in
    which selectors were declared;
  * selectors are resolved on the ORIGINAL document — after redaction no
    selector is re-interpreted against the shortened array;
  * granular_markings metadata that cites a marking the caller may not use is
    stripped itself, so a restricted marking id is never echoed.
"""
from __future__ import annotations

from .selectors import is_covered


def render_path(tokens) -> str:
    out = ""
    for token in tokens:
        if isinstance(token, int):
            out += f".[{token}]"
        else:
            if out:
                out += "."
            out += token
    return out


def any_cover(tokens, blocked) -> bool:
    """True when any blocked path equals ``tokens`` or is one of its parents."""
    return any(is_covered(tokens, b) for b in blocked)


def _project(value, tokens, blocked, redacted):
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            child_tokens = tokens + [key]
            if any_cover(child_tokens, blocked):
                redacted.append(render_path(child_tokens))
                continue  # hidden property: deleted, no placeholder
            result[key] = _project(child, child_tokens, blocked, redacted)
        return result
    if isinstance(value, list):
        result = []
        for idx, child in enumerate(value):
            child_tokens = tokens + [idx]
            if any_cover(child_tokens, blocked):
                redacted.append(render_path(child_tokens))
                result.append(None)  # null keeps the original index; value not copied
                continue
            result.append(_project(child, child_tokens, blocked, redacted))
        return result
    return value


def _strip_granular_metadata(projected, blocked, blocked_marking_refs, redacted):
    entries = projected.get("granular_markings")
    if not isinstance(entries, list):
        return
    kept = []
    dropped = False
    for entry in entries:
        if isinstance(entry, dict) and entry.get("marking_ref") in blocked_marking_refs:
            dropped = True
            continue
        kept.append(entry)
    if dropped:
        redacted.append("granular_markings")
    if kept:
        projected["granular_markings"] = kept
    else:
        projected.pop("granular_markings", None)


def redact_object(obj, blocked_token_paths, blocked_marking_refs=None):
    """Project ``obj``. Returns (projected_dict, redacted_path_strings)."""
    blocked = list(blocked_token_paths)
    blocked_marking_refs = set(blocked_marking_refs or ())
    redacted = []
    projected = {}
    for key, child in obj.items():
        tokens = [key]
        if any_cover(tokens, blocked):
            redacted.append(render_path(tokens))
            continue
        projected[key] = _project(child, tokens, blocked, redacted)
    _strip_granular_metadata(projected, blocked, blocked_marking_refs, redacted)
    # de-duplicate while preserving order (overlapping selectors may both name
    # a parent and a child; the parent already covers the child).
    seen = set()
    unique = []
    for path in redacted:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return projected, unique
