"""Marking resolution, policy loading and field-level visibility.

A marking definition body is treated as an *opaque label*: no TLP level or
statement semantics are ever inferred. Only the marking id and the principal's
allow-list matter.
"""
from __future__ import annotations

import hashlib

from .util import SGError, canon
from .selectors import split_selector, validate_selector, identity_field_hidden


def load_policy(doc: dict):
    """Validate a policy.json document and return a normalized policy."""
    if not isinstance(doc, dict) or not isinstance(doc.get("principals"), list):
        raise SGError("invalid_policy", "policy needs a principals array")
    principals = {}
    order = []
    for entry in doc["principals"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("principal"), str):
            raise SGError("invalid_policy", "each principal entry needs a string principal")
        name = entry["principal"]
        allowed = entry.get("allowed_marking_ids", [])
        if not isinstance(allowed, list) or not all(isinstance(m, str) for m in allowed):
            raise SGError("invalid_policy", "allowed_marking_ids must be an array of strings")
        if name in principals:
            raise SGError("invalid_policy", f"duplicate principal entry")
        principals[name] = set(allowed)
        order.append(name)
    return {"principals": principals, "order": order, "raw": doc}


def policy_digest(doc: dict) -> str:
    """Stable digest of the exact policy document (canonical bytes)."""
    return hashlib.sha256(canon(doc)).hexdigest()


def check_marking_definitions(marking_rows):
    """Build the marking map from received definitions.

    marking_rows: list of (marking_id, canon_hex, raw_json_text).
    Returns (known_ids, conflicted_ids). A duplicated id with different
    canonical content is a definition conflict — recorded but not resolved.
    """
    seen = {}
    conflicts = set()
    for marking_id, canon_hex, _raw in marking_rows:
        if marking_id in seen:
            if seen[marking_id] != canon_hex:
                conflicts.add(marking_id)
        else:
            seen[marking_id] = canon_hex
    return set(seen.keys()), conflicts


def object_level_markings(obj):
    refs = obj.get("object_marking_refs", [])
    if refs is None:
        return []
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
        return _BAD_REFS
    return refs


_BAD_REFS = object()


def granular_entries(obj):
    """Yield (marking_ref, selector_string) from granular_markings.

    Structure is validated; malformed entries raise so the object can be
    withdrawn during ingestion.
    """
    entries = obj.get("granular_markings", [])
    if entries is None:
        return
    if not isinstance(entries, list):
        raise SGError("invalid_granular", "granular_markings must be an array")
    for entry in entries:
        if not isinstance(entry, dict):
            raise SGError("invalid_granular", "granular marking entry must be an object")
        ref = entry.get("marking_ref")
        selectors = entry.get("selectors")
        if not isinstance(ref, str):
            raise SGError("invalid_granular", "granular marking needs a string marking_ref")
        if not isinstance(selectors, list) or not all(isinstance(s, str) for s in selectors):
            raise SGError("invalid_granular", "selectors must be an array of strings")
        for selector in selectors:
            yield ref, selector


def resolve_object_block(obj, known_marking_ids, conflicted_marking_ids):
    """Ingestion-time checks independent of any principal.

    Returns (block_reason_or_None, parsed_granular_list).
    parsed_granular_list: [(marking_ref, selector, tokens), ...] for valid rows.
    """
    refs = object_level_markings(obj)
    if refs is _BAD_REFS:
        return "invalid-object_marking_refs", []
    for ref in refs:
        if ref not in known_marking_ids:
            return f"unknown-marking:{ref}", []
        if ref in conflicted_marking_ids:
            return f"conflicted-marking:{ref}", []

    parsed = []
    try:
        entries = list(granular_entries(obj))
    except SGError as exc:
        return exc.code, []
    for ref, selector in entries:
        if ref not in known_marking_ids:
            return f"unknown-marking:{ref}", []
        if ref in conflicted_marking_ids:
            return f"conflicted-marking:{ref}", []
        try:
            tokens = validate_selector(obj, selector)
        except SGError:
            return "invalid_selector", []
        if identity_field_hidden(tokens):
            # Must be checked at ingestion time: the object can never appear in
            # any normal projection, otherwise another entry point would leak
            # the identity/version field.
            return "identity-field-redacted", []
        parsed.append((ref, selector, tokens))
    return None, parsed


def effective_field_markings(obj, path_tokens, parsed_granular):
    """Union of object-level labels and every granular label covering path."""
    labels = set(object_level_markings(obj)) if object_level_markings(obj) is not _BAD_REFS else set()
    for ref, _selector, tokens in parsed_granular:
        if path_tokens[: len(tokens)] == tokens and len(tokens) <= len(path_tokens):
            labels.add(ref)
    return labels


def visible_for_principal(obj, parsed_granular, allowed_set):
    """Decide object visibility and collect blocked field paths for a principal.

    Returns (visible_bool, blocked_tokens_list, blocked_marking_refs,
    hidden_reason_or_None).
    Object-level marking refs gate the whole row; granular refs the caller
    lacks only block the covered field paths. An object with no labels at all
    is public.
    """
    refs = object_level_markings(obj)
    if refs is _BAD_REFS:
        return False, [], set(), "invalid-object_marking_refs"
    for ref in refs:
        if ref not in allowed_set:
            return False, [], set(), "object-marking-denied"
    blocked = []
    blocked_refs = set()
    for ref, _selector, tokens in parsed_granular:
        if ref not in allowed_set:
            blocked.append(tokens)
            blocked_refs.add(ref)
    return True, blocked, blocked_refs, None
