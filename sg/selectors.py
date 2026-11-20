"""STIX 2.1 granular-marking selectors.

Syntax (per STIX 2.1 part 4 "granular markings" examples):
  - property names joined by '.'
  - array index written as ``.[N]`` (the dot is part of the bracket token),
    e.g. ``labels.[1]``, ``external_references.[0].source_name``.

Existence is checked against the *original* received version only.
A parent path covers its whole subtree; coverage is not order-sensitive.
"""
from __future__ import annotations

from .util import SGError

# Identities / version-control fields: hiding any of them breaks the rule
# that an object must not become reachable through another entry point, so the
# whole object is withdrawn from the normal projection.
IDENTITY_FIELDS = ("type", "id", "spec_version", "created", "modified")


def split_selector(selector: str):
    """Split a selector into path tokens.

    Property tokens stay strings; an array index written ``.[N]`` attaches to
    the preceding property as an int token (``labels.[1]`` ->
    ``['labels', 1]``; ``external_references.[0].source_name`` ->
    ``['external_references', 0, 'source_name']``).
    Raises SGError('invalid_selector') on malformed syntax.
    """
    if not isinstance(selector, str) or selector == "":
        raise SGError("invalid_selector", "empty or non-string selector")
    tokens = []
    for part in selector.split("."):
        if part == "":
            raise SGError("invalid_selector", "empty path component in selector")
        if part.startswith("["):
            if not part.endswith("]"):
                raise SGError("invalid_selector", "malformed array index")
            inside = part[1:-1]
            if not inside.isdigit() or (inside.startswith("0") and inside != "0"):
                raise SGError("invalid_selector",
                              "array index must be a non-negative integer")
            if not tokens:
                raise SGError("invalid_selector", "array index with no parent property")
            tokens.append(int(inside))
        else:
            if "[" in part or "]" in part:
                raise SGError("invalid_selector", "malformed array index syntax")
            if not part[:1].isalpha() and part[:1] != "_":
                raise SGError("invalid_selector",
                              "property names must start with a letter or underscore")
            tokens.append(part)
    if not tokens:
        raise SGError("invalid_selector", "selector has no tokens")
    return tokens


def path_exists(obj, tokens) -> bool:
    """Does the referenced position exist in the original object?"""
    cur = obj
    for token in tokens:
        if isinstance(token, int):
            if not isinstance(cur, list) or token >= len(cur):
                return False
            cur = cur[token]
        else:
            if not isinstance(cur, dict) or token not in cur:
                return False
            cur = cur[token]
    return True


def validate_selector(obj, selector: str):
    """Return parsed tokens or raise SGError('invalid_selector')."""
    tokens = split_selector(selector)
    if not path_exists(obj, tokens):
        raise SGError("invalid_selector", "selector references a position absent from the original object")
    return tokens


def is_covered(child_tokens, blocked_tokens) -> bool:
    """True when blocked_tokens is a prefix path of (equals or parents) child."""
    if len(blocked_tokens) > len(child_tokens):
        return False
    return child_tokens[: len(blocked_tokens)] == blocked_tokens


def identity_field_hidden(tokens) -> bool:
    return bool(tokens) and not isinstance(tokens[0], int) and tokens[0] in IDENTITY_FIELDS


def enumerate_paths(obj):
    """Yield (tokens, value) for every existing position, depth-first."""
    stack = [([], obj)]
    while stack:
        tokens, cur = stack.pop()
        yield tokens, cur
        if isinstance(cur, dict):
            for key in reversed(list(cur.keys())):
                stack.append((tokens + [key], cur[key]))
        elif isinstance(cur, list):
            for idx in reversed(range(len(cur))):
                stack.append((tokens + [idx], cur[idx]))
