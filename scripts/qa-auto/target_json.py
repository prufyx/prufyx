"""Strict reading of a CRD version target file (Python 3 stdlib only).

The gate scripts and the Go extractor (crdversions.LoadTarget) read the same bytes. Go matches object keys without regard to
case, merges duplicate members and repairs invalid UTF-8, so a document the two could read differently is refused here: strict
UTF-8 without a byte-order mark, ASCII keys, no two keys of one object equal in lower case, no unpaired surrogate, no number,
and at the levels listed below only the exact key spellings of the Go struct tags with their JSON types. A new Go field is
refused until it is listed. load() raises ValueError and nothing else for a refused document.
"""
import json

MAX_BYTES = 2 << 20

# A rule is a JSON type, [rule] for an array of that rule, or a dict for an object with only these keys (all may be missing
# unless required below). list and dict as rules: only the every-depth rules apply inside.
PIN = {"tag": str, "commit": str}
REMOTE = {"fromLine": str, "kustomization": str, "repo": str, "directory": str, "pins": [PIN]}
PATH = {"path": str, "match": str, "guard": str, "directory": bool, "recursive": bool, "optional": bool}
TARGET = dict.fromkeys(("project", "catalog", "name", "repo", "component", "factProject", "releaseScheme", "minFrom",
                        "declaredChannel", "constructorProfile"), str)
TARGET.update(attest=bool, profileAttestation=bool, tagPrefixes=[str], paths=[PATH], exclude=list, generation=list,
              channels=list, sourceGrants=list, literalKustomization=dict, remote=REMOTE)
TOP = {"schema": str, "target": TARGET}


def _object(pairs):
    seen, value = set(), {}
    for key, item in pairs:
        if not key.isascii():
            raise ValueError("non-ASCII key")
        if key.lower() in seen:
            raise ValueError("duplicate key %r" % key[:80])
        seen.add(key.lower())
        value[key] = item
    return value


def _number(_):
    raise ValueError("numbers are not allowed")


def _surrogates(value):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeError:
                raise ValueError("unpaired surrogate") from None
        elif isinstance(item, dict):
            stack.extend(item.values())  # keys are ASCII
        elif isinstance(item, list):
            stack.extend(item)


def _check(value, rule, where):
    kind = rule if isinstance(rule, type) else type(rule)
    if type(value) is not kind:
        raise ValueError("%s has the wrong type" % where)
    if isinstance(rule, list):
        for item in value:
            _check(item, rule[0], where + "[]")
    elif isinstance(rule, dict):
        for key, item in value.items():
            if key not in rule:
                raise ValueError("%s has the unknown key %r" % (where, key[:80]))
            if key == "remote" and item is None:  # the only member that may be null
                continue
            _check(item, rule[key], where + "." + key)


def load(raw: bytes) -> dict:
    if not isinstance(raw, bytes):
        raise ValueError("no document")
    if len(raw) > MAX_BYTES:
        raise ValueError("document exceeds the size limit")
    text = raw.decode("utf-8")  # never json.loads on bytes: it would guess UTF-16/32 and skip a byte-order mark
    if text.startswith("﻿"):
        raise ValueError("byte-order mark")
    try:
        value = json.loads(text, object_pairs_hook=_object, parse_int=_number, parse_float=_number, parse_constant=_number)
    except RecursionError:
        raise ValueError("nesting exceeds the limit") from None
    _surrogates(value)
    _check(value, TOP, "document")
    if "target" not in value:
        raise ValueError("document has no target")
    return value
