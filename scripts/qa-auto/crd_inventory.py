"""CRD version targets that exist at the base of a change must still exist at its head.

Pure functions over `git ls-tree -r -z` bytes. Strict: anything malformed raises ValueError.
"""
import re

TD = "cli/internal/extract/crdversions/"
TARGET = re.compile(re.escape(TD) + r"target-[\w.-]+\.json", re.A)
ENTRY = re.compile(rb"([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40}|[0-9a-f]{64})\t([^\0]+)")
REGULAR = ("100644", "blob")


def listing(raw):
    """`git ls-tree -r -z` output -> {path: (mode, type)}."""
    if not isinstance(raw, bytes):
        raise ValueError("tree listing is not bytes")
    if not raw:
        return {}
    if not raw.endswith(b"\0"):
        raise ValueError("tree listing is truncated")
    out = {}
    for record in raw[:-1].split(b"\0"):
        m = ENTRY.fullmatch(record)
        if not m:
            raise ValueError("unreadable tree listing entry")
        # a name that is not UTF-8 stays distinct and can never match TARGET (ASCII)
        path = m.group(4).decode("utf-8", "surrogateescape")
        if path in out:
            raise ValueError("tree listing names a path twice")
        out[path] = (m.group(1).decode(), m.group(2).decode())
    return out


def removed_targets(base_ls, head_ls):
    """Sorted base target paths that are not a regular file (100644 blob) at the same path at the head."""
    base, head = listing(base_ls), listing(head_ls)
    return sorted(p for p in base if TARGET.fullmatch(p) and head.get(p) != REGULAR)
