#!/usr/bin/env python3
"""Reference implementation of the pathset digest (stdlib only).

Not run by the Go tests. Run by hand:  python3 -I pathset_ref.py vectors.json
Exits 0 when every vector matches, 1 otherwise. Any other implementation
(for example a Python consumer) must produce exactly these results.
"""
import hashlib
import json
import sys

MAX_PATHS = 10000
MAX_PATH_BYTES = 4096


def valid(paths):
    """Return the error class for an invalid set, or None."""
    if len(paths) == 0:
        return "empty-set"
    if len(paths) > MAX_PATHS:
        return "too-many-paths"
    # Precedence per path, same as the Go implementation: empty, length,
    # newline, NUL, UTF-8, duplicate. A Python str cannot hold arbitrary
    # invalid UTF-8 bytes, so "invalid-utf8" is only reachable for lone
    # surrogates here; the Go tests cover raw invalid bytes (JSON cannot).
    seen = set()
    for p in paths:
        if p == "":
            return "empty-path"
        if len(p.encode("utf-8", "surrogatepass")) > MAX_PATH_BYTES:
            return "path-too-long"
        if "\n" in p:
            return "newline"
        if "\x00" in p:
            return "nul"
        try:
            p.encode("utf-8")
        except UnicodeEncodeError:
            return "invalid-utf8"
        if p in seen:
            return "duplicate"
        seen.add(p)
    return None


def digest(paths):
    """Return (digest, None) or (None, error class)."""
    err = valid(paths)
    if err:
        return None, err
    ordered = sorted(paths, key=lambda p: p.encode("utf-8"))
    h = hashlib.sha256("\n".join(ordered).encode("utf-8")).hexdigest()
    return "sha256:" + h, None


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        vectors = json.load(f)["vectors"]
    bad = 0
    for v in vectors:
        got, err = digest(v["paths"])
        if v.get("error"):
            ok = err == v["error"] and got is None
        else:
            ok = err is None and got == v["digest"]
        if not ok:
            bad += 1
            print("MISMATCH", v["name"], got, err)
    print("vectors", len(vectors), "mismatches", bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
