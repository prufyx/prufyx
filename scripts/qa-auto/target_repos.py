#!/usr/bin/env python3
"""Which upstream repos a head may add as CRD version targets in gate mode (fail closed).

usage: target_repos.py --src DIR --base SHA --changed FILE [--maintainer CMD [--runner CMD] --now RFC3339]

A target-*.json decides which upstream repo the CRD oracle clones, so a head may not change a base target's repo and may add
a new target only for a repo that is already a target repo at the base, listed in QA_GATE_REPOS (comma list owner/name), or
derived from a signed onboarding batch: the head adds exactly one cli/knowledge/onboarding/<id>.json, the maintainer tool
compiled from the BASE tree (`approval verify --onboarding-signature`: strict decoding, pinned key from the base key file,
identity tier, validity window) accepts its signature, and the batch's signed artifact list names the new target path with the
sha256 of the head's bytes. The signature binds the target bytes and so the repo. The full batch checks (trees, landscape repo,
admission history, dry run) stay with the Knowledge gate; this script only decides whether the oracle may clone the named repo.

Every target of the base must be a regular file (100644 blob) at the same path at the head, whether or not the changed list
names it: a removed, renamed or retyped base target is refused, and neither a signed batch nor QA_GATE_REPOS admits it. A changed
target whose head bytes cannot be read is refused too.

Exit 0: every target change is allowed (nothing printed). Exit 1: refused, one line of reasons on stdout.
Exit 4: only new unknown repos remain and no --maintainer was given: stdout is empty, the caller prepares the maintainer from
the base tree and runs again with --maintainer. Any error is exit 1 (never 0).
"""
import argparse, hashlib, json, os, re, shlex, subprocess, sys, tempfile

# -I excludes the script directory; import only this trusted companion.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import crd_inventory

TD = crd_inventory.TD
TARGET = crd_inventory.TARGET
BATCH_DIR = "cli/knowledge/onboarding/"
BATCH = re.compile(re.escape(BATCH_DIR) + r"(ob-[0-9]{8}-[0-9]{1,3})\.json", re.A)
KEYS = "cli/knowledge/trust/web-approval-keys.json"
TIMEOUT = 120


class Refuse(Exception):
    pass


def git(src, *args):
    return subprocess.run(["git", "-C", src, *args], capture_output=True, timeout=TIMEOUT)


def show(src, rev, path):
    r = git(src, "show", f"{rev}:{path}")
    return None if r.returncode else r.stdout


def listing(src, rev):
    r = git(src, "ls-tree", "-r", "-z", rev, "--", TD)
    if r.returncode:
        raise ValueError("tree listing failed")
    return r.stdout


def repo_of(raw):
    # strict UTF-8, no byte-order mark: json.loads on bytes would also guess UTF-16/32 and skip a BOM; on str it refuses U+FEFF
    r = json.loads(raw.decode("utf-8"))["target"]["repo"]
    r = r[len("github.com/"):] if r.startswith("github.com/") else r
    if not re.fullmatch(r"[A-Za-z0-9_][\w.-]*/[A-Za-z0-9_][\w.-]*", r, re.A):
        raise ValueError("bad repo")
    return r


def derive(a, changed):
    """Return {path: digest} that a signed batch added by the head commits to; raise Refuse on anything else."""
    added = [p for p in changed if BATCH.fullmatch(p) and show(a.src, a.base, p) is None and show(a.src, "HEAD", p) is not None]
    if len(added) != 1:
        raise Refuse("no single signed onboarding batch added (%d)" % len(added))
    keys = show(a.src, a.base, KEYS)
    if keys is None:
        raise Refuse("no base key file")
    tool = shlex.split(a.runner or "") + shlex.split(a.maintainer)
    with tempfile.TemporaryDirectory(prefix="targets-", dir=os.environ.get("QA_TMP") or None) as tmp:
        kp = os.path.join(tmp, "keys.json")
        bp = os.path.join(tmp, os.path.basename(added[0]))
        with open(kp, "wb") as f:
            f.write(keys)
        with open(bp, "wb") as f:
            f.write(show(a.src, "HEAD", added[0]))
        r = subprocess.run(tool + ["approval", "keys-digest", "--keys", kp], capture_output=True, timeout=TIMEOUT)
        kd = r.stdout.decode().strip()
        if r.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", kd):
            raise Refuse("keys-digest failed")
        r = subprocess.run(tool + ["approval", "verify", "--onboarding-signature", bp, "--keys", kp, "--keys-digest", kd,
                                   "--now", a.now], capture_output=True, timeout=TIMEOUT)
        if r.returncode:
            raise Refuse("batch signature refused (exit %d)" % r.returncode)
        lines = [l for l in r.stdout.decode("utf-8", "replace").split("\n") if l]
        if len(lines) != 1:
            raise Refuse("unreadable signature report")
        rep = json.loads(lines[0])
    signed = {}
    for art in rep["artifacts"]:
        if signed.setdefault(art["path"], art["digest"]) != art["digest"]:
            raise Refuse("batch lists a path twice")
    return signed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--changed", required=True)
    ap.add_argument("--maintainer")
    ap.add_argument("--runner")
    ap.add_argument("--now")
    a = ap.parse_args()
    if a.maintainer and not a.now:
        print("target check failed: --now is required with --maintainer")
        sys.exit(1)
    bad = []
    try:
        known = {x.strip() for x in os.environ.get("QA_GATE_REPOS", "").split(",") if x.strip()}
        base_ls = listing(a.src, a.base)
        # first, and independent of --changed: no base target may disappear from the head
        gone = crd_inventory.removed_targets(base_ls, listing(a.src, "HEAD"))
        bad.extend(f"{p}: base target removed or not a regular file" for p in gone)
        for f in sorted(crd_inventory.listing(base_ls)):
            if TARGET.fullmatch(f):
                t = show(a.src, a.base, f)
                try:
                    known.add(repo_of(t))
                except Exception:
                    raise ValueError("base target unreadable")
        changed = [p for p in open(a.changed).read().split("\n") if p]
        unknown = {}
        for p in changed:
            if not TARGET.fullmatch(p) or p in gone:  # gone: already refused above; its head bytes are not a target
                continue
            head = show(a.src, "HEAD", p)
            if head is None:
                bad.append(f"{p}: target check failed (head unreadable)")  # never read as a deletion
                continue
            hr = repo_of(head)
            old = show(a.src, a.base, p)
            if old is not None:
                if repo_of(old) != hr:
                    bad.append(f"{p}: repo changed")
            elif hr not in known:
                unknown[p] = (hr, "sha256:" + hashlib.sha256(head).hexdigest())
        if unknown and not bad:
            if not a.maintainer:
                sys.exit(4)
            try:
                signed = derive(a, changed)
                for p, (hr, dg) in unknown.items():
                    if signed.get(p) != dg:
                        bad.append(f"{p}: new repo {hr} not in a signed onboarding batch")
            except Refuse as e:
                bad.extend(f"{p}: new repo {hr} not known ({e})" for p, (hr, _) in unknown.items())
        elif unknown:
            bad.extend(f"{p}: new repo {hr} not known" for p, (hr, _) in unknown.items())
        print(" ".join(bad[:10]))
        sys.exit(1 if bad else 0)
    except SystemExit:
        raise
    except Exception as e:
        print(f"target check failed: {type(e).__name__}")
        sys.exit(1)


if __name__ == "__main__":
    main()
