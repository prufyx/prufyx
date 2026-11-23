#!/usr/bin/env python3
"""Deterministic check of a project-check rule renewal (base..head), fail closed.

usage: renewal_check.py --src DIR --base REF --head REF --maintainer CMD --out FILE [--runner CMD] [--now RFC3339]

A renewal is a change of cli/internal/projectcheck/data/rules.json that only moves evidence.reviewedAt/validUntil of
existing rules. For every changed rule id this checks, with the repository's own verifiers (never reimplemented):
  1. the entry differs from base ONLY in evidence.reviewedAt and evidence.validUntil, both strictly later, validUntil
     after reviewedAt, the window within the pack's 90-day limit, reviewedAt not after --now;
  2. a community approval exists at head and `prufyx-maintainer approval verify` accepts it for that rule against the
     base and head packs (it binds the candidate digest of the new entry and the signature), with the owner keys read
     from the BASE tree;
  3. `prufyx-maintainer corpus-attestation check --pack community --tree SRC` accepts the committed attestation
     (packDigest and ruleSetDigest recomputed from the head rules).
Result cases (suite "rules", key "renewal|..."): a failed check is a mismatch, a check that could not run is an error;
"renewal|summary" is always written exactly once. Exit 0 whenever the cases were written.
MAINTAINER must be built from the BASE tree (run.sh does that), and the diff base..head may only touch the project-check
rules, its attestation, community approval records and documentation: any other changed path is a mismatch.
"""
import argparse, copy, datetime, json, os, re, shlex, subprocess, sys, tempfile

RULES = "cli/internal/projectcheck/data/rules.json"
KEYS = "cli/knowledge/trust/web-approval-keys.json"
APPROVALS = "cli/knowledge/approvals/community/"
ATTEST = "cli/internal/projectcheck/data/corpus-attestation.json"
ALLOWED = re.compile(r"cli/knowledge/approvals/community/[^/]+\.json|[^/]+\.md|cli/docs/.+|changelog\.d/.+")
ALLOWED_EXACT = {RULES, ATTEST}
MAX_WINDOW = datetime.timedelta(days=90)  # projectcheck.go: validUntil - reviewedAt <= 90 days
TIMEOUT = 300


class Fail(Exception):
    """A check ran and the renewal is not acceptable (mismatch)."""


class Broken(Exception):
    """The check could not run (error)."""


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Broken("duplicate JSON member")
        out[k] = v
    return out


def parse(raw):
    if raw is None or len(raw) > 16 * 1024 * 1024:
        raise Broken("missing or oversized JSON")
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda n: (_ for _ in ()).throw(Broken(n)))
    except (ValueError, RecursionError) as e:
        raise Broken("unparseable JSON: %s" % e)


def show(src, ref, path):
    r = subprocess.run(["git", "-C", src, "show", ref + ":" + path], capture_output=True, timeout=TIMEOUT)
    if r.returncode:
        raise Broken("cannot read %s at %s" % (path, ref[:12]))
    return r.stdout


def when(v, what):
    if not isinstance(v, str):
        raise Fail(what + " is not a timestamp")
    try:
        return datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Fail(what + " is not RFC 3339 UTC")


def entries(doc):
    es = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(es, list):
        raise Broken("entries not a list")
    out = {}
    for e in es:
        rid = e["rule"]["id"] if isinstance(e, dict) and isinstance(e.get("rule"), dict) else None
        if not isinstance(rid, str) or not rid or rid in out:
            raise Broken("entry id")
        out[rid] = e
    return out


def canon(v):
    return json.dumps(v, sort_keys=True, allow_nan=False)


def rule_window(base, head, now):
    """Check 1 for one entry pair: evidence sits at entry.rule.evidence."""
    stripped, stamps = [], []
    for side in (base, head):
        s = copy.deepcopy(side)
        ev = s["rule"].get("evidence") if isinstance(s.get("rule"), dict) else None
        if not isinstance(ev, dict):
            raise Fail("evidence object missing")
        stamps.append((ev.pop("reviewedAt", None), ev.pop("validUntil", None)))
        stripped.append(s)
    if canon(stripped[0]) != canon(stripped[1]):
        raise Fail("entry changed beyond evidence.reviewedAt/validUntil")
    ob, nb = when(stamps[0][0], "base reviewedAt"), when(stamps[1][0], "head reviewedAt")
    ou, nu = when(stamps[0][1], "base validUntil"), when(stamps[1][1], "head validUntil")
    if not (nb > ob and nu > ou):
        raise Fail("reviewedAt and validUntil must both move forward")
    if not nu > nb:
        raise Fail("validUntil is not after reviewedAt")
    if nu - nb > MAX_WINDOW:
        raise Fail("validity window exceeds 90 days")
    if now is not None and nb > now:
        raise Fail("reviewedAt is in the future")


def run(cmd, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=TIMEOUT, **kw)
    except (OSError, subprocess.SubprocessError) as e:
        raise Broken("cannot run %s: %s" % (cmd[-1] if cmd else "?", e))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--maintainer", required=True)
    ap.add_argument("--runner", default="")
    ap.add_argument("--now", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cases = []

    def add(key, state, why=""):
        cases.append({"suite": "rules", "key": "renewal|" + key, "wrongpass": False,
                      "mismatch": state == "mismatch", "error": state == "error",
                      "detail": {"why": why[:300]} if why else {}})

    summary = "ok"
    try:
        now = when(a.now, "--now") if a.now else None
        base_raw, head_raw = show(a.src, a.base, RULES), show(a.src, a.head, RULES)
        base, head = parse(base_raw), parse(head_raw)
        r = subprocess.run(["git", "-C", a.src, "diff", "--name-only", "--no-renames", "-z", a.base, a.head],
                           capture_output=True, timeout=TIMEOUT)
        if r.returncode:
            raise Broken("cannot list the changed paths")
        paths = [x.decode("utf-8", "replace") for x in r.stdout.split(b"\0") if x]
        outside = [x for x in paths if x not in ALLOWED_EXACT and not ALLOWED.fullmatch(x)]
        if outside:
            raise Fail("diff touches paths beyond a renewal: " + ", ".join(sorted(outside)[:3]))
        be, he = entries(base), entries(head)
        changed = sorted(i for i in set(be) | set(he) if canon(be.get(i)) != canon(he.get(i)))
        attest_changed = show(a.src, a.base, "cli/internal/projectcheck/data/corpus-attestation.json") != \
            show(a.src, a.head, "cli/internal/projectcheck/data/corpus-attestation.json")
        if not changed and not attest_changed:
            raise Fail("no project-check rule changed: nothing is renewed")
        with tempfile.TemporaryDirectory(prefix="renewal-", dir=os.environ.get("QA_TMP") or None) as tmp:
            bp, hp, kp = (os.path.join(tmp, n) for n in ("base-pack.json", "head-pack.json", "keys.json"))
            for path, raw in ((bp, base_raw), (hp, head_raw), (kp, show(a.src, a.base, KEYS))):
                with open(path, "wb") as f:
                    f.write(raw)
            tool = shlex.split(a.runner) + shlex.split(a.maintainer)
            r = run(tool + ["approval", "keys-digest", "--keys", kp])
            kd = r.stdout.decode().strip()
            if r.returncode or not kd.startswith("sha256:"):
                raise Broken("keys-digest failed")
            for rid in changed:
                try:
                    if rid not in be or rid not in he:
                        raise Fail("rule added or removed, not renewed")
                    rule_window(be[rid], he[rid], now)
                    ap_raw = show(a.src, a.head, APPROVALS + rid + ".json") if _exists(a.src, a.head, APPROVALS + rid + ".json") else None
                    if ap_raw is None:
                        raise Fail("no community approval at head")
                    apath = os.path.join(tmp, "approval.json")
                    with open(apath, "wb") as f:
                        f.write(ap_raw)
                    cmd = tool + ["approval", "verify", "--approval", apath, "--pack", "community", "--rule", rid,
                                  "--base-pack", bp, "--head-pack", hp, "--keys", kp, "--keys-digest", kd]
                    if a.now:
                        cmd += ["--now", a.now]
                    v = run(cmd)
                    if v.returncode == 1:
                        raise Fail("approval refused: " + v.stderr.decode(errors="replace").strip()[:200])
                    if v.returncode:
                        raise Broken("approval verify exit %d" % v.returncode)
                    add(rid, "ok")
                except Fail as e:
                    add(rid, "mismatch", str(e)); summary = "mismatch"
                except Broken as e:
                    add(rid, "error", str(e)); summary = "error" if summary == "ok" else summary
            c = run(tool + ["corpus-attestation", "check", "--pack", "community", "--tree", a.src])
            if c.returncode == 0:
                add("attestation", "ok")
            else:
                add("attestation", "mismatch", "attestation does not match the head rules (exit %d)" % c.returncode)
                summary = "mismatch"
    except Fail as e:
        add("input", "mismatch", str(e)); summary = "mismatch"
    except Broken as e:
        add("input", "error", str(e)); summary = "error"
    except Exception as e:  # anything unforeseen is an errored check, never a silent pass
        add("input", "error", "unexpected: %s" % e); summary = "error"
    add("summary", summary if summary != "ok" else "ok", "" if summary == "ok" else "renewal check " + summary)
    # the summary case must itself carry the failure so a consumer that only counts it still fails closed
    with open(a.out, "w") as f:
        json.dump(cases, f)
    return 0


def _exists(src, ref, path):
    r = subprocess.run(["git", "-C", src, "cat-file", "-e", ref + ":" + path], capture_output=True, timeout=TIMEOUT)
    return r.returncode == 0


if __name__ == "__main__":
    sys.exit(main())
