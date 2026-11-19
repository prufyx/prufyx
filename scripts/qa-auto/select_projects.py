#!/usr/bin/env python3
"""Decide what a run must cover from the files changed since the last green sha.

usage: select_projects.py --changed FILE --src DIR     (FILE: git diff --name-only, one path per line)
prints {"db": bool (db-related path changed: run the db suite), "mode": "full|incremental|none", "projects": [...], "relevant": bool, "reasons": [...]}
  target-<p>.json            -> project p
  knowledge / data / lines   -> projects whose slug is in the path, else full
  any other cli/** or scripts/qa-auto/** -> full (the scanner or this harness changed)
  docs, tests, changelog ... -> ignored
"""
import argparse, glob, json, os, re, subprocess

RULES = "cli/internal/cncfcheck/data/rules.json"
ATTEST = "cli/internal/cncfcheck/data/corpus-attestation.json"
RULES_COMMUNITY = "cli/internal/projectcheck/data/rules.json"
ATTEST_COMMUNITY = "cli/internal/projectcheck/data/corpus-attestation.json"
AGGREGATE = (RULES, ATTEST, RULES_COMMUNITY, ATTEST_COMMUNITY)
RULES_PATHS = (RULES, RULES_COMMUNITY)
RULES_OF = {ATTEST: RULES, ATTEST_COMMUNITY: RULES_COMMUNITY}
APPROVAL = re.compile(r"cli/knowledge/approvals/(cncf|community)/([a-z0-9]+(?:-[a-z0-9]+)*)\.[^/]+")
SLUG = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
RULES_META = {"revision", "policyDigest", "landscapeFileDigest", "registryDigest"}
RULES_KEYED = {"lineAttestations": ("component", "line", "factFamily"),
               "servedAPIs": ("component", "line"), "pathPolicies": ("component", "policy")}
ATTEST_META = {"revision", "packDigest", "ruleSetDigest", "ruleCount"}


class Unattributable(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Unattributable("duplicate JSON member")
        out[k] = v
    return out


def _const(name):
    raise Unattributable("non-finite number " + name)


def _canon(v):
    # type-exact comparison: true != 1, 1 != 1.0
    return json.dumps(v, sort_keys=True, allow_nan=False)


def _load(raw):
    if raw is None or len(raw) > 16 * 1024 * 1024:
        raise Unattributable("missing or oversized JSON")
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_const)
    except (ValueError, RecursionError) as e:
        raise Unattributable("unparseable JSON: %s" % e)


def _need(cond, why):
    if not cond:
        raise Unattributable(why)


def _entries(doc):
    es = doc.get("entries")
    _need(isinstance(es, list), "entries not a list")
    out = {}
    for e in es:
        _need(isinstance(e, dict) and isinstance(e.get("rule"), dict), "entry shape")
        rid, proj = e["rule"].get("id"), e.get("project")
        _need(isinstance(rid, str) and rid and rid not in out, "entry id")
        _need(isinstance(proj, str) and SLUG.fullmatch(proj), "entry project")
        out[rid] = e
    return out


def _component_map(entry_sets):
    m = {}
    for es in entry_sets:
        for e in es.values():
            facts = e.get("requiredFacts", [])
            _need(isinstance(facts, list), "requiredFacts shape")
            for f in facts:
                _need(isinstance(f, dict) and isinstance(f.get("component"), str), "fact shape")
                m.setdefault(f["component"], set()).add(e["project"])
    return m


def _attribute(component, cmap, known, trusted):
    """Union of every trusted binding (base target purl, base entries, last-segment slug); empty => unattributable."""
    _need(isinstance(component, str), "component shape")
    got = set(cmap.get(component, ())) | ({trusted[component]} if component in trusted else set())
    last = component.rsplit("/", 1)[-1]
    if last in known:
        got.add(last)
    _need(got, "component not attributable: " + component[:80])
    return got


def _keyed(doc, name, fields):
    items = doc.get(name)
    _need(isinstance(items, list), name + " not a list")
    out = {}
    for it in items:
        _need(isinstance(it, dict), name + " item shape")
        key = tuple(it.get(f) for f in fields)
        _need(all(isinstance(k, str) and k for k in key) and key not in out, name + " key")
        out[key] = it
    return out


def _changed_keys(a, b):
    return [k for k in set(a) | set(b) if (_canon(a[k]) if k in a else None) != (_canon(b[k]) if k in b else None)]


def aggregate_projects(path, old_raw, new_raw, slugs, rules_pair=None, trusted=None, catalogue=()):
    """Projects whose entries differ between old and new aggregate data file; raises Unattributable (=> full)."""
    old, new = _load(old_raw), _load(new_raw)
    _need(isinstance(old, dict) and isinstance(new, dict) and set(old) == set(new), "top-level shape differs")
    _need(_canon(old.get("schema")) == _canon(new.get("schema")) and isinstance(new.get("schema"), str), "schema differs")
    if rules_pair is None:
        rules_pair = (old, new) if path in RULES_PATHS else None
    _need(rules_pair is not None, "rules.json unavailable")
    _need(isinstance(trusted, dict), "no trusted base component bindings")
    oe, ne = _entries(rules_pair[0]), _entries(rules_pair[1])
    cmap = _component_map([oe])  # base entries only: the PR cannot bind components
    known = set(slugs) | {e["project"] for e in oe.values()} | set(catalogue)
    found = set()
    if path in RULES_PATHS:
        for k in set(old) - {"schema", "entries"} - RULES_META - set(RULES_KEYED):
            _need(_canon(old[k]) == _canon(new[k]), "unknown section changed: " + str(k)[:40])
        for k in RULES_META & (set(old) | set(new)):
            _need(isinstance(old.get(k), str) and isinstance(new.get(k), str), "metadata shape")
        for rid in _changed_keys(oe, ne):
            for side in (oe, ne):
                if rid in side:
                    _need(side[rid]["project"] in known, "entry project unknown: " + side[rid]["project"])
                    _need(side[rid]["project"] in set(slugs) | set(catalogue) or rid in ne, "removed entry of a project outside the catalogue")
                    found.add(side[rid]["project"])
        for name, fields in RULES_KEYED.items():
            if name not in old:
                continue
            ok, nk = _keyed(old, name, fields), _keyed(new, name, fields)
            for key in _changed_keys(ok, nk):
                found |= _attribute(key[0], cmap, known, trusted)
    else:
        for k in set(old) - {"schema", "components"} - ATTEST_META:
            _need(_canon(old[k]) == _canon(new[k]), "unknown section changed: " + str(k)[:40])
        for k in ATTEST_META:
            _need(isinstance(old.get(k), (str, int)) and isinstance(new.get(k), (str, int)), "metadata shape")
        oc, nc = old.get("components"), new.get("components")
        _need(isinstance(oc, list) and isinstance(nc, list), "components shape")
        _need(all(isinstance(c, str) for c in oc + nc) and len(set(oc)) == len(oc) and len(set(nc)) == len(nc), "components shape")
        for c in set(oc) ^ set(nc):
            found |= _attribute(c, cmap, known, trusted)
    return found & set(slugs)


def _approval_rule_project(path, group, prefix, reader):
    """File prefix is not a project id: resolve the approved rule id to its head rules.json entry's project; None on any doubt."""
    if reader is None:
        return None
    try:
        rule_id = _load(reader(path)[1])["record"]["ruleId"]
        rules = _load(reader(RULES if group == "cncf" else RULES_COMMUNITY)[1])
        _need(isinstance(rule_id, str) and rule_id.startswith(prefix + "."), "approval rule id")
        return _entries(rules)[rule_id]["project"]
    except (Unattributable, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        return None


def selection(changed, slugs, reader=None, trusted=None, catalogue=()):
    """reader(path) -> (base_bytes|None, head_bytes|None); without one, aggregate data files stay full."""
    projects, reasons, full, db = set(), [], False, False
    DBRE = re.compile(r"^cli/(internal/)?(knowledge|[a-z]*db[a-z]*)")
    for p in changed:
        if not p:
            continue
        if DBRE.search(p) and not re.search(r"_test\.go$|\.md$|/docs/", p):
            db = True
        m = re.fullmatch(r"cli/internal/extract/crdversions/target-(.+)\.json", p)
        if m:
            try:
                gone = reader is not None and reader(p)[1] is None
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                gone = True
            if gone:
                full = True; reasons.append("target removed or unreadable " + p); continue
            projects.add(m.group(1)); reasons.append("target " + m.group(1)); continue
        if re.fullmatch(r"cli/docs/generated/[^/]+", p) and not (RULES in changed or RULES_COMMUNITY in changed):
            full = True; reasons.append("generated file changed without rules.json " + p); continue
        am = APPROVAL.fullmatch(p)
        if not am and p.startswith("cli/knowledge/approvals/"):
            full = True; reasons.append("approval path of unknown shape " + p); continue
        if am:
            # approval file <project>.<rule>.json: the project is the first dotted segment, and must be a known catalogue id
            first = am.group(2)
            if first not in slugs and first not in catalogue:
                first = _approval_rule_project(p, am.group(1), first, reader) or first
            if first in slugs:
                projects.add(first); reasons.append("approval " + first)
            elif first in catalogue and SLUG.fullmatch(first):
                reasons.append("approval (catalogue project without QA target) " + first)
            else:
                full = True; reasons.append("approval (unknown project) " + p)
            continue
        if re.search(r"coveragereport/testdata/lines-.*\.json$", p) or re.search(r"(^|/)(knowledge|data)/", p):
            hit = [s for s in slugs if s in p]
            if p in AGGREGATE:
                if reader is None:
                    full = True; reasons.append("data aggregate, no diff objects " + p); continue
                try:
                    old, new = reader(p)
                    pair = None
                    if p in RULES_OF:
                        r_old, r_new = reader(RULES_OF[p])
                        pair = (_load(r_old), _load(r_new))
                    got = aggregate_projects(p, old, new, slugs, pair, trusted, catalogue)
                except (Unattributable, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as e:
                    full = True; reasons.append("data aggregate unattributable (%s) %s" % (e, p)); continue
                projects.update(got); reasons.append("data aggregate %s -> %s" % (p, sorted(got))); continue
            if hit:
                projects.update(hit); reasons.append("data " + p)
            else:
                full = True; reasons.append("data (no project in path) " + p)
            continue
        if p.startswith("scripts/qa-auto/") and not p.endswith(".md"):
            full = True; reasons.append("tooling " + p); continue
        if re.search(r"(^|/)(testdata|docs|changelog\.d|\.github)/|\.md$|_test\.go$|^(LICENSES|NOTICE|THIRD-PARTY|SOURCE-PREVIEW)", p):
            continue
        if p.startswith("cli/") or p.startswith("scripts/qa-auto/"):
            full = True; reasons.append("code/tooling " + p)
    mode = "full" if full else ("incremental" if projects else "none")
    return {"mode": mode, "projects": sorted(projects), "relevant": mode != "none", "db": db, "reasons": reasons[:20]}


if __name__ == "__main__":
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--changed", required=True)
    ap.add_argument("--src", required=True)
    a = ap.parse_args()
    changed = open(a.changed).read().splitlines()
    slugs = sorted(re.sub(r"^target-|\.json$", "", os.path.basename(p))
                   for p in glob.glob(a.src + "/cli/internal/extract/crdversions/target-*.json"))
    reader = trusted = None
    if os.environ.get("QA_BASE"):
        # -I excludes the script directory; import only this trusted companion.
        sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
        import qa_batch_scope
        reader = qa_batch_scope.diff_reader(a.src, qa_batch_scope.BASE_REF, qa_batch_scope.HEAD_REF)
        try:
            trusted = qa_batch_scope.base_components(a.src, qa_batch_scope.BASE_REF)
        except (ValueError, OSError, subprocess.SubprocessError):
            trusted = None
    catalogue = set()
    if os.environ.get("QA_BASE"):
        catalogue = qa_batch_scope.base_catalogue(a.src, qa_batch_scope.BASE_REF)
    else:
        sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
        import qa_batch_scope
        try:
            catalogue = qa_batch_scope.catalogue_from([open(os.path.join(a.src, f), "rb").read() for f in qa_batch_scope.CATALOGUE_FILES])
        except OSError:
            catalogue = set()
    selected = selection(changed, slugs, reader, trusted, catalogue)
    if os.environ.get("QA_BASE"):
        try:
            if (os.environ.get("QA_SCOPE_HEAD_REF") != qa_batch_scope.HEAD_REF or
                    os.environ.get("QA_SCOPE_BASE_REF") != qa_batch_scope.BASE_REF):
                raise ValueError("SCOPE_PROVENANCE: fixed refs required")
            head, base = os.environ.get("QA_SHA", ""), os.environ["QA_BASE"]
            actual = qa_batch_scope.git(a.src, "diff", "--name-only", "--no-renames", base, head).splitlines()
            if changed != actual:
                raise ValueError("SCOPE_PROVENANCE: caller diff differs from fixed objects")
            frozen = qa_batch_scope.environment_contract()
            extra = frozen["extra_projects"] if frozen else [p for p in os.environ.get("QA_PROJECTS", "").split(",") if p]
            contract = qa_batch_scope.freeze(a.src, head, base, os.environ.get("QA_RUN_ID", ""), extra)
            if frozen is not None and frozen != contract:
                raise ValueError("SCOPE_MISMATCH: fetched contract differs from trusted parent")
            selected.update(projects=contract["projects"], batch_scope=contract)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            ap.exit(3, "SCOPE_INVALID: " + str(error) + "\n")
    print(json.dumps(selected))
