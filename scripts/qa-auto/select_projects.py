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
RULES_KEYED = {"lineAttestations": ("component", "line", "factFamily"),
               "servedAPIs": ("component", "line"), "pathPolicies": ("component", "policy")}
RULES_META = {"revision", "policyDigest", "landscapeFileDigest", "registryDigest"}
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


def _comps(entry):
    facts = entry.get("requiredFacts", [])
    _need(isinstance(facts, list), "requiredFacts shape")
    out = set()
    for f in facts:
        _need(isinstance(f, dict) and isinstance(f.get("component"), str), "fact shape")
        out.add(f["component"])
    return out


def _closure(entry_sets, seed_ids, seed_comps, trusted, known):
    """Projects reachable from the seeds through shared components, transitively and in both directions.

    An entry joins when one of its requiredFacts components is already in the set (so the changed entry's referenced
    components' entries, and every entry that requires the changed entry's components, are both covered); the
    component's own target binding and last-segment slug join too. The result must be a subset of the QA slugs (checked
    by the caller); any malformed data raises Unattributable (=> full)."""
    _need(isinstance(trusted, dict), "no trusted base component bindings")
    pool = []
    for es in entry_sets:
        pool.extend(es.values())
    comps, projects = set(seed_comps), set()
    for es in entry_sets:
        for rid in seed_ids:
            if rid in es:
                projects.add(es[rid]["project"])
                comps |= _comps(es[rid])
    grown = True
    while grown:
        grown = False
        for e in pool:
            ec = _comps(e)
            if (ec & comps) and (not ec <= comps or e["project"] not in projects):
                comps |= ec
                projects.add(e["project"])
                grown = True
    for c in comps:
        if c in trusted:
            projects.add(trusted[c])
        last = c.rsplit("/", 1)[-1]
        if last in known:
            projects.add(last)
    return projects


def _only_targets(projects, slugs):
    gone = set(projects) - set(slugs)
    _need(not gone, "project without a QA target: " + ",".join(sorted(gone))[:80])
    return set(projects)


def aggregate_projects(path, old_raw, new_raw, slugs, rules_pair=None, trusted=None, catalogue=(), strict=False):
    """Projects whose entries differ between old and new aggregate data file; raises Unattributable (=> full).

    strict (the batch-scope selector): pack-level changes, non-QA projects and the requiredFacts closure force full.
    The default keeps the older validator contract that k8s_oracle relies on."""
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
    found, seed_comps = set(), set()
    if path in RULES_PATHS:
        if strict:
            # Every pack-level key (revision, policyDigest, registryDigest, landscapeFileDigest, policyId, any other) must
            # be unchanged. No exceptions: renewals do not touch them (measured on the renewal PRs), so a change is a real
            # pack change that can alter every project.
            for k in set(old) - {"schema", "entries"} - set(RULES_KEYED):
                _need(_canon(old[k]) == _canon(new[k]), "pack-level field changed: " + str(k)[:40])
        else:
            for k in set(old) - {"schema", "entries"} - RULES_META - set(RULES_KEYED):
                _need(_canon(old[k]) == _canon(new[k]), "unknown section changed: " + str(k)[:40])
            for k in RULES_META & (set(old) | set(new)):
                _need(isinstance(old.get(k), str) and isinstance(new.get(k), str), "metadata shape")
        seed_ids = set()
        for rid in _changed_keys(oe, ne):
            seed_ids.add(rid)
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
                if strict and name == "lineAttestations":
                    for item in (ok.get(key), nk.get(key)):
                        ids = item.get("ruleIds", []) if item is not None else []
                        _need(isinstance(ids, list) and all(isinstance(i, str) for i in ids), "ruleIds shape")
                        for i in ids:
                            _need(i in oe or i in ne, "attestation rule id does not resolve: " + i[:60])
                            seed_ids.add(i)
                got = _attribute(key[0], cmap, known, trusted)
                if strict:
                    _need(got <= set(slugs), "keyed item of a project without a QA target: " + key[0][:60])
                found |= got
                seed_comps.add(key[0])
        if strict:
            found |= _closure([oe, ne], seed_ids, seed_comps, trusted, known)
    else:
        for k in set(old) - {"schema", "components"} - ATTEST_META:
            _need(_canon(old[k]) == _canon(new[k]), "unknown section changed: " + str(k)[:40])
        for k in ATTEST_META:
            _need(isinstance(old.get(k), (str, int)) and isinstance(new.get(k), (str, int)), "metadata shape")
        oc, nc = old.get("components"), new.get("components")
        _need(isinstance(oc, list) and isinstance(nc, list), "components shape")
        _need(all(isinstance(c, str) for c in oc + nc) and len(set(oc)) == len(oc) and len(set(nc)) == len(nc), "components shape")
        for c in set(oc) ^ set(nc):
            got = _attribute(c, cmap, known, trusted)
            if strict:
                _need(got <= set(slugs), "attestation component of a project without a QA target: " + c[:60])
            found |= got
            seed_comps.add(c)
        if strict:
            found |= _closure([oe, ne], (), seed_comps, trusted, known)
    return _only_targets(found, slugs) if strict else found & set(slugs)


def _approval_projects(path, group, reader, trusted, slugs, catalogue):
    """The file name prefix is never trusted: resolve the approved rule id in the BASE rules.json of the group, then take
    its project and the closure of its components. Any doubt (unreadable, id not in base, mismatch) raises."""
    _need(reader is not None, "no diff objects for approval")
    pair = reader(path)
    ids = set()
    for raw in pair:
        if raw is not None:
            rid = _load(raw)["record"]["ruleId"]
            _need(isinstance(rid, str) and rid, "approval rule id")
            ids.add(rid)
    _need(len(ids) == 1, "approval rule id missing or differs between base and head")
    rules_path = RULES if group == "cncf" else RULES_COMMUNITY
    base_rules = _entries(_load(reader(rules_path)[0]))
    rid = ids.pop()
    _need(rid in base_rules, "approval rule id not in base rules")
    known = set(slugs) | {e["project"] for e in base_rules.values()} | set(catalogue)
    got = _closure([base_rules], [rid], (), trusted, known)
    return _only_targets(got, slugs)


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
        # Derived files (generated docs, README, corpus-attestation) are not recomputed here: they are trusted only when a
        # rules.json changed in the same diff (the scoped entries then explain them); alone they force full.
        if (re.fullmatch(r"cli/docs/generated/[^/]+", p) or p == "README.md") and not (RULES in changed or RULES_COMMUNITY in changed):
            full = True; reasons.append("derived file changed without rules.json " + p); continue
        if p in RULES_OF and RULES_OF[p] not in changed:
            full = True; reasons.append("attestation changed without its rules.json " + p); continue
        if p == "README.md":
            continue
        am = APPROVAL.fullmatch(p)
        if not am and p.startswith("cli/knowledge/approvals/"):
            full = True; reasons.append("approval path of unknown shape " + p); continue
        if am:
            try:
                got = _approval_projects(p, am.group(1), reader, trusted, slugs, catalogue)
            except (Unattributable, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as e:
                full = True; reasons.append("approval unresolvable (%s) %s" % (e, p)); continue
            projects.update(got); reasons.append("approval %s -> %s" % (p, sorted(got))); continue
        if re.search(r"coveragereport/testdata/lines-.*\.json$", p) or re.search(r"(^|/)(knowledge|data)/", p):
            hit = [s for s in slugs if re.search(r"(?<![a-z0-9])" + re.escape(s) + r"(?![a-z0-9])", p)]  # whole token, never a substring (dex vs index)
            if p in AGGREGATE:
                if reader is None:
                    full = True; reasons.append("data aggregate, no diff objects " + p); continue
                try:
                    old, new = reader(p)
                    pair = None
                    if p in RULES_OF:
                        r_old, r_new = reader(RULES_OF[p])
                        pair = (_load(r_old), _load(r_new))
                    got = aggregate_projects(p, old, new, slugs, pair, trusted, catalogue, strict=True)
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
