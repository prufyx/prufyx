#!/usr/bin/env python3
"""Kubernetes removed-API oracle from upstream swagger.json (GVK set per minor).

usage: k8s_oracle.py --out cases.json [--lo 20] [--hi 37]
Suites: k8s-range (all GVKs of minor m, scan m -> m+1), k8s-single (each removed
non-alpha GVK alone), k8s-plan (multi-hop `prufyx plan`, per-stage verdicts).
WRONGPASS: a removed GVK is in the input and scan/plan exits 0 / says PASS.
"""
import argparse, json, os, sys, urllib.error, urllib.request
from qalib import *
import qa_scope

SKIP_KINDS = ("DeleteOptions", "WatchEvent", "Status", "CreateOptions", "UpdateOptions",
              "PatchOptions", "Scale", "Eviction", "Binding", "EphemeralContainers")
_sw = {}


class UnavailableVersion(Exception):
    def __init__(self, evidence):
        self.evidence = evidence


def verified_absent_ref(minor):
    source = "https://github.com/kubernetes/kubernetes.git"
    missing, previous = f"refs/tags/v1.{minor}.0", f"refs/tags/v1.{minor-1}.0"
    result = subprocess.run(["git", "ls-remote", "--refs", "--tags", source, missing, previous],
                            text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError("official version-ref lookup failed")
    refs = {}
    for line in result.stdout.splitlines():
        sha, ref = line.split()
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or ref not in (missing, previous) or ref in refs:
            raise ValueError("official version-ref response malformed")
        refs[ref] = sha
    if missing in refs or previous not in refs:
        raise ValueError("404 did not establish an unavailable version")
    return dict(source=source, missing_ref=missing, previous_ref=previous, previous_ref_sha=refs[previous])


def swagger(m):
    if m in _sw:
        return _sw[m]
    fn = f"{CACHE}/k8s-{m}.json"
    if not os.path.exists(fn):
        os.makedirs(CACHE, exist_ok=True)
        url = f"https://raw.githubusercontent.com/kubernetes/kubernetes/v1.{m}.0/api/openapi-spec/swagger.json"
        try:
            data = urllib.request.urlopen(url, timeout=120).read()
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            raise UnavailableVersion(verified_absent_ref(m)) from error
        open(fn + ".part", "wb").write(data)
        os.replace(fn + ".part", fn)
    s = set()
    with open(fn) as swagger_file:
        definitions = json.load(swagger_file)["definitions"]
    for df in definitions.values():
        for g in df.get("x-kubernetes-group-version-kind", []):
            k = g["kind"]
            if k.endswith("List") or k in SKIP_KINDS:
                continue
            s.add((g["group"], g["version"], k))
    if not s:
        raise ValueError("swagger contains no served object scope")
    _sw[m] = s
    return s


def inp(gvks, name):
    fn = f"{TMP}/k8s/{name}.yaml"
    write_private(fn, "---\n".join(doc(g, v, k) for (g, v, k) in sorted(gvks)))
    return fn



def record_input(scope, target, report, requested):
    if report is None or not complete_scan_scope(report, requested):
        summary = (report or {}).get("summary", {})
        scope["omitted"].append(dict(target=target, requested=requested,
            read=summary.get("documentsRead"), intake_omitted=summary.get("documentsOmitted"),
            reason="input was not completely processed; replay the full synthetic input"))


def required_single_targets(singles):
    """Infer requirements from the exact data diff; operator input can only add."""
    required = set()
    if ENV("QA_BASE", ""):
        try:
            paths = sh("git", "-C", SRC, "diff", "--name-only", "--no-renames", ENV("QA_BASE"), ENV("QA_SHA"))
            if paths.returncode:
                raise ValueError("changed paths unreadable")
            rule_path = "cli/internal/cncfcheck/data/rules.json"
            for path in paths.stdout.splitlines():
                if path == rule_path:
                    before = sh("git", "-C", SRC, "show", f"{ENV('QA_BASE')}:{rule_path}")
                    after = sh("git", "-C", SRC, "show", f"{ENV('QA_SHA')}:{rule_path}")
                    if before.returncode or after.returncode:
                        raise ValueError("rules unreadable")
                    documents = [json.loads(result.stdout) for result in (before, after)]
                    entries = []
                    for document in documents:
                        rows = document["entries"]
                        indexed = {row["rule"]["id"]: row for row in rows}
                        if len(indexed) != len(rows):
                            raise ValueError("ambiguous rules")
                        entries.append(indexed)
                    if {k: v for k, v in documents[0].items() if k != "entries"} != {k: v for k, v in documents[1].items() if k != "entries"}:
                        raise ValueError("changed rule-pack metadata")
                    for rule_id in set(entries[0]) | set(entries[1]):
                        if entries[0].get(rule_id) == entries[1].get(rule_id):
                            continue
                        for entry in (entries[0].get(rule_id), entries[1].get(rule_id)):
                            if entry is None or entry["project"] != "kubernetes":
                                continue
                            fact = entry["rule"].get("condition", {}).get("factId")
                            members = kubernetes_removal_facts().get(fact)
                            if not members:
                                raise ValueError("changed Kubernetes rule cannot be narrowed")
                            for member in members:
                                matches = {target for target, gvk in singles.items() if "/".join(gvk) == member}
                                required.update(matches or {"k8s-single|required:" + member})
                elif path.startswith("cli/") and not (path.endswith(".md") or path.startswith("cli/docs/") or
                        path.startswith("cli/internal/extract/crdversions/target-") or path == "cli/internal/customresources/table.json"):
                    raise ValueError("changed data cannot be narrowed")
        except Exception:
            required.update(singles)  # ambiguity requires every single, including excluded targets
    extra = ENV("QA_REQUIRED_TARGETS", "")
    if extra:
        with open(extra) as required_file:
            added = json.load(required_file)
        if not isinstance(added, list) or not all(isinstance(x, str) for x in added):
            raise ValueError("required targets must be a list")
        required.update(added)
    return required

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--lo", type=int, default=int(ENV("QA_K8S_LO", "20")))
    ap.add_argument("--hi", type=int, default=int(ENV("QA_K8S_HI", "37")))
    a = ap.parse_args()
    hi = a.hi
    # An unavailable version is a pre-execution exclusion, never a lower maximum.
    unavailable, source_errors = {}, {}
    for minor in range(a.lo, hi + 1):
        try:
            swagger(minor)
        except UnavailableVersion as error:
            unavailable[minor] = error.evidence
        except Exception as error:
            source_errors[minor] = type(error).__name__
    requested, singles, excluded = set(), {}, []
    executed = set()

    def unavailable_target(target, minors):
        proof = next((unavailable[minor] for minor in minors if minor in unavailable), None)
        if proof:
            excluded.append(dict(target=target, kind="unavailable-version", evidence=proof,
                                 reason="swagger 404 and checked official absent version ref; no PASS claim",
                                 next_test="retry the exact version when its official release ref appears"))
            return True
        return False

    for minor in range(a.lo, hi + 1):
        target = f"k8s-version|1.{minor}.0"
        requested.add(target)
        if minor not in source_errors and not unavailable_target(target, [minor]):
            executed.add(target)
    for minor in range(a.lo, hi):
        band = f"1.{minor}->1.{minor+1}"
        range_target, set_target = "k8s-range|" + band, "k8s-single-set|" + band
        requested.update([range_target, set_target])
        if minor in source_errors or minor + 1 in source_errors:
            singles[set_target] = ("", "", "")
            continue
        if unavailable_target(range_target, [minor, minor + 1]):
            unavailable_target(set_target, [minor, minor + 1])
            singles[set_target] = ("", "", "")
            continue
        executed.add(set_target)
        for gvk in sorted(swagger(minor) - swagger(minor + 1)):
            target = f"k8s-single|1.{minor}->1.{minor+1} {'/'.join(gvk)}"
            requested.add(target)
            singles[target] = gvk
            if "alpha" in gvk[1]:
                excluded.append(dict(target=target, reason="single-alpha API unsupported by the beta/stable family",
                                     next_test="add an alpha-scoped removal rule and reproduce this single object across its removal boundary"))
    windows = [(lo, end) for lo, end in [(20, 30), (24, 37), (30, 37), (28, 29), (36, 37)] if lo >= a.lo and end <= hi]
    for lo, end in windows:
        targets = {f"k8s-plan|1.{lo}->1.{end} overall"}
        targets.update(f"k8s-plan|1.{lo}->1.{end} stage 1.{minor}.0->1.{minor+1}.0" for minor in range(lo, end))
        requested.update(targets)
        if not any(minor in source_errors for minor in range(lo, end + 1)):
            for target in targets:
                unavailable_target(target, range(lo, end + 1))
    head, base, run_id = ENV("QA_SCOPE_HEAD", ENV("QA_SHA", "")), ENV("QA_BASE", ""), ENV("QA_RUN_ID", "")
    scope = qa_scope.declare(head, base, run_id, requested, required_single_targets(singles), excluded)
    scope_path = a.out.removesuffix(".cases.json") + ".scope.json"
    dump(scope, scope_path + ".declared")
    cases = []
    if source_errors:
        for minor, reason in source_errors.items():
            cases.append(case("k8s", f"version-1.{minor}.0", error=True, why=reason))
    for m in range(a.lo, hi):
        if source_errors or m in unavailable or m + 1 in unavailable:
            continue
        sa, sb = swagger(m), swagger(m + 1)
        removed = sorted(sa - sb)
        fr, to = f"kubernetes=1.{m}.0", f"kubernetes=1.{m+1}.0"
        code, j, tail = prufyx("scan", inp(sa, "range"), fr, to)
        key = f"1.{m}->1.{m+1}"
        executed.add("k8s-range|" + key)
        record_input(scope, "k8s-range|" + key, j, len(sa))
        if j is None:
            cases.append(case("k8s-range", key, error=True, why=tail))
        else:
            wp, mm, missing, statuses = scoped_result(code, j, [x for x in removed if "alpha" not in x[1]], "kubernetes", "kubernetes.removed_served_gvk")
            wp = wp or (bool(removed) and is_pass(code, j))
            cases.append(case("k8s-range", key, wrongpass=wp, mismatch=mm, error=not complete_scan_scope(j, len(sa)), exit=code,
                              verdict=j.get("verdict"), removed=len(removed), notMentioned=missing,
                              requested=len(sa), executed=j.get("summary", {}).get("documentsRead"), families=statuses))
        for x in removed:
            if "alpha" in x[1]:
                continue
            code, j, tail = prufyx("scan", inp({x}, "single"), fr, to)
            key = f"1.{m}->1.{m+1} {'/'.join(x)}"
            executed.add("k8s-single|" + key)
            record_input(scope, "k8s-single|" + key, j, 1)
            if j is None:
                cases.append(case("k8s-single", key, error=True, why=tail))
            else:
                wp, mm, missing, statuses = scoped_result(code, j, [x], "kubernetes", "kubernetes.removed_served_gvk")
                cases.append(case("k8s-single", key, wrongpass=wp, mismatch=mm, error=not complete_scan_scope(j, 1),
                                  exit=code, verdict=j.get("verdict"), missing=missing, families=statuses))
    for lo, h in windows:
        if source_errors or any(minor in unavailable for minor in range(lo, h + 1)):
            continue
        gv = {x for x in swagger(lo) if "alpha" not in x[1]}
        path = inp(gv, "plan")
        frm, to = f"kubernetes=1.{lo}.0", f"kubernetes=1.{h}.0"
        # Plans omit intake counts and object locations. Bind their stages to a complete scan
        # of the same file and range, including the scan's exact object/removal-rule findings.
        scan_code, scan, scan_tail = prufyx("scan", path, frm, to)
        code, j, tail = prufyx("plan", path, frm, to)
        if j is None:
            cases.append(case("k8s-plan", f"1.{lo}->1.{h}", error=True, why=tail))
            continue
        complete = (code in (0, 10, 11) and scan_code in (0, 10, 11) and
                    scan is not None and complete_scan_scope(scan, len(gv)) and
                    bool(scan.get("provenance", {}).get("inputDigest")) and
                    scan["provenance"]["inputDigest"] == j.get("provenance", {}).get("inputDigest"))
        expected_stages = [(f"1.{m}", f"1.{m+1}") for m in range(lo, h)]
        actual_stages = [(s["from"], s["to"]) for s in j.get("stages", [])]
        stages_match = (len(actual_stages) == h - lo and all(vkey(fr)[:2] == vkey(a) and vkey(to)[:2] == vkey(b)
                        for (fr, to), (a, b) in zip(actual_stages, expected_stages)))
        if not stages_match:
            cases.append(case("k8s-plan", f"1.{lo}->1.{h} scope", error=True, why="requested stages missing or different"))
        overall_complete = complete and stages_match and j.get("verdict") in ("BLOCKED", "SCOPE_COMPLETE_PASS")
        anyexp = False
        for s in j.get("stages", []):
            target = f"k8s-plan|1.{lo}->1.{h} stage 1.{int(s['from'].split('.')[1])}.0->1.{int(s['to'].split('.')[1])}.0"
            k = int(s["to"].split(".")[1])
            exp = sorted(x for x in (swagger(k - 1) - swagger(k)) if x in gv)
            anyexp |= bool(exp)
            got = s["verdict"]
            ids = {finding["ruleId"] for finding in s.get("findings", [])}
            bound = dict(scan or {}, findings=[f for f in (scan or {}).get("findings", [])
                         if f.get("ruleId") in ids and f.get("hop", {}).get("from") == s["from"] and
                         f.get("hop", {}).get("to") == s["to"]], paths=[dict(p, hops=[hop for hop in p.get("hops", [])
                         if hop.get("index") == s.get("index")]) for p in (scan or {}).get("paths", [])])
            wp, mm, missing, statuses = scoped_result(scan_code, bound, exp, "kubernetes", "kubernetes.removed_served_gvk")
            stage_complete = (complete and stages_match and s.get("component") == "kubernetes" and
                              not missing and not wp and not mm and
                              got == ("BLOCKED" if exp else "SCOPE_COMPLETE_PASS") and
                              not s.get("gaps") and not s.get("unsupported"))
            overall_complete &= stage_complete
            if stage_complete:
                executed.add(target)
            cases.append(case("k8s-plan", f"1.{lo}->1.{h} stage {s['from']}->{s['to']}",
                              wrongpass=wp or (bool(exp) and "PASS" in got),
                              mismatch=mm or ((got == "BLOCKED") != bool(exp) and "PASS" not in got),
                              error=not stage_complete, verdict=got, expectedBlocked=bool(exp),
                              missing=missing, families=statuses, completeInput=complete))
        overall_complete &= not (anyexp and is_pass(code, j))
        if overall_complete:
            executed.add(f"k8s-plan|1.{lo}->1.{h} overall")
        cases.append(case("k8s-plan", f"1.{lo}->1.{h} overall", wrongpass=anyexp and is_pass(code, j),
                          error=not overall_complete, exit=code, verdict=j.get("verdict"), scanNote=scan_tail))
    qa_scope.remaining_omitted(scope, executed, "upstream read or candidate execution incomplete; retry this exact target")
    scope.update(executed=sorted(executed), state="COMPLETE")
    for exclusion in scope["excluded"]:
        cases.append(case("k8s", exclusion["target"], status="EXCLUDED", **exclusion))
    for reason in qa_scope.errors(scope, head, base, run_id):
        cases.append(case("k8s", "declared-scope", error=True, why=reason))
    dump(scope, scope_path)
    dump(cases, a.out)
    print("k8s total", json.dumps(counts(cases)), "cases", len(cases))


if __name__ == "__main__":
    main()
