#!/usr/bin/env python3
"""Kubernetes removed-API oracle from upstream swagger.json (GVK set per minor).

usage: k8s_oracle.py --out cases.json [--lo 20] [--hi 37]
Suites: k8s-range (all GVKs of minor m, scan m -> m+1), k8s-single (each removed
non-alpha GVK alone), k8s-plan (multi-hop `prufyx plan`, per-stage verdicts).
WRONGPASS: a removed GVK is in the input and scan/plan exits 0 / says PASS.
"""
import argparse, json, os, sys, urllib.request
from qalib import *
import qa_scope

SKIP_KINDS = ("DeleteOptions", "WatchEvent", "Status", "CreateOptions", "UpdateOptions",
              "PatchOptions", "Scale", "Eviction", "Binding", "EphemeralContainers")
_sw = {}


def swagger(m):
    if m in _sw:
        return _sw[m]
    fn = f"{CACHE}/k8s-{m}.json"
    if not os.path.exists(fn):
        os.makedirs(CACHE, exist_ok=True)
        url = f"https://raw.githubusercontent.com/kubernetes/kubernetes/v1.{m}.0/api/openapi-spec/swagger.json"
        data = urllib.request.urlopen(url, timeout=120).read()
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
    # Read the complete requested truth and declare the scope before invoking the candidate.
    for minor in range(a.lo, hi + 1):
        swagger(minor)
    requested, singles, excluded = set(), {}, []
    for minor in range(a.lo, hi):
        requested.add(f"k8s-range|1.{minor}->1.{minor+1}")
        for gvk in sorted(swagger(minor) - swagger(minor + 1)):
            target = f"k8s-single|1.{minor}->1.{minor+1} {'/'.join(gvk)}"
            requested.add(target)
            singles[target] = gvk
            if "alpha" in gvk[1]:
                excluded.append(dict(target=target, reason="single-alpha API unsupported by the beta/stable family",
                                     next_test="add an alpha-scoped removal rule and reproduce this single object across its removal boundary"))
    windows = [(lo, end) for lo, end in [(20, 30), (24, 37), (30, 37), (28, 29), (36, 37)] if lo >= a.lo and end <= hi]
    for lo, end in windows:
        requested.add(f"k8s-plan|1.{lo}->1.{end} overall")
        requested.update(f"k8s-plan|1.{lo}->1.{end} stage 1.{minor}.0->1.{minor+1}.0" for minor in range(lo, end))
    head, base, run_id = ENV("QA_SCOPE_HEAD", ENV("QA_SHA", "")), ENV("QA_BASE", ""), ENV("QA_RUN_ID", "")
    scope = qa_scope.declare(head, base, run_id, requested, required_single_targets(singles), excluded)
    scope_path = a.out.removesuffix(".cases.json") + ".scope.json"
    dump(scope, scope_path + ".declared")
    executed = set()
    cases = []
    for m in range(a.lo, hi):
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
                cases.append(case("k8s-single", f"1.{m}->1.{m+1} {'/'.join(x)}",
                                  status="EXCLUDED", why="declared single-alpha exclusion; no PASS claim",
                                  requested=1, executed=0))
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
        gv = {x for x in swagger(lo) if "alpha" not in x[1]}
        code, j, tail = prufyx("plan", inp(gv, "plan"), f"kubernetes=1.{lo}.0", f"kubernetes=1.{h}.0")
        executed.add(f"k8s-plan|1.{lo}->1.{h} overall")
        if j is None:
            cases.append(case("k8s-plan", f"1.{lo}->1.{h}", error=True, why=tail))
            continue
        expected_stages = [(f"1.{m}", f"1.{m+1}") for m in range(lo, h)]
        actual_stages = [(s["from"], s["to"]) for s in j.get("stages", [])]
        if len(actual_stages) != h - lo or any(not fr.startswith(a + ".") or not to.startswith(b + ".") for (fr, to), (a, b) in zip(actual_stages, expected_stages)):
            cases.append(case("k8s-plan", f"1.{lo}->1.{h} scope", error=True, why="requested stages missing or different"))
        anyexp = False
        for s in j.get("stages", []):
            executed.add(f"k8s-plan|1.{lo}->1.{h} stage {s['from']}->{s['to']}")
            k = int(s["to"].split(".")[1])
            exp = sorted(x for x in (swagger(k - 1) - swagger(k)) if x in gv)
            anyexp |= bool(exp)
            got = s["verdict"]
            cases.append(case("k8s-plan", f"1.{lo}->1.{h} stage {s['from']}->{s['to']}",
                              wrongpass=bool(exp) and "PASS" in got,
                              mismatch=(got == "BLOCKED") != bool(exp) and "PASS" not in got and got != "UNKNOWN",
                              verdict=got, expectedBlocked=bool(exp)))
        cases.append(case("k8s-plan", f"1.{lo}->1.{h} overall", wrongpass=anyexp and is_pass(code, j),
                          exit=code, verdict=j.get("verdict")))
    scope.update(executed=sorted(executed), state="COMPLETE")
    for reason in qa_scope.errors(scope, head, base, run_id):
        cases.append(case("k8s", "declared-scope", error=True, why=reason))
    dump(scope, scope_path)
    dump(cases, a.out)
    print("k8s total", json.dumps(counts(cases)), "cases", len(cases))


if __name__ == "__main__":
    main()
