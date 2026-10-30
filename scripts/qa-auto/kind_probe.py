#!/usr/bin/env python3
"""Stage (e): kind probes. ONE cluster `qa-auto-<sha8>`, always deleted (finally/atexit/SIGTERM).

usage: kind_probe.py --sha8 SHA8 --out cases.json [--crd-cases crd.json]
Probes (all must never exit 0 / PASS when a removal exists; BLOCKED or UNKNOWN expected):
  builtin  fixed manifests with removed built-in APIs (PSP, FlowSchema v1beta2, HPA v2beta2,
           CronJob v1beta1, Ingress extensions/v1beta1) scanned across the removing minor
  crd      real upstream CRDs (schemas relaxed) applied to the kind cluster, sample CRs created,
           live objects dumped with kubectl and scanned, for projects the CRD oracle found removals in
  assess   `prufyx assess` against the kind kubeconfig (informational, recorded)
kind/kubectl run via devbox ($QA_DEVBOX). Only a cluster named qa-auto-<sha8> is ever touched.
"""
import argparse, atexit, json, os, signal, subprocess, sys
from qalib import *
import crd_oracle

DEVBOX = ENV("QA_DEVBOX", "/opt/prufyx/bin/devbox")
IMAGE = ENV("QA_KIND_IMAGE", "kindest/node:v1.30.13")
NCRD = int(ENV("QA_PROBE_CRD", "2"))

BUILTIN = [  # (name, apiVersion, kind, from, to)
    ("psp", "policy/v1beta1", "PodSecurityPolicy", "1.24.0", "1.25.0"),
    ("flowschema", "flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema", "1.28.0", "1.29.0"),
    ("hpa", "autoscaling/v2beta2", "HorizontalPodAutoscaler", "1.25.0", "1.26.0"),
    ("cronjob", "batch/v1beta1", "CronJob", "1.24.0", "1.25.0"),
    ("ingress", "extensions/v1beta1", "Ingress", "1.21.0", "1.22.0"),
]
CONTROL = ("control-deployment", "apps/v1", "Deployment", "1.24.0", "1.25.0")


def dv(script, timeout=300):
    r = subprocess.run([DEVBOX, "-w", TMP, "sh", "-c", script], capture_output=True, text=True,
                       timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout, r.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sha8", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--crd-cases", default="")
    a = ap.parse_args()
    name = f"qa-auto-{a.sha8}"
    assert name.startswith("qa-auto-") and all(c.isalnum() or c == "-" for c in name)
    kc = f"{TMP}/kind/kubeconfig"
    os.makedirs(f"{TMP}/kind", exist_ok=True)
    cases = []

    def cleanup():
        try:  # our own cluster only; best effort, idempotent
            dv(f"kind delete cluster --name {name} >/dev/null 2>&1", 120)
        except Exception:
            pass

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        cleanup()
        rc, _, err = dv(f"kind create cluster --name {name} --image {IMAGE} --kubeconfig {kc} --wait 180s", 400)
        builtin(cases)  # file based, needs no cluster
        if rc:
            cases.append(case("kind", "create", error=True, why=err[-300:]))
        else:
            os.chmod(kc, 0o600)
            crd(cases, kc, a.crd_cases)
            assess(cases, kc, name)
    finally:
        cleanup()
        try:
            _, out, _ = dv("kind get clusters", 60)
            if name in out.split():
                cases.append(case("kind", "cleanup", error=True, why="cluster still present: " + name))
        except Exception:
            pass
        dump(cases, a.out)
        print("kind total", json.dumps(counts(cases)), "cases", len(cases))


def builtin(cases):
    for n, av, k, fr, to in BUILTIN + [CONTROL]:
        fn = f"{TMP}/kind/{n}.yaml"
        write_private(fn, f"apiVersion: {av}\nkind: {k}\nmetadata:\n  name: qa-{n}\n  namespace: default\n")
        code, j, tail = prufyx("scan", fn, f"kubernetes={fr}", f"kubernetes={to}")
        key = f"builtin {av} {k} {fr}->{to}"
        if j is None:
            cases.append(case("kind", key, error=True, why=tail))
        elif n.startswith("control"):
            cases.append(case("kind", key, mismatch=j.get("verdict") == "BLOCKED", exit=code, verdict=j.get("verdict")))
        else:
            cases.append(case("kind", key, wrongpass=is_pass(code, j),
                              mismatch=(j.get("verdict") not in ("BLOCKED", "UNKNOWN")) and not is_pass(code, j),
                              exit=code, verdict=j.get("verdict")))


def crd(cases, kc, crd_cases):
    if not crd_cases or not os.path.exists(crd_cases):
        cases.append(case("kind", "crd", note="no crd cases; skipped"))
        return
    seen, picks = set(), []
    for c in sorted(json.load(open(crd_cases)), key=lambda c: c["key"]):
        d = c["detail"]
        proj, f, t = (c["key"].split("|") + ["", ""])[:3]
        if d.get("nExpect") and proj not in seen and not c["error"]:
            seen.add(proj)
            picks.append((proj, f, t, set(d["expectRemoved"])))
        if len(picks) >= NCRD:
            break
    K = f"kubectl --kubeconfig {kc}"
    for proj, f, t, exp in picks:
        key = f"crd {proj} {f}->{t}"
        try:
            tj = json.load(open(f"{crd_oracle.TD}/target-{proj}.json"))["target"]
            gd = f"{CACHE}/git/{proj}.git"
            pref = tj["tagPrefixes"][0]
            txt = crd_oracle.crd_text(tj, gd, f)
            d = f"{TMP}/kind/{proj}"
            os.makedirs(d, exist_ok=True)
            write_private(f"{d}/crds.yaml", sh(CRDGVK, "-strip", inp=txt).stdout)
            write_private(f"{d}/samples.yaml", sh(CRDGVK, "-sample", inp=txt).stdout)
            dv(f"{K} apply --server-side --force-conflicts -f {d}/crds.yaml >/dev/null 2>&1; "
               f"{K} wait --for=condition=Established crd --all --timeout=60s >/dev/null 2>&1; "
               f"{K} apply -f {d}/samples.yaml >/dev/null 2>&1; true", 300)
            _, res, _ = dv(f"{K} get crd -o jsonpath='{{range .items[*]}}{{.spec.names.plural}}.{{.spec.group}},{{end}}'", 60)
            res = res.strip().rstrip(",")
            if not res:
                cases.append(case("kind", key, note="no CRDs established; skipped"))
                continue
            _, js, _ = dv(f"{K} get {res} -A -o json 2>/dev/null", 120)
            items = json.loads(js).get("items", []) if js.strip() else []
            dumped = {x["apiVersion"] + "/" + x["kind"] for x in items}
            hit = sorted(dumped & exp)
            _, ym, _ = dv(f"{K} get {res} -A -o yaml 2>/dev/null", 120)
            fn = f"{d}/dump.yaml"
            write_private(fn, ym)
            code, j, tail = prufyx("scan", fn, f"{proj}={f[len(pref):]}", f"{proj}={t[len(pref):]}")
            if not hit:
                cases.append(case("kind", key, note="no object of a removed GVK in the live dump; skipped",
                                  dumped=len(dumped)))
            elif j is None:
                cases.append(case("kind", key, error=True, why=tail))
            else:
                cases.append(case("kind", key, wrongpass=is_pass(code, j),
                                  mismatch=(j.get("verdict") not in ("BLOCKED", "UNKNOWN")) and not is_pass(code, j),
                                  exit=code, verdict=j.get("verdict"), removedDumped=hit[:5]))
        except Exception as e:
            cases.append(case("kind", key, error=True, why=repr(e)[:200]))


def assess(cases, kc, name):
    try:
        rc, out, err = dv(f"{BIN} assess --kubeconfig {kc} --acknowledge-kubeconfig-exec-risk --format json "
                          f"--to 1.31.0 kind-{name}", 300)
        v = None
        try:
            v = json.loads(out).get("verdict")
        except Exception:
            pass
        cases.append(case("kind", "assess 1.30->1.31 (informational)", exit=rc, verdict=v, tail=(out + err)[-200:]))
    except Exception as e:
        cases.append(case("kind", "assess", note=repr(e)[:200]))


if __name__ == "__main__":
    main()
