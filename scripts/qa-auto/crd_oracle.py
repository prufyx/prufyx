#!/usr/bin/env python3
"""CRD oracle: served CRD GVKs at real upstream tags vs `prufyx scan`.

usage: crd_oracle.py --out cases.json [--projects a,b | --all] [--jobs N]
Targets come from $QA_SRC/cli/internal/extract/crdversions/target-*.json,
pairs from $QA_COV (coverage report, every pair forced to A) or, when a project
is not in it, from consecutive minor lines found in the tags.
WRONGPASS: a served GVK is gone at TO and the scan exits 0 / says PASS.
MISMATCH: any other disagreement (missed finding, false finding, CRD family not PASS).
"""
import argparse, glob, json, os, re, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from qalib import *
import qa_scope
import qa_batch_scope

TD = os.path.join(SRC, "cli/internal/extract/crdversions")
COV = ENV("QA_COV", "")
# PR/gate mode (QA_BASE set): clones of head-named repos go to the per-run scratch, never into the persistent cache,
# so an attacker repo named by a head cannot become the CRD truth of later runs.
GATE = bool(ENV("QA_BASE", ""))
GITROOT = os.path.join(TMP, "git") if GATE else os.path.join(CACHE, "git")
NAME = re.compile(r"[A-Za-z0-9_][\w.-]*", re.A)


def _safe_path(x):
    return (isinstance(x, str) and 0 < len(x) <= 300 and re.fullmatch(r"[A-Za-z0-9_][\w./-]*", x, re.A) is not None
            and ".." not in x.split("/") and not x.startswith("/"))


def validate_target(tj):
    """Fail closed on any target value that could steer git or a regex engine; returns (repo, error)."""
    try:
        repo = str(tj["repo"])
        repo = repo[len("github.com/"):] if repo.startswith("github.com/") else repo
        o, _, n = repo.partition("/")
        if not (NAME.fullmatch(o) and NAME.fullmatch(n)):
            return "", f"repo {repo[:80]!r} is not owner/name"
        prefs = tj["tagPrefixes"]
        if not isinstance(prefs, list) or not prefs or not all(isinstance(x, str) and re.fullmatch(r"[\w./-]*", x, re.A) and not x.startswith("-") for x in prefs):
            return "", "tagPrefixes invalid"
        for p in tj["paths"]:
            if not _safe_path(p.get("path")):
                return "", f"path {str(p.get('path'))[:80]!r} invalid"
            if type(p.get("optional", False)) is not bool:
                return "", "optional must be a boolean"
            if p.get("directory"):
                m = p["match"]
                if not isinstance(m, str) or len(m) > 200 or "(" in m or "\\" in m and re.search(r"\\[1-9]", m) or re.search(r"[+*}]\?*[+*{]", m) or len(re.findall(r"[*+]|\{\d*,\d*\}", m)) > 2:
                    return "", "match invalid (length, any group, backreference or stacked quantifier or more than 2 unbounded quantifiers)"
                re.compile(m)
        if tj.get("remote") is not None:
            bad = validate_remote(tj["remote"])
            if bad:
                return "", bad
        return repo, ""
    except Exception as e:
        return "", f"target invalid: {type(e).__name__}"


REF_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?", re.A)
RESOURCE_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml", re.A)
KUSTOMIZATION_API = "kustomize.config.k8s.io/v1beta1"
MAX_KUSTOMIZATION_RESOURCES = 512  # extractor MaxCRDsPerTag
MAX_KUSTOMIZATION_BYTES = 1 << 20


def validate_remote(rm):
    """Fail closed on a remote block that could steer git; returns an error text or ''."""
    try:
        o, _, n = str(rm["repo"]).removeprefix("github.com/").partition("/")
        if not (NAME.fullmatch(o) and NAME.fullmatch(n)):
            return "remote repo is not owner/name"
        if not _safe_path(rm["directory"]) or not _safe_path(rm["kustomization"]):
            return "remote directory or kustomization path invalid"
        pins = rm["pins"]
        if not isinstance(pins, list) or not pins:
            return "remote pins missing"
        for pin in pins:
            if set(pin) != {"tag", "commit"} or not isinstance(pin["tag"], str) or REF_RE.fullmatch(pin["tag"]) is None \
                    or not isinstance(pin["commit"], str) or re.fullmatch(r"[0-9a-f]{40}", pin["commit"], re.A) is None:
                return "remote pin invalid"
        return ""
    except Exception as e:
        return f"remote invalid: {type(e).__name__}"


def projects_all():
    return sorted(re.sub(r"^target-|\.json$", "", os.path.basename(p)) for p in glob.glob(TD + "/target-*.json"))


class MatchTimeout(Exception):
    pass


_MATCH_CODE = ("import json,re,sys\nd=json.load(sys.stdin)\nr=re.compile(d['m'])\n"
               "print(json.dumps([f for f in d['f'] if len(f.split('/')[-1])<=255 and r.search(f.split('/')[-1])]))")
MATCH_TIMEOUT = float(ENV("QA_MATCH_TIMEOUT", "5"))


def match_names(pattern, files):
    """The target's `match` regex is head-supplied: apply it in a child process under a hard wall-clock bound."""
    try:
        r = subprocess.run([sys.executable, "-I", "-c", _MATCH_CODE], input=json.dumps({"m": pattern, "f": files}),
                           capture_output=True, text=True, timeout=MATCH_TIMEOUT)
        if r.returncode:
            raise ValueError("matcher child failed")
        return json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        raise MatchTimeout(pattern[:80])
    except Exception as e:
        raise MatchTimeout(f"match failed: {type(e).__name__}")


def checked(*args):
    r = sh(*args)
    if r.returncode:
        raise ValueError("command failed: " + " ".join(args[:4]))
    return r.stdout


def path_absent(gd, tag, path):
    """True only when git answers successfully and the path is not in the tree (a git failure raises)."""
    return not checked("git", "-C", gd, "ls-tree", "--name-only", "--end-of-options", tag, path).strip()


def remote_applies(tj, tagname):
    """Mirror of the extractor's Remote.appliesTo: releases from `fromLine` on read their CRDs from another repository."""
    rm = tj.get("remote")
    if not rm:
        return False
    try:
        floor = tuple(int(x) for x in str(rm["fromLine"]).split("."))
        if len(floor) != 2:
            raise ValueError
    except Exception:
        raise ValueError("remote fromLine invalid")
    m = re.search(r"(\d+)\.(\d+)", tagname or "")
    if not m:  # cannot place the release on a line: never assume it is served locally
        raise ValueError("remote-served target: release line of %r unknown" % (tagname,))
    return (int(m.group(1)), int(m.group(2))) >= floor


def kustomization_resources(name, body):
    """Strict reading of a kustomization, mirroring the extractor's kustomizationResources: one document of exactly the
    keys apiVersion, kind and resources (kustomize v1beta1 Kustomization), resources a non-empty list of plain strings.
    The reader is deliberately narrower than YAML (block style, whole-line comments, plain or simply quoted scalars);
    anything else is refused, never guessed."""
    if len(body) > MAX_KUSTOMIZATION_BYTES or "{{" in body or "\t" in body or "\r" in body:
        raise ValueError(f"{name} is not a plain strictly readable kustomization")

    def scalar(v):
        v = v.strip()
        q = re.fullmatch(r"(['\"])([^'\"\\#]*)\1(?:\s+#.*)?", v)
        if q:
            v = q.group(2)
        else:
            v = re.split(r"\s+#", v, maxsplit=1)[0].strip()  # a trailing comment needs leading whitespace
            if not v or v[0] in "&*!|>{[%@`'\"#-?:," or "#" in v or ": " in v or v.endswith(":"):
                raise ValueError(f"{name} has a scalar this reader does not model")
        if not v:
            raise ValueError(f"{name} has an empty scalar")
        return v

    doc, res, in_res, started = {}, None, False, False
    for raw in body.split("\n"):
        line = raw.rstrip(" ")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line == "---" and not started and not doc:
            started = True
            continue
        m = re.fullmatch(r"( *)- (.+)", line)
        if m and in_res:
            res.append(scalar(m.group(2)))
            continue
        m = re.fullmatch(r"([A-Za-z]+):(?: (.*))?", line)
        if not m or m.group(1) in doc:
            raise ValueError(f"{name} is not one plain document of apiVersion, kind and resources")
        key, val = m.group(1), m.group(2)
        if key not in ("apiVersion", "kind", "resources"):
            raise ValueError(f"{name} has the key {key!r}: only apiVersion, kind and resources are modelled")
        in_res = key == "resources"
        if in_res:
            if val is not None and val.strip():
                raise ValueError(f"{name} resources is not a block list")
            res = doc[key] = []
        else:
            if val is None:
                raise ValueError(f"{name} has an empty {key}")
            doc[key] = scalar(val)
    if doc.get("apiVersion") != KUSTOMIZATION_API or doc.get("kind") != "Kustomization":
        raise ValueError(f"{name} is not a {KUSTOMIZATION_API} Kustomization")
    items = doc.get("resources")
    if not items or len(items) > MAX_KUSTOMIZATION_RESOURCES:
        raise ValueError(f"{name} has no resources list of a supported size")
    return items


def remote_ref(rm, name, body):
    """The tag named by the release's one remote resource https://github.com/<repo>/<directory>?ref=<tag>."""
    items = kustomization_resources(name, body)
    if len(items) != 1:
        raise ValueError(f"{name} lists {len(items)} resources: exactly one remote resource is modelled")
    want = str(rm["repo"]).removeprefix("github.com/") + "/" + rm["directory"]
    m = re.fullmatch(r"https://github\.com/([^?#%\s]+)\?ref=([^?#%\s&=]+)", items[0], re.A)
    if not m or m.group(1) != want or REF_RE.fullmatch(m.group(2)) is None:
        raise ValueError(f"{name} names a resource other than https://github.com/{want}?ref=<release tag>")
    return m.group(2)


def remote_text(tj, gd, tag, rgd):
    """Mirror of the extractor's readRemoteInventory: the release's kustomization at `tag` of the release clone gd names
    one tag of the remote repository; the target's pin for that tag, confirmed against the remote clone rgd, gives the
    commit whose directory kustomization lists the plain files that hold the definitions. Any doubt is an error."""
    rm = tj["remote"]
    bad = validate_remote(rm)
    if bad:
        raise ValueError(bad)
    if not rgd or not os.path.isdir(rgd):
        raise ValueError("remote clone unavailable")
    ref = remote_ref(rm, rm["kustomization"], checked("git", "-C", gd, "show", "--end-of-options", f"{tag}:{rm['kustomization']}"))
    pins = [p["commit"] for p in rm["pins"] if p["tag"] == ref]
    if not pins:
        raise ValueError(f"{rm['kustomization']} names the tag {ref} of {rm['repo']}, which the target does not pin to a commit")
    pinned = pins[0]
    actual = checked("git", "-C", rgd, "rev-parse", "--verify", "refs/tags/" + ref + "^{commit}").strip()
    if actual != pinned:
        raise ValueError(f"remote tag {ref} moved or differs from its pin")
    d = rm["directory"]
    names = kustomization_resources(d + "/kustomization.yaml", checked(
        "git", "-C", rgd, "show", "--end-of-options", f"{pinned}:{d}/kustomization.yaml"))
    if len(set(names)) != len(names) or any(RESOURCE_FILE_RE.fullmatch(n) is None or n == "kustomization.yaml" for n in names):
        raise ValueError(f"{d}/kustomization.yaml lists a resource other than distinct plain file names")
    tree = {}
    for ent in checked("git", "-C", rgd, "ls-tree", "-r", "-z", "--end-of-options", pinned, d + "/").split("\0"):
        if ent:
            meta, _, p = ent.partition("\t")
            tree[p] = meta.split()[0]
    txt = ""
    for n in sorted(names):
        mode = tree.get(d + "/" + n)
        if mode is None:
            raise ValueError(f"listed file {n} does not exist in {d} at the pinned commit")
        if mode not in ("100644", "100755"):
            raise ValueError(f"{n} is a symbolic link or not a regular file")
        body = checked("git", "-C", rgd, "show", "--end-of-options", f"{pinned}:{d}/{n}")
        if not body.strip():
            raise ValueError("requested blob was empty")
        txt += "\n---\n" + body
    return txt


def crd_text(tj, gd, tag, tagname=None, rgd=None):
    """Concatenated CRD YAML of one project at one tag (from the bare clone gd).
    Semantics mirror the extractor: an Optional path that is absent at the tag contributes nothing, a missing
    non-optional path is an error, a present directory without matching files is an error. A release that the
    target serves from a Remote repository is read through its pinned remote clone rgd (remote_text); no pin, a moved
    tag, a missing clone or any unmodelled shape is an explicit error, never empty."""
    if remote_applies(tj, tagname if tagname is not None else tag):
        return remote_text(tj, gd, tag, rgd)
    txt = ""
    for p in tj["paths"]:
        if p.get("optional") and path_absent(gd, tag, p["path"]):
            continue
        if p.get("directory"):
            fl = checked("git", "-C", gd, "ls-tree", "-r", "--name-only", "--end-of-options", tag, p["path"] + "/").splitlines()
            fl = match_names(p["match"], fl)
            if not fl:
                raise ValueError("no files matched requested directory")
        else:
            fl = [p["path"]]
        for f in fl:
            body = checked("git", "-C", gd, "show", "--end-of-options", f"{tag}:{f}")
            if not body.strip():
                raise ValueError("requested blob was empty")
            txt += "\n---\n" + body
    return txt


PADDED_TAG = re.compile(r"([2-9]\d)\.(0[1-9])\.(0|[1-9]\d*)", re.A)


def tag_commit(gd, tag):
    out = checked("git", "-C", gd, "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", out):
        raise ValueError("tag did not resolve to a commit")
    return out


def scan_version(gd, pref, version):
    """Version string for `prufyx scan`. The extractor accepts one leading zero in the minor only for majors 20..99
    (v25.08.0 is v25.8.0); the scan argument parser rejects it. Substitute the canonical form only when git proves the
    canonical tag exists on the same commit as the padded tag. Anything else is passed through unchanged and fails closed."""
    m = PADDED_TAG.fullmatch(version)
    if not m or not gd:
        return version
    canon = f"{m[1]}.{int(m[2])}.{m[3]}"
    try:
        if tag_commit(gd, pref + version) == tag_commit(gd, pref + canon):
            return canon
    except ValueError:
        pass
    return version


def lines_from(lines, min_from):
    """Release lines at or above the target's minFrom ("0.36"); the target declares nothing older is served from its path."""
    if not min_from:
        return lines
    floor = tuple(int(x) for x in str(min_from).split("."))
    return [l for l in lines if l >= floor]


def adjacent_pairs(lines, min_from, project):
    retained = lines_from(lines, min_from)
    dropped = max(0, len(lines) - 1) - max(0, len(retained) - 1)
    if min_from:
        print(f"crd {project}: minFrom={min_from} dropped_pairs={dropped}", flush=True)
    return [{"from": ".".join(map(str, a)), "to": ".".join(map(str, b))}
            for a, b in zip(retained, retained[1:])]


def check_served_floor(min_from, line, served):
    """Reject a floor above a line whose target CRDs were actually read as served."""
    if min_from and served and tuple(map(int, min_from.split("."))) > line:
        raise ValueError(f"minFrom {min_from} exceeds observed served line {line[0]}.{line[1]}")


def crd_rows(tj, gd, tag, tagname=None, rgd=None):
    text = crd_text(tj, gd, tag, tagname, rgd)
    result = sh(CRDGVK, inp=text)
    if result.returncode:
        raise ValueError("CRD YAML helper failed")
    rows = json.loads(result.stdout)
    if not isinstance(rows, list):
        raise ValueError("helper output must be a list")
    for row in rows:
        if (not isinstance(row, dict) or
                any(not isinstance(row.get(key), str) or not row[key].strip() for key in ("G", "V", "K")) or
                any(type(row.get(key)) is not bool for key in ("Served", "Store"))):
            raise ValueError("helper output contains an invalid GVK row")
    if not rows and "CustomResourceDefinition" in text:
        raise ValueError("helper omitted every CRD version")
    return rows


def served_set(tj, gd, tag, tagname=None, rgd=None):
    return {(row["G"], row["V"], row["K"]) for row in crd_rows(tj, gd, tag, tagname, rgd) if row["Served"]}


def defined_kinds(tj, gd, tag, tagname=None, rgd=None):
    """(group, kind) of every CRD defined at the tag, served or not."""
    return {(row["G"], row["K"]) for row in crd_rows(tj, gd, tag, tagname, rgd)}


def classify_whole(tj, gd, tag, removed, cache, tagname=None, rgd=None):
    """Whole-CRD part of `removed`, or [] on any failed, empty or otherwise doubtful read of the later tag (fail closed)."""
    if not removed:
        return []
    try:
        if tag not in cache:
            cache[tag] = defined_kinds(tj, gd, tag, tagname, rgd)
        if not cache[tag]:
            return []  # nothing defined at the later tag: a silent partial read cannot prove an absence
        return whole_removed(removed, cache[tag])
    except Exception:
        return []


def whole_removed(removed, later_defined):
    """Removed GVKs whose (group, kind) CRD is absent from the later line (whole-CRD removal).
    A version served:false/removed inside a still-defined CRD is not in this set. Fail closed: no definition set means none."""
    if later_defined is None:
        return []
    return [x for x in removed if (x[0], x[2]) not in later_defined]


def run(proj, cov):
    try:
        return _run(proj, cov)
    except Exception as e:  # fail closed: an error case, never a skip
        return [case("crd", proj, error=True, why="oracle failed: %s" % e)]


def prepare(proj, cov, plan):
    """Resolve the whole source inventory before any candidate scan is started."""
    plan["requested"].add("crd-project|" + proj)
    comp = next((x for x in cov if x["project"] == proj), None)
    if comp is not None:
        plan["requested"].update(f"crd-line|{proj}|{pair['from']}|{pair['to']}" for pair in comp["pairs"])
    if plan.get("binding"):
        tj = plan["binding"]["target"]["spec"]
    else:
        with open(f"{TD}/target-{proj}.json") as target_file:
            tj = json.load(target_file)["target"]
    repo, bad = validate_target(tj)
    if bad:
        raise ValueError("target rejected: " + bad)
    if not re.fullmatch(r"[A-Za-z0-9_][\w.-]*", proj, re.A):
        raise ValueError("project name rejected")
    gd = f"{GITROOT}/{proj}.git"
    os.makedirs(os.path.dirname(gd), exist_ok=True)
    if not os.path.isdir(gd):
        r = sh("git", "clone", "-q", "--bare", "--filter=blob:none", "--", f"https://github.com/{repo}.git", gd)
        if r.returncode:
            shutil.rmtree(gd, ignore_errors=True)
            raise ValueError("clone failed")
    r = sh("git", "-C", gd, "fetch", "-q", "--tags", "--force")
    if r.returncode:
        raise ValueError("fetch tags failed")
    rgd = None
    if tj.get("remote"):  # the remote-served releases read their definitions from this second clone
        rgd = f"{GITROOT}/{proj}.remote.git"
        rrepo = str(tj["remote"]["repo"]).removeprefix("github.com/")
        if not os.path.isdir(rgd):
            r = sh("git", "clone", "-q", "--bare", "--filter=blob:none", "--", f"https://github.com/{rrepo}.git", rgd)
            if r.returncode:
                shutil.rmtree(rgd, ignore_errors=True)
                raise ValueError("remote clone failed")
        r = sh("git", "-C", rgd, "fetch", "-q", "--tags", "--force")
        if r.returncode:
            raise ValueError("remote fetch tags failed")
    pinned = {}
    for pair in plan.get("proof_pairs", {}).values():
        for side in ("from", "to"):
            tag, expected = pair[side + "Tag"], pair[side + "Commit"]
            if tag not in pinned:
                actual = checked("git", "-C", gd, "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}").strip()
                if not re.fullmatch(r"[0-9a-f]{40}", actual):
                    raise ValueError("proof tag did not resolve to a commit")
                pinned[tag] = actual
            if pinned[tag] != expected:
                raise ValueError("proof tag moved or commit differs")
    pref = tj["tagPrefixes"][0]
    tags = checked("git", "-C", gd, "tag", "-l").splitlines()
    lines = {}
    for t in tags:
        if re.fullmatch(re.escape(pref) + r"\d+\.\d+\.\d+", t):
            lines.setdefault(vkey(t)[:2], []).append(t)
    for l in lines:
        lines[l].sort(key=vkey)
    cache = {}

    def served(tag):
        if tag not in cache:
            ref = pinned.get(tag, tag)
            cache[tag] = served_set(tj, gd, ref, tag, rgd) if tj.get("remote") else served_set(tj, gd, ref)
            check_served_floor(tj.get("minFrom"), vkey(tag[len(pref):])[:2], cache[tag])
        return cache[tag]

    if comp is None:
        pairs = adjacent_pairs(sorted(lines), tj.get("minFrom"), proj)
        if tj.get("minFrom") and lines_from(sorted(lines), "") != lines_from(sorted(lines), tj.get("minFrom")):
            # target data has no independent earliest-served field: releases below minFrom were not observed
            plan["floor_unknown"] = dict(floor=tj["minFrom"], evidence="minFrom is declared, not independently observed below the floor",
                reason="earliest served line unverified for uninspected releases; no PASS claim below minFrom",
                next_test="add an independent earliest-served field to the target data or inspect the older releases")
    else:
        pairs = comp["pairs"]
    if not pairs:
        raise ValueError("no usable pairs")
    defined_cache = {}

    def whole(tag, removed):
        ref = pinned.get(tag, tag)
        result = classify_whole(tj, gd, ref, removed, defined_cache, tag, rgd) if tj.get("remote") else classify_whole(tj, gd, ref, removed, defined_cache)
        if defined_cache.get(ref):  # groups that still have a CRD at the later tag (only a non-empty, successful read)
            plan.setdefault("later_groups", {})[tag] = {g for g, _ in defined_cache[ref]}
        return result

    plan.update(proj=proj, pref=pref, gd=gd, catalog=tj.get("catalog", ""))
    known_pairs = []
    missing_line = False
    for pr in pairs:
        line_target = f"crd-line|{proj}|{pr['from']}|{pr['to']}"
        plan["requested"].add(line_target)
        l1 = tuple(int(x) for x in pr["from"].split("."))
        l2 = tuple(int(x) for x in pr["to"].split("."))
        if l1 not in lines or l2 not in lines:
            missing_line = True
            continue
        exact = [(f, t) for f in sorted({lines[l1][0], lines[l1][-1]}, key=vkey)
                 for t in sorted({lines[l2][0], lines[l2][-1]}, key=vkey)]
        plan["requested"].update(f"crd|{proj}|{f}|{t}" for f, t in exact)
        known_pairs.extend((line_target, f, t) for f, t in exact)
    if missing_line:
        raise ValueError("requested release line missing")
    # The envelope's exact pair may be neither the first nor last patch of a
    # release line. Keep it as its own immutable, mandatory execution.
    for target, pair in plan.get("proof_pairs", {}).items():
        f, t = pair["fromTag"], pair["toTag"]
        if not f.startswith(pref) or not t.startswith(pref):
            raise ValueError("proof tags do not match target prefix")
        sf, st = served(f), served(t)
        if not sf:
            raise ValueError("required proof pair source served set empty")
        plan["jobs"].append((target, f, t, sf, sorted(sf - st), whole(t, sorted(sf - st))))
    for line_target, f, t in known_pairs:
        sf, st = served(f), served(t)
        target = f"crd|{proj}|{f}|{t}"
        if not sf:
            plan["excluded"].append(dict(target=target, evidence="complete served-set read: empty",
                reason="verified empty served source scope; no PASS claim",
                next_test="select a source release with served objects or review this empty-source boundary"))
        else:
            plan["jobs"].append((target, f, t, sf, sorted(sf - st), whole(t, sorted(sf - st))))
        plan["metadata"].add(line_target)
    plan["metadata"].add("crd-project|" + proj)


DESIGN_STATUS = "DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL"


# Gap reason the scanner gives (observed, cilium 1.17.0 -> 1.18.0 with only a removed CRD) a pair whose only difference is a CRD the later anchor no longer defines: no rule exists, so the hop has no data.
DESIGN_GAP_REASONS = frozenset({"COMPONENT_NOT_COVERED"})


# The scanner also says how many manifests belong to a group no reviewed project owns (a CRD the later release no longer defines).
UNOWNED_GAP_REASON = "DOCUMENTS_NOT_EVALUATED"
UNOWNED_COUNT = re.compile(r"(\d{1,6}) manifest\(s\) use custom-resource groups that no reviewed project owns, so no custom-resource set is complete", re.A)

FAMILY = "crd.custom_resource_versions"


def listed_groups():
    """Every API group the reviewed custom-resource table attributes to some project, or None when the table cannot be read
    (then no unowned-document expectation is derived and the unowned-group gap stays refused)."""
    try:
        with open(os.path.join(SRC, "cli/internal/customresources/table.json")) as handle:
            table = json.load(handle)
        groups = {g["name"] for p in table["projects"] for g in p["groups"]}
        return groups if groups and all(isinstance(g, str) and g for g in groups) else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def unowned_served(served, removed, listed):
    """Served documents whose group no reviewed project lists: the scanner cannot attribute them, so it reports them as one
    unowned-group gap whatever the release pair is. Empty (nothing derived) when the inputs are unread, or when any expected
    removal lies in such a group, because a removal the scanner cannot see must never be excused by this count."""
    if served is None or listed is None:
        return set()
    unowned = {x for x in served if x[0] not in listed}
    return set() if any(x[0] not in listed for x in removed) else unowned


def unowned_gap_ok(gap, whole_docs):
    """The unowned-group gap is part of the design shape only when its count is exactly the number of whole-CRD removals
    whose whole group is gone at the later release (their documents are the ones no project owns any more); any other count
    means an unexplained document. whole_docs is 0 (nothing allowed) unless every whole removal is of a vanished group."""
    m = UNOWNED_COUNT.fullmatch(gap.get("detail")) if isinstance(gap.get("detail"), str) else None
    return bool(m) and whole_docs > 0 and int(m.group(1)) == whole_docs


def whole_signal_clause(report, component, whole_docs=0, allow_findings=False, must_have_unowned=False):
    """None when the scan output has the documented whole-CRD shape, else a short code naming the first failing clause.
    Whole-only shape: no findings, no unsupported combination, nothing omitted, at least one gap for the component, every gap
    reason in the removed-definition set, every hop of the component NO_DATA with only those reasons and no family evaluated.
    One unowned-group gap (DOCUMENTS_NOT_EVALUATED) is allowed besides the design gap when its count equals whole_docs.
    Mixed shape (allow_findings): the same gap rules (at least one design gap, none foreign), no hop check; findings are judged elsewhere."""
    if report.get("unsupported"):
        return "UNSUPPORTED"
    if report.get("omitted"):
        return "OMITTED"
    if report.get("findings") and not allow_findings:
        return "FINDINGS"
    gaps = [g for g in report.get("gaps") or [] if isinstance(g, dict)]
    if len(gaps) != len(report.get("gaps") or []):
        return "GAP_MALFORMED"
    mine = [g for g in gaps if g.get("component") == component]
    if len(mine) != len(gaps):
        return "GAP_COMPONENT"
    unowned = [g for g in mine if g.get("reason") == UNOWNED_GAP_REASON]
    mine = [g for g in mine if g.get("reason") != UNOWNED_GAP_REASON]
    if len(unowned) > 1 or any(not unowned_gap_ok(g, whole_docs) for g in unowned):
        return "GAP_UNOWNED"
    if must_have_unowned and not unowned:
        return "GAP_UNOWNED_MISSING"
    if any(g.get("reason") not in DESIGN_GAP_REASONS for g in mine):
        return "GAP_REASON"
    if not mine:
        return "NO_GAP"
    if allow_findings:
        return None
    hops = [h for p in report.get("paths") or [] if isinstance(p, dict) and p.get("component") == component
            for h in p.get("hops") or []]
    if not hops:
        return "NO_HOP"
    # observed for a whole-CRD pair: every hop NO_DATA with only the same reason, no family evaluated
    if not all(isinstance(h, dict) and h.get("status") == "NO_DATA" for h in hops):
        return "HOP_STATUS"
    if not all(set(h.get("reasons") or []) <= DESIGN_GAP_REASONS for h in hops):
        return "HOP_REASON"
    if any(h.get("families") for h in hops):
        return "HOP_FAMILIES"
    return None


def whole_removal_signal(report, component, whole_docs=0):
    return whole_signal_clause(report, component, whole_docs) is None


def version_findings_clause(report, version, component):
    """None only when the findings are exactly the version-level expected removals: each expected one reported by this component's
    removal rule, and no finding that is not one of them."""
    findings = report.get("findings") or []
    if not all(isinstance(f, dict) for f in findings):
        return "EXTRA_FINDING"
    def matches(f, item):
        g, v, k = item
        return (f.get("component") == component and removal_claim(f.get("ruleId"), component, FAMILY, "/".join(item)) and
                any(loc.get("kind") == k and loc.get("name") == object_name(g, v, k) for loc in f.get("locations", []) if isinstance(loc, dict)))
    if any(not any(matches(f, x) for f in findings) for x in version):
        return "VERSION_MISSING"
    if any(not any(matches(f, x) for x in version) for f in findings):
        return "EXTRA_FINDING"
    return None


def whole_diagnostics(code, report, component, whole, clause=None):
    """Compact record of why a whole-removal candidate was or was not classified, so no re-run is needed to analyse it."""
    report = report or {}
    gaps = [g for g in report.get("gaps") or [] if isinstance(g, dict)]
    hops = [h for p in report.get("paths") or [] if isinstance(p, dict) and p.get("component") == component
            for h in p.get("hops") or [] if isinstance(h, dict)]
    return {"scanExit": code, "verdict": report.get("verdict"), "nFindings": len(report.get("findings") or []),
            "gapReasons": sorted({str(g.get("reason")) for g in gaps}),
            "hopStatuses": sorted({str(h.get("status")) for h in hops}),
            "clause": clause or whole_signal_clause(report, component) or "OK"}


def classify_pair(code, report, removed, whole_crd, component, later_groups=None, served=None, listed=None):
    """(wrongpass, mismatch, missing, statuses, design, clause); clause is a short code for diagnostics.
    later_groups: groups that still have a CRD at the later release, None when unread (the unowned-group gap is then not accepted)."""
    whole_set = set(whole_crd) & set(removed)
    gone = len(whole_set) if later_groups is not None and all(x[0] not in later_groups for x in whole_set) else 0
    # served documents of groups no project lists are unowned in every scan of this input; their count joins the expected
    # unowned-group gap, which must then be present, and the removals themselves never lie in such a group
    foreign = len(unowned_served(served, removed, listed)) if whole_set else 0
    gone += foreign
    version = [x for x in removed if x not in whole_set]
    wp, mm, missing, statuses = scoped_result(code, report, version, component, FAMILY)
    if not whole_set:
        return wp, mm, missing, statuses, False, "NO_WHOLE"
    if is_pass(code, report) or "PASS" in statuses:
        return True, False, missing, statuses, False, "PASS"
    unknown = report.get("verdict") == "UNKNOWN"
    if not version:
        clause = "EXIT" if code != 11 else ("NOT_UNKNOWN" if not unknown else whole_signal_clause(report, component, gone, must_have_unowned=foreign > 0))
        if clause is None:
            return False, False, [], statuses, True, "OK"
        return False, True, ["/".join(x) for x in sorted(whole_set)], statuses, False, clause
    # mixed: version-level removals are reported by their rules, the whole-CRD part is silent by documented design
    if code == 10 and report.get("verdict") == "BLOCKED":
        clause = whole_signal_clause(report, component, gone, allow_findings=True, must_have_unowned=foreign > 0) or version_findings_clause(report, version, component)
        if clause is None and not missing and not mm:
            return False, False, [], statuses, True, "OK"
    else:
        clause = "EXIT" if code != 10 else "NOT_BLOCKED"
    clause = clause or "VERSION_MISSING"
    if not unknown or not missing:
        missing = missing + ["/".join(x) for x in sorted(whole_set)]
    return False, True, missing, statuses, False, clause


def crd_verdict(code, report, removed, whole_crd, component, later_groups=None, served=None, listed=None):
    """(wrongpass, mismatch, missing, statuses, design) for one pair.
    A CRD defined earlier and absent later is a whole-CRD removal; by documented design (definitionsRemoved)
    the scanner reports UNKNOWN (exit 11, no findings) because the effect depends on the install method.
    That exact outcome, and only for a set made entirely of whole-CRD removals, is DESIGN_UNKNOWN_WHOLE_CRD_REMOVAL.
    A mixed set (version-level plus whole-CRD) is design only when the scan is BLOCKED (exit 10), its findings are exactly the
    version-level expected removals and every gap is a design gap. Any PASS stays WRONGPASS; anything else stays MISMATCH."""
    return classify_pair(code, report, removed, whole_crd, component, later_groups, served, listed)[:5]


def community_refusal(catalog, tail):
    """True only for a community-catalog target whose scan refused it with the documented usage message."""
    return catalog == "community" and "is in the community catalog" in tail and "does not check community projects" in tail


def execute(plan):
    out, executed, omitted = [], set(plan["metadata"]), []
    proj, pref = plan["proj"], plan["pref"]
    for n, (target, f, t, sf, removed, whole_crd) in enumerate(plan["jobs"]):
        docs = "---\n".join(doc(g, v, k) for (g, v, k) in sorted(sf))
        fn = f"{TMP}/crd/{proj}-{n}.yaml"
        write_private(fn, docs)
        try:
            code, j, tail = prufyx("scan", fn, f"{proj}={scan_version(plan.get('gd'), pref, f[len(pref):])}",
                                 f"{proj}={scan_version(plan.get('gd'), pref, t[len(pref):])}")
        finally:
            os.remove(fn)
        executed.add(target)
        key = target if target.startswith("crd-proof|") else f"{proj}|{f}|{t}"
        if j is None and community_refusal(plan.get("catalog"), tail):
            # scan declares community-catalog projects unsupported: not a verdict, so nothing to compare.
            # Still executed every night, so the first release whose scan accepts them is checked automatically.
            out.append(case("crd", key, status="UNSUPPORTED_COMMUNITY", exit=code, why=tail))
            continue
        if j is None:
            omitted.append(dict(target=target, reason="candidate response unreadable; replay the full input"))
            out.append(case("crd", key, error=True, why=tail))
            continue
        wp, mm, missing, crd, design, clause = classify_pair(code, j, removed, whole_crd, proj, plan.get("later_groups", {}).get(t),
                                                                  set(sf), listed_groups())
        complete = complete_scan_scope(j, len(sf))
        if not complete:
            omitted.append(dict(target=target, reason="input omitted or incomplete; replay the full input"))
        out.append(case("crd", key, wrongpass=wp, mismatch=mm, error=not complete, exit=code,
                        **({"wholeCrdCandidate": True, "whole": whole_diagnostics(code, j, proj, whole_crd, clause)} if whole_crd else {}),
                        **({"status": DESIGN_STATUS, "wholeCrdRemoved": ["/".join(x) for x in whole_crd]} if design else {}),
                        verdict=j.get("verdict"), crd=crd, missing=missing, requested=len(sf),
                        executed=j.get("summary", {}).get("documentsRead"), expectRemoved=["/".join(x) for x in removed],
                        nExpect=len(removed), nFindings=len(j.get("findings", [])),
                        **({"proof_pair": plan["proof_pairs"][target]} if target in plan.get("proof_pairs", {}) else {})))
    for exclusion in plan["excluded"]:
        out.append(case("crd", exclusion["target"], status="EXCLUDED", **exclusion))
    if plan.get("floor_unknown"):
        out.append(case("crd", f"crd-floor|{proj}", status="UNKNOWN_EARLIEST_SERVED", **plan["floor_unknown"]))
    return out, executed, omitted


def new_plan():
    return dict(requested=set(), metadata=set(), excluded=[], jobs=[])


def _run(proj, cov):
    plan = new_plan()
    prepare(proj, cov, plan)
    return execute(plan)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--projects", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--no-changed-projects", action="store_true")
    ap.add_argument("--jobs", type=int, default=int(ENV("QA_JOBS", "3")))
    a = ap.parse_args()
    cov = []
    if COV:
        with open(COV) as coverage_file:
            cov = json.load(coverage_file)["projects"]
    ps = [] if a.no_changed_projects else (projects_all() if a.all or not a.projects else a.projects.split(","))
    contract = qa_batch_scope.environment_contract()
    bindings = {}
    if contract is not None:
        if (contract["head"], contract["base"], contract["run_id"]) != (
                ENV("QA_SCOPE_HEAD", ENV("QA_SHA", "")), ENV("QA_BASE", ""), ENV("QA_RUN_ID", "")):
            raise ValueError("scope contract identity differs")
        ps = sorted(set(ps) | set(contract["projects"]))
        bindings = {p["slug"]: p for e in contract["envelopes"] for p in e["projects"]}
    if not ps and not a.no_changed_projects:
        raise ValueError("requested project inventory empty")
    plans = {}
    cases = []
    # All source plans, including failed requests, exist before any scan.
    for project in ps:
        plan = plans[project] = new_plan()
        if project in bindings:
            plan["binding"] = bindings[project]
            pair = bindings[project]["proof"]["pair"]
            target = qa_batch_scope.proof_target(project, pair)
            plan["proof_pairs"] = {target: pair}
            plan["requested"].update({"crd-project|" + project, target})
        try:
            prepare(project, cov, plan)
        except Exception as error:
            plan["error"] = str(error)
    requested = set().union(*(plan["requested"] for plan in plans.values()))
    excluded = [entry for plan in plans.values() if "error" not in plan for entry in plan["excluded"]]
    executed = set()
    if a.no_changed_projects:
        requested.add("crd-project|no-changed-projects")
    required = set(requested) if GATE and ps else set()
    if ENV("QA_REQUIRED_CRD_TARGETS", ""):
        with open(ENV("QA_REQUIRED_CRD_TARGETS")) as required_file:
            extra = json.load(required_file)
        if not isinstance(extra, list) or not all(isinstance(target, str) for target in extra):
            raise ValueError("additional required CRD targets invalid")
        required.update(extra)
    head, base, run_id = ENV("QA_SCOPE_HEAD", ENV("QA_SHA", "")), ENV("QA_BASE", ""), ENV("QA_RUN_ID", "")
    scope = qa_scope.declare(head, base, run_id, requested, required, excluded, qa_scope.CRD_PROFILE)
    scope_path = a.out.removesuffix(".cases.json") + ".scope.json"
    dump(scope, scope_path + ".declared")
    if a.no_changed_projects:
        executed.update(requested)
        cases.append(case("crd", "no-changed-projects", status="VERIFIED_ABSENCE",
                          next_test="reselect projects on the next changed target or rule diff"))
    for project, plan in plans.items():
        if "error" in plan:
            cases.append(case("crd", project, error=True, why=plan["error"]))
            continue
        try:
            result, completed, omitted = execute(plan)
            cases.extend(result)
            executed.update(completed)
            scope["omitted"].extend(omitted)
        except Exception as error:
            cases.append(case("crd", project, error=True, why="execution failed: " + str(error)))
    qa_scope.remaining_omitted(scope, executed, "source or execution failed; repair and replay this target")
    scope.update(executed=sorted(executed), state="COMPLETE")
    for reason in qa_scope.errors(scope, head, base, run_id, qa_scope.CRD_PROFILE):
        cases.append(case("crd", "declared-scope", error=True, why=reason))
    dump(scope, scope_path)
    dump(cases, a.out)
    print("crd total", json.dumps(counts(cases)))


if __name__ == "__main__":
    main()
