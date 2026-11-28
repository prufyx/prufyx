"""Source floors: the oracle's own list of upgrades that upstream does not allow from an older source. Python 3 stdlib only.

source_floors.json sits next to this file and is read from there only, never from the checkout under test. Each floor
names a project, a target minor line, the lowest source version upstream admits for that line, pinned upstream citations,
the source/target pairs to probe and the facts that declare every checked condition safe. For each pinned pair, and for
each rules.json entry of the component that reaches the target line from below the floor, `check cncf` runs with those
facts. Exit 0 is a wrong PASS. A non-zero result counts only when it does not depend on the probe being weak: exit 10 or
11 with a report in which every claim is a version block, or UNKNOWN because the pair is not reviewed or the rule
evidence is withdrawn or stale. Everything else (a missing or blocking fact, another exit code, an unreadable report, a
bad floor file, no QA_NOW) is an error. There is no allow-list.

A floor covers only what it lists: a target line without a floor is not checked.
"""
import json, os, re, subprocess

import qalib

HERE = os.path.dirname(os.path.abspath(__file__))
FLOORS = os.path.join(HERE, "source_floors.json")
RULES = "cli/internal/cncfcheck/data/rules.json"
SCHEMA = "prufyx.io/qa-source-floors/v1"
INPUT_SCHEMA = "prufyx.io/operator-declared-constraint-input/v1alpha1"
AUTHORITY = "OPERATOR_DECLARED_MINIMIZED"
TIMEOUT = 20
BLOCKED_EXIT, UNKNOWN_EXIT = 10, 11
PASS_VERDICTS = {"PASS", "SCOPE_COMPLETE_PASS"}
VERSION_OPERATORS = {"require_intermediate_version", "forbid_target_version"}  # block on the pair alone, not on a fact
SETTLED_UNKNOWN = {"RULE_TRANSITION_NOT_REVIEWED", "RULE_EVIDENCE_WITHDRAWN", "RULE_EVIDENCE_STALE"}
KEYS = {"id", "project", "component", "targetLine", "minimumSource", "probes", "safeFacts", "citations"}
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
LINE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SLUG = re.compile(r"[a-z0-9][a-z0-9.-]*")
CITATION = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/blob/[0-9a-f]{40}/[\w./-]+", re.A)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def version(text):
    need(isinstance(text, str) and VERSION.fullmatch(text), "not an x.y.z version: %r" % (text,))
    return tuple(int(x) for x in text.split("."))


def unique(pairs):
    out = dict(pairs)
    need(len(out) == len(pairs), "duplicate JSON key")
    return out


def load(path):
    """The validated floor list; any defect raises."""
    with open(path, "rb") as fh:
        data = json.loads(fh.read().decode("utf-8"), object_pairs_hook=unique)
    need(isinstance(data, dict) and set(data) == {"schema", "floors"} and data["schema"] == SCHEMA, "schema or top-level keys")
    floors = data["floors"]
    need(isinstance(floors, list) and floors, "floors must be a non-empty list")
    ids, lines = set(), set()
    for f in floors:
        need(isinstance(f, dict) and set(f) == KEYS, "floor keys must be exactly %s" % sorted(KEYS))
        for k in ("id", "project"):
            need(isinstance(f[k], str) and SLUG.fullmatch(f[k]), "bad %s" % k)
        need(isinstance(f["component"], str) and f["component"].startswith("pkg:"), "bad component")
        need(isinstance(f["targetLine"], str) and LINE.fullmatch(f["targetLine"]), "bad targetLine")
        line = tuple(int(x) for x in f["targetLine"].split("."))
        need(f["id"] not in ids and (f["component"], line) not in lines, "duplicate floor %s" % f["id"])
        ids.add(f["id"])
        lines.add((f["component"], line))
        floor = version(f["minimumSource"])
        need(floor[:2] < line, "minimumSource must be below the target line")
        need(isinstance(f["probes"], list) and f["probes"], "probes must be a non-empty list")
        for p in f["probes"]:
            need(isinstance(p, dict) and set(p) == {"from", "to"}, "probe keys")
            need(version(p["from"]) < floor, "probe source %s is not below the floor" % p["from"])
            need(version(p["to"])[:2] == line, "probe target %s is not on the target line" % p["to"])
        need(isinstance(f["safeFacts"], list) and f["safeFacts"], "safeFacts must be a non-empty list")
        seen = set()
        for x in f["safeFacts"]:
            need(isinstance(x, dict) and set(x) == {"side", "id", "boolValue"}, "fact keys")
            need(x["side"] in ("current", "proposed") and isinstance(x["id"], str) and x["id"]
                 and type(x["boolValue"]) is bool, "bad fact")
            need((x["side"], x["id"]) not in seen, "duplicate fact")
            seen.add((x["side"], x["id"]))
        need(isinstance(f["citations"], list) and f["citations"], "citations must be a non-empty list")
        for c in f["citations"]:
            need(isinstance(c, dict) and set(c) == {"url", "line"} and isinstance(c["url"], str)
                 and CITATION.fullmatch(c["url"]) and type(c["line"]) is int and c["line"] > 0,
                 "citation must be a GitHub file at a 40-hex commit with a line")
    return floors


def rule_probes(floor, entries):
    """(source, target) pairs of the component's own rules that reach the target line from below the floor."""
    low = version(floor["minimumSource"])
    line = tuple(int(x) for x in floor["targetLine"].split("."))
    found, used = set(), False
    for e in entries:
        rule = e["rule"]
        sub = rule["subject"]
        if e["project"] != floor["project"] or sub["component"] != floor["component"]:
            continue
        used = True
        sources = {version(sub["from"])}
        targets = {version(sub["to"])}
        rng = rule.get("range")
        if rng:
            f, t = rng["from"], rng["to"]
            first, end = version(f["gte"]), version(f["lt"])
            sources.add(first)
            below = (low[0], low[1], low[2] - 1)  # floor minus one patch
            if low[2] and first <= below < end:
                sources.add(below)
            start = max(version(t["gte"]), line + (0,))
            if start < version(t["lt"]):
                targets.add(start)
        found.update((s, t) for s in sources for t in targets if s < low and t[:2] == line)
    need(used, "no rule of project %s names component %s" % (floor["project"], floor["component"]))
    return {tuple(".".join(map(str, v)) for v in pair) for pair in found}


def document(floor, source, target):
    doc = {"schema": INPUT_SCHEMA, "authority": AUTHORITY}
    for side, ver in (("current", source), ("proposed", target)):
        facts = [{"id": x["id"], "state": "declared", "boolValue": x["boolValue"]} for x in floor["safeFacts"] if x["side"] == side]
        doc[side] = {"components": [{"component": floor["component"], "version": ver, "facts": facts}]}
    return doc


def judge(code, stdout, project):
    """(wrong PASS, error text or None) for one probe result."""
    if code == 0:
        return True, None
    try:
        report = json.loads(stdout)
        need(isinstance(report, dict), "not an object")
        verdicts = [report.get("assessment"), report.get("verdict")]
        check = report.get("check")
        if isinstance(check, dict):
            verdicts.append(check.get("assessment"))
        if any(isinstance(v, str) and v in PASS_VERDICTS for v in verdicts):
            return True, None
        if code not in (BLOCKED_EXIT, UNKNOWN_EXIT):
            return False, "exit %s proves nothing about the pair" % code
        need(report.get("project") == project, "report is for another project")
        claims = check["claims"]
        need(isinstance(claims, list), "claims is not a list")
        states = [(c["ruleId"], c["status"], c["operator"], c["reasonCode"]) for c in claims]
    except (ValueError, KeyError, TypeError):
        return False, "exit %s without a readable check report" % code
    version_block = any(s == "BLOCKED" and o in VERSION_OPERATORS for _, s, o, _ in states)
    for rid, status, operator, reason in states:
        if status == "BLOCKED" and operator in VERSION_OPERATORS:
            continue
        if status == "UNKNOWN" and reason in SETTLED_UNKNOWN:
            continue
        if status == "NOTICE" or (status == "PASS" and version_block):
            continue
        return False, "probe is not conclusive: rule %s is %s (%s, %s)" % (rid, status, operator, reason)
    if code == BLOCKED_EXIT and not version_block:
        return False, "exit 10 without a version block"
    return False, None


def run_probe(project, doc, name):
    path = os.path.join(qalib.TMP, "floors", name)
    qalib.write_private(path, json.dumps(doc))
    cmd = [qalib.BIN, "check", "cncf", "--project", project, "--input", path, "--now", qalib.NOW, "--format", "json"]
    try:
        r = subprocess.run(qalib.boxed(cmd), capture_output=True, text=True, timeout=TIMEOUT, errors="replace")
    except subprocess.TimeoutExpired:
        return -9, "", cmd
    return r.returncode, r.stdout, cmd


def cases(src, floors_path=FLOORS, runner=run_probe):
    """Cases of suite "rules", keys "floor|...". Never empty: a defect is an error case."""
    def broken(key, why):
        return qalib.case("rules", "floor|" + key, error=True, why=why)
    try:
        floors = load(floors_path)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        return [broken("list-unreadable", repr(e)[:300])]
    if not qalib.NOW:
        return [broken("no-clock", "QA_NOW is not set")]
    try:
        with open(os.path.join(src, RULES), "rb") as fh:
            entries = json.load(fh)["entries"]
        need(isinstance(entries, list) and entries, "rules.json has no entries")
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [broken("rules-unreadable", repr(e)[:300])]
    out = []
    for floor in floors:
        pairs = {(p["from"], p["to"]) for p in floor["probes"]}
        try:
            pairs |= rule_probes(floor, entries)
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            out.append(broken(floor["id"] + "|rules", repr(e)[:300]))  # the pinned pairs still run
        for i, (source, target) in enumerate(sorted(pairs)):
            key = "floor|%s|%s->%s" % (floor["id"], source, target)
            data = document(floor, source, target)
            try:
                code, stdout, cmd = runner(floor["project"], data, "%s-%d.json" % (floor["id"], i))
            except OSError as e:
                out.append(qalib.case("rules", key, error=True, why="probe did not run: %r" % e))
                continue
            wrong, why = judge(code, stdout, floor["project"])
            detail = {"project": floor["project"], "exit": code, "minimumSource": floor["minimumSource"]}
            if wrong or why:
                detail.update(why=why or "a source below the upstream floor passes", citations=floor["citations"],
                              input=json.dumps(data), command="prufyx " + " ".join(cmd[1:]))
            out.append(qalib.case("rules", key, wrongpass=wrong, mismatch=wrong, error=bool(why), **detail))
    return out
