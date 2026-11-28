"""Source floors: the oracle's own list of upgrades that upstream does not allow from an older source. Python 3 stdlib only.

source_floors.json sits next to this file and is read from there only, never from the checkout under test. Each floor
names a project, a target minor line, the lowest admitted source version for that line (basis "upstream": the number is
upstream's; basis "derived": a conservative lower bound derived from upstream text that names no number), pinned upstream
citations, the source/target pairs to probe and the facts that declare every checked condition safe.

Rule sources: source_floors.json classifies every data file a non-test Go file embeds and every rules.json outside
vendor and testdata. "rules" files are scanned and probed on their own check route. A "verdict" file decides a check
outside the rule format and must not name a floored project or component. A "support" file decides no version pair and
must not hold a rule. An unclassified or unreadable file, or a listed rules file that no Go file embeds, is an error and
no floor is then reported clean. Checks written only as Go code, and signed knowledge loaded at run time, are not read.

Static check (no binary, no clock): every entry of every "rules" file is read. A rule of a floored component that
can PASS (any operator that is not a version block or a notice, evidence not withdrawn) must not cover any source below
the floor with a target on the floored line, through its anchor pair, its range or its crossing; a line attestation of the
floored line must not list a source release below the floor. Each violation is a wrong PASS. A rule or attestation of a
floored component that cannot be read in full is an error.

Probes: for each pinned pair, and for each rules entry of the component that reaches the target line from below the floor,
the check route of the file that names the component runs with those facts (`check cncf`, or `check batch` with one
community_project item). Exit 0 is a wrong PASS. A non-zero result counts only when it does not depend on the probe being weak: exit 10 or
11 with a report in which every claim is a version block, or UNKNOWN because the pair is not reviewed or the rule
evidence is withdrawn or stale. Everything else (a missing or blocking fact, another exit code, an unreadable report, a
bad floor file, no QA_NOW) is an error. There is no allow-list.

Release order entries (an entry with "kind" in place of a target line and a minimum) hold upstream limits that one
minimum cannot express. Each lists the upstream releases it knows. "no-skip": releases below "blockedBelow" are taken one
at a time, patch releases included; a violation is a pair from a source below that version which skips a listed release
or has an unlisted end below it. "release-order": the target release must not be older than the source release; a
violation is an unlisted end or a source released after the target. A pair that does not go forward violates both. A
range or crossing of a rule that can PASS, and a line attestation, cannot be compared release by release: they are
violations for a "release-order" component, and for a "no-skip" component when they start below "blockedBelow". Probes of
these entries carry their own safe facts and only the listed pairs are probed.

A floor covers only what it lists: a target line without a floor is not checked.
"""
import datetime, fnmatch, json, os, re, subprocess

import qalib

HERE = os.path.dirname(os.path.abspath(__file__))
FLOORS = os.path.join(HERE, "source_floors.json")
RULES = "cli/internal/cncfcheck/data/rules.json"
PROJECT_RULES = "cli/internal/projectcheck/data/rules.json"
CNCF, COMMUNITY = "cncf", "community_project"
ROUTES = (CNCF, COMMUNITY)
PLAN_SCHEMA = "prufyx.io/batch-check-plan/v1alpha1"
PLAN_AUTHORITY = "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS"
BATCH_SCHEMA = "prufyx.io/batch-check-report/v1alpha1"
EMBED = re.compile(r"^[ \t]*//go:embed(?:[ \t]+(.*))?$", re.M)
EMBED_FIELD = re.compile(r'"[^"\\]*"|`[^`]*`|[^\s"`]+|\S')
SKIP_DIRS = {".git", "vendor", "testdata"}
SCHEMA = "prufyx.io/qa-source-floors/v1"
INPUT_SCHEMA = "prufyx.io/operator-declared-constraint-input/v1alpha1"
AUTHORITY = "OPERATOR_DECLARED_MINIMIZED"
TIMEOUT = 20
BLOCKED_EXIT, UNKNOWN_EXIT = 10, 11
PASS_VERDICTS = {"PASS", "SCOPE_COMPLETE_PASS"}
VERSION_OPERATORS = {"require_intermediate_version", "forbid_target_version"}  # block on the pair alone, not on a fact
SETTLED_UNKNOWN = {"RULE_TRANSITION_NOT_REVIEWED", "RULE_EVIDENCE_WITHDRAWN", "RULE_EVIDENCE_STALE"}
KEYS = {"id", "project", "component", "targetLine", "minimumSource", "basis", "note", "probes", "safeFacts", "citations"}
BASES = {"upstream", "derived"}
NO_SKIP, RELEASE_ORDER = "no-skip", "release-order"
ORDER_KEYS = {"id", "project", "component", "kind", "basis", "note", "releases", "probes", "citations"}
KINDS = {NO_SKIP: ORDER_KEYS | {"blockedBelow"}, RELEASE_ORDER: ORDER_KEYS}
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# Operators whose claim is never PASS. Every other operator, known or new, is treated as able to PASS.
NEVER_PASS = {"require_intermediate_version", "forbid_target_version", "notice_one_way", "notice_set_member_present",
              "notice_set_member_absent"}
# A key outside these sets could widen what a rule matches, so it makes a floored rule unreadable.
RULE_KEYS = {"id", "operator", "subject", "range", "crossing", "condition", "setCondition", "appliesWhen", "dependency",
             "intermediate", "severity", "evidence", "nextAction", "reasonCode"}
SUBJECT_KEYS = {"component", "from", "to"}
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


def read_json(path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"), object_pairs_hook=unique)


def check_sources(sources):
    need(isinstance(sources, dict) and set(sources) == {"rules", "verdict", "support"}, "ruleSources keys")
    rules = sources["rules"]
    need(isinstance(rules, dict) and rules and all(isinstance(r, str) and r in ROUTES for r in rules.values()),
         "ruleSources.rules must map files to a known route")
    need(set(rules.values()) == set(ROUTES), "every check route needs its rules file")
    seen = list(rules)
    for kind in ("verdict", "support"):
        need(isinstance(sources[kind], list) and all(isinstance(p, str) and p for p in sources[kind]),
             "ruleSources.%s must be a list of paths" % kind)
        seen += sources[kind]
    need(len(seen) == len(set(seen)), "a rule source is classified twice")
    # A wildcard only stands for the last part of a support file name.
    for p in list(rules) + sources["verdict"]:
        need(not set(p) & set("*?["), "wildcard not allowed: %s" % p)
    for p in sources["support"]:
        need(not set(os.path.dirname(p)) & set("*?[") and not os.path.basename(p).startswith(("*", "?", "[")),
             "wildcard too wide: %s" % p)


def load(path):
    """The validated floor list; any defect raises."""
    return parse(path)[0]


def parse(path):
    """(floors, rule sources) of the validated list file; any defect raises."""
    data = read_json(path)
    need(isinstance(data, dict) and set(data) == {"schema", "ruleSources", "floors"} and data["schema"] == SCHEMA,
         "schema or top-level keys")
    check_sources(data["ruleSources"])
    floors = data["floors"]
    need(isinstance(floors, list) and floors, "floors must be a non-empty list")
    ids, lines = set(), set()
    for f in floors:
        need(isinstance(f, dict), "floor is not an object")
        if "kind" in f:
            check_order(f, ids, lines)
            continue
        need(set(f) == KEYS, "floor keys must be exactly %s" % sorted(KEYS))
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
        need(isinstance(f["basis"], str) and f["basis"] in BASES, "basis must be one of %s" % sorted(BASES))
        need(isinstance(f["note"], str) and f["note"].strip(), "note must be a non-empty string")
        need(isinstance(f["probes"], list) and f["probes"], "probes must be a non-empty list")
        for p in f["probes"]:
            need(isinstance(p, dict) and set(p) == {"from", "to"}, "probe keys")
            need(version(p["from"]) < floor, "probe source %s is not below the floor" % p["from"])
            need(version(p["to"])[:2] == line, "probe target %s is not on the target line" % p["to"])
        check_facts(f["safeFacts"])
        check_citations(f["citations"])
    return floors, data["ruleSources"]


def check_facts(facts):
    need(isinstance(facts, list) and facts, "safeFacts must be a non-empty list")
    seen = set()
    for x in facts:
        need(isinstance(x, dict) and set(x) == {"side", "id", "boolValue"}, "fact keys")
        need(x["side"] in ("current", "proposed") and isinstance(x["id"], str) and x["id"]
             and type(x["boolValue"]) is bool, "bad fact")
        need((x["side"], x["id"]) not in seen, "duplicate fact")
        seen.add((x["side"], x["id"]))


def check_citations(citations):
    need(isinstance(citations, list) and citations, "citations must be a non-empty list")
    for c in citations:
        need(isinstance(c, dict) and set(c) == {"url", "line"} and isinstance(c["url"], str)
             and CITATION.fullmatch(c["url"]) and type(c["line"]) is int and c["line"] > 0,
             "citation must be a GitHub file at a 40-hex commit with a line")


def check_order(f, ids, taken):
    """Validate one release order entry; ids and taken hold what earlier entries claimed."""
    kind = f["kind"]
    need(isinstance(kind, str) and kind in KINDS, "unknown kind: %r" % (kind,))
    need(set(f) == KINDS[kind], "%s keys must be exactly %s" % (kind, sorted(KINDS[kind])))
    for k in ("id", "project"):
        need(isinstance(f[k], str) and SLUG.fullmatch(f[k]), "bad %s" % k)
    need(isinstance(f["component"], str) and f["component"].startswith("pkg:"), "bad component")
    need(f["id"] not in ids and (f["component"], kind) not in taken, "duplicate floor %s" % f["id"])
    ids.add(f["id"])
    taken.add((f["component"], kind))
    need(isinstance(f["basis"], str) and f["basis"] in BASES, "basis must be one of %s" % sorted(BASES))
    need(isinstance(f["note"], str) and f["note"].strip(), "note must be a non-empty string")
    releases = f["releases"]
    if kind == NO_SKIP:
        end = version(f["blockedBelow"])
        need(isinstance(releases, list) and len(releases) > 1, "releases must be a list of at least two versions")
        listed = [version(r) for r in releases]
        need(listed == sorted(set(listed)) and listed[-1] < end, "releases must ascend and stay below blockedBelow")
    else:
        need(isinstance(releases, dict) and len(releases) > 1, "releases must map at least two versions to dates")
        for v, day in releases.items():
            version(v)
            need(isinstance(day, str) and DATE.fullmatch(day), "bad release date: %r" % (day,))
            datetime.date.fromisoformat(day)
    need(isinstance(f["probes"], list) and f["probes"], "probes must be a non-empty list")
    pairs = set()
    for p in f["probes"]:
        need(isinstance(p, dict) and set(p) == {"from", "to", "safeFacts"}, "probe keys")
        pair = (version(p["from"]), version(p["to"]))
        need(order_violation(f, *pair), "probe %s -> %s breaks no limit" % (p["from"], p["to"]))
        need(pair not in pairs, "duplicate probe")
        pairs.add(pair)
        check_facts(p["safeFacts"])
    check_citations(f["citations"])


def dotted(v):
    return ".".join(map(str, v))


def order_violation(entry, source, target):
    """Why the exact pair (version tuples) breaks a release order entry, or None."""
    if source >= target:
        return "the pair does not go forward"
    if entry["kind"] == NO_SKIP:
        end = version(entry["blockedBelow"])
        if source >= end:
            return None
        listed = [version(r) for r in entry["releases"]]
        for v in (source, target):
            if v < end and v not in listed:
                return "%s is not a listed upstream release" % dotted(v)
        skipped = [dotted(r) for r in listed if source < r < target]
        return "the upgrade skips release %s" % ", ".join(skipped) if skipped else None
    days = {version(v): day for v, day in entry["releases"].items()}
    for v in (source, target):
        if v not in days:
            return "%s is not a listed upstream release" % dotted(v)
    if days[source] > days[target]:
        return "%s was released %s, after %s (%s)" % (dotted(source), days[source], dotted(target), days[target])
    return None


def rule_probes(floor, entries):
    """(source, target) pairs of the component's own rules that reach the target line from below the floor.
    None when no rule of the floor's project names the component."""
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
    if not used:
        return None
    return {tuple(".".join(map(str, v)) for v in pair) for pair in found}


def expand(base, pattern):
    """Files one go:embed pattern of the package directory base takes in; nothing matched raises."""
    if pattern.startswith("all:"):
        pattern = pattern[4:]
    parts = pattern.split("/")
    need(all(p not in ("", ".", "..") for p in parts), "unsupported embed pattern %r" % pattern)
    paths = [base]
    for part in parts:
        found = []
        for p in paths:
            if set(part) & set("*?["):
                if os.path.isdir(p):
                    found += [os.path.join(p, n) for n in os.listdir(p) if fnmatch.fnmatchcase(n, part)]
            elif os.path.exists(os.path.join(p, part)):
                found.append(os.path.join(p, part))
        paths = found
    need(paths, "embed pattern %r matches nothing" % pattern)
    files = []

    def failed(e):
        raise e
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p, onerror=failed):
                files += [os.path.join(root, n) for n in names]
        else:
            files.append(p)
    return files


def discover(src):
    """(embedded data files, rules.json files, [(path, error)]) of the checkout, as repository paths."""
    embedded, named, errors = set(), set(), []

    def failed(e):
        errors.append((os.path.relpath(e.filename or src, src), repr(e)))
    for root, dirs, names in os.walk(src, onerror=failed):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            path = os.path.join(root, n)
            rel = os.path.relpath(path, src)
            if n == "rules.json":
                named.add(rel)
            if not n.endswith(".go") or n.endswith("_test.go"):
                continue
            try:
                with open(path, "rb") as fh:
                    text = fh.read().decode("utf-8")
                for m in EMBED.finditer(text.replace("\r\n", "\n")):
                    fields = EMBED_FIELD.findall(m.group(1) or "")
                    need(fields, "empty embed directive")
                    for field in fields:
                        need(field not in ('"', "`"), "unreadable embed pattern")
                        if field[0] in '"`':
                            field = field[1:-1]
                        embedded.update(os.path.relpath(f, src) for f in expand(root, field) if not f.endswith(".go"))
            except (OSError, ValueError) as e:
                errors.append((rel, repr(e)))
    return embedded, named, errors


def walk_json(value):
    """Every object and every string (keys included) of a JSON value."""
    stack = [value]
    while stack:
        v = stack.pop()
        yield v
        if isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)


def classify(sources, rel):
    if rel in sources["rules"]:
        return "rules"
    if rel in sources["verdict"]:
        return "verdict"
    for pattern in sources["support"]:
        if os.path.dirname(rel) == os.path.dirname(pattern) and fnmatch.fnmatchcase(os.path.basename(rel),
                                                                                    os.path.basename(pattern)):
            return "support"
    return None


def inventory(src, floors, sources):
    """[(repository path, why)]: every defect that leaves a rule source unchecked."""
    embedded, named, errors = discover(src)
    slugs = {f["project"] for f in floors}
    needles = set()
    for f in floors:
        needles.add(f["component"].lower())
        if f["component"].startswith("pkg:github/"):
            needles.add("github.com/" + f["component"][len("pkg:github/"):].lower())
    for rel in sorted(sources["rules"]):
        if rel not in embedded:
            errors.append((rel, "listed rules file is not embedded by any Go file"))
    for rel in sorted(embedded | named):
        kind = classify(sources, rel)
        if kind is None:
            errors.append((rel, "unclassified rule source"))
            continue
        if kind == "rules":
            continue  # read in full by read_knowledge
        try:
            if os.path.basename(rel) == "rules.json":
                raise ValueError("a rules.json must be classified as rules")
            for v in walk_json(read_json(os.path.join(src, rel))):
                if kind == "support":
                    need(not (isinstance(v, dict) and isinstance(v.get("operator"), str) and "subject" in v),
                         "a support file holds a rule")
                elif isinstance(v, str):
                    need(v not in slugs and not any(n in v.lower() for n in needles),
                         "a verdict file the check cannot compare names a floored project: %s" % v[:80])
        except (OSError, ValueError, RecursionError) as e:
            errors.append((rel, repr(e)))
    return errors


def read_knowledge(src, sources):
    """[(repository path, entries, line attestations)] of every listed rules file; all of them must read."""
    out = []
    for rel in sorted(sources["rules"]):
        data = read_json(os.path.join(src, rel))
        need(isinstance(data, dict), "%s is not an object" % rel)
        entries, attested = data.get("entries"), data.get("lineAttestations", [])
        need(isinstance(entries, list) and entries, "%s has no entries" % rel)
        need(isinstance(attested, list), "%s lineAttestations is not a list" % rel)
        out.append((rel, entries, attested))
    return out


def interval(bound):
    need(isinstance(bound, dict) and set(bound) == {"gte", "lt"}, "bound keys must be gte and lt")
    low, end = version(bound["gte"]), version(bound["lt"])
    need(low < end, "empty bound")
    return low, end


def coverage(rule):
    """(match kind, lowest source, first target, end of targets) for every region of pairs the rule covers."""
    need(set(rule) <= RULE_KEYS, "unknown rule keys: %s" % sorted(set(rule) - RULE_KEYS))
    sub = rule["subject"]
    need(set(sub) == SUBJECT_KEYS, "subject keys must be exactly %s (a chart subject cannot be compared)" % sorted(SUBJECT_KEYS))
    to = version(sub["to"])
    out = [("anchor", version(sub["from"]), to, (to[0], to[1], to[2] + 1))]
    if "range" in rule:
        rng = rule["range"]
        need(isinstance(rng, dict) and {"from", "to"} <= set(rng) <= {"from", "to", "bounds"}, "range keys")
        first, end = interval(rng["to"])
        out.append(("range", interval(rng["from"])[0], first, end))
    if "crossing" in rule:  # the engine never passes a crossing match; covered all the same
        crossing = rule["crossing"]
        need(isinstance(crossing, dict) and set(crossing) == {"change", "horizon"}, "crossing keys")
        change, end = version(crossing["change"]["version"]), version(crossing["horizon"]["lt"])
        need(change < end, "empty crossing")
        out.append(("crossing", (0, 0, 0), change, end))
    return out


def limit(floor):
    """The detail that names what a floor or release order entry demands."""
    return {"kind": floor["kind"]} if "kind" in floor else {"minimumSource": floor["minimumSource"]}


def pinned_pairs(floor):
    """{(source, target): safe facts} of the listed probes."""
    return {(p["from"], p["to"]): p["safeFacts"] if "kind" in floor else floor["safeFacts"] for p in floor["probes"]}


def planned(floor, entries):
    """{(source, target): safe facts} to probe for one rules file; None when no rule of the project names the component."""
    if "kind" in floor:
        named = [e for e in entries
                 if e["project"] == floor["project"] and e["rule"]["subject"]["component"] == floor["component"]]
        return pinned_pairs(floor) if named else None
    derived = rule_probes(floor, entries)
    if derived is None:
        return None
    found = {pair: floor["safeFacts"] for pair in derived}
    found.update(pinned_pairs(floor))
    return found


def order_reasons(entry, regions):
    """Why the regions of a rule that can PASS break a release order entry."""
    out = []
    for kind, source, target, _ in regions:
        if kind == "anchor":
            reason = order_violation(entry, source, target)
        elif entry["kind"] == RELEASE_ORDER or source < version(entry["blockedBelow"]):
            reason = "a %s from %s cannot be compared release by release" % (kind, dotted(source))
        else:
            reason = None
        if reason:
            out.append(reason)
    return out


def static_cases(floors, knowledge):
    """One wrong PASS per (floor, rule or attestation) that reaches the floored line from below the floor, and per
    (release order entry, rule or attestation) that breaks it."""
    out, dirty = [], set()
    by_component, orders = {}, {}
    for floor in floors:
        group = by_component.setdefault(floor["component"], [])
        if "kind" in floor:
            orders.setdefault(floor["component"], []).append(floor)
        else:
            group.append((floor, version(floor["minimumSource"]), tuple(int(x) for x in floor["targetLine"].split("."))))

    def violation(floor, rel, name, **detail):
        dirty.add(floor["id"])
        out.append(qalib.case("rules", "floor|static|%s|%s|%s" % (floor["id"], rel, name), wrongpass=True, mismatch=True,
                              project=floor["project"], file=rel, basis=floor["basis"], citations=floor["citations"],
                              **dict(limit(floor), **detail)))

    def unreadable(rel, name, why, component):
        # Without a component it could belong to any floor: none is reported clean.
        dirty.update(f["id"] for f in floors if component is None or f["component"] == component)
        out.append(qalib.case("rules", "floor|static|unreadable|%s|%s" % (rel, name), error=True, why=repr(why)[:300]))

    for rel, entries, attested in knowledge:
        for i, entry in enumerate(entries):
            name, component = "entry-%d" % i, None
            try:
                rule = entry["rule"]
                found = rule["subject"]["component"]
                need(isinstance(found, str) and found, "no subject component")
                component = found
                if component not in by_component:
                    continue
                need(isinstance(rule["id"], str) and rule["id"], "no rule id")
                name = rule["id"]
                regions = coverage(rule)
                operator, evidence = rule.get("operator"), rule.get("evidence")
                if isinstance(evidence, dict) and evidence.get("state") == "withdrawn":
                    continue
                if isinstance(operator, str) and operator in NEVER_PASS:
                    continue
                for floor, low, line in by_component[component]:
                    start, stop = line + (0,), (line[0], line[1] + 1, 0)
                    hits = [{"match": kind, "lowestSource": ".".join(map(str, source))}
                            for kind, source, first, end in regions
                            if source < low and max(first, start) < min(end, stop)]
                    if hits:
                        violation(floor, rel, name, rule=name, operator=operator, covered=hits,
                                  why="a rule that can PASS covers a source below the floor")
                for entry_order in orders.get(component, []):
                    why = order_reasons(entry_order, regions)
                    if why:
                        violation(entry_order, rel, name, rule=name, operator=operator,
                                  why="a rule that can PASS breaks the release order: " + "; ".join(why))
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                unreadable(rel, name, e, component)
        for i, att in enumerate(attested):
            name, component = "attestation-%d" % i, None
            try:
                found = att["component"]
                need(isinstance(found, str) and found, "no attestation component")
                component = found
                if component not in by_component:
                    continue
                need(isinstance(att["line"], str) and LINE.fullmatch(att["line"]), "bad attestation line")
                for floor, low, line in by_component[component]:
                    if tuple(int(x) for x in att["line"].split(".")) != line:
                        continue
                    releases = att["releases"]["from"]
                    need(isinstance(releases, list) and releases, "no source releases")
                    below = [r["version"] for r in releases if version(r["version"]) < low]
                    if below:
                        violation(floor, rel, name, sources=below,
                                  why="a line attestation covers source releases below the floor")
                for entry_order in orders.get(component, []):
                    releases = att["releases"]["from"]
                    need(isinstance(releases, list) and releases, "no source releases")
                    covered = [(r["version"], version(r["version"])) for r in releases]
                    if entry_order["kind"] == NO_SKIP:
                        covered = [c for c in covered if c[1] < version(entry_order["blockedBelow"])]
                    if covered:
                        violation(entry_order, rel, name, sources=[c[0] for c in covered],
                                  why="a line attestation cannot be compared release by release")
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                unreadable(rel, name, e, component)
    out.extend(qalib.case("rules", "floor|static|" + f["id"], project=f["project"]) for f in floors if f["id"] not in dirty)
    return out


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


def judge_batch(code, stdout, project):
    """judge() for one `check batch` probe with a single community_project item."""
    if code == 0:
        return True, None
    try:
        report = json.loads(stdout)
        need(isinstance(report, dict), "not an object")
        items = report["items"]
        need(isinstance(items, list) and all(isinstance(i, dict) for i in items), "items is not a list of objects")
        verdicts = [report.get("aggregateCategory"), report.get("decision")]
        for i in items:
            verdicts += [i.get("outcome"), i.get("category")]
        if any(isinstance(v, str) and v in PASS_VERDICTS for v in verdicts):
            return True, None
        need(report.get("schema") == BATCH_SCHEMA and len(items) == 1, "not a one-item batch report")
        need(items[0].get("kind") == COMMUNITY and items[0].get("project") == project, "item is for another project")
        child = items[0]["report"]
        need(isinstance(child, dict), "item report is not an object")
    except (ValueError, KeyError, TypeError):
        return False, "exit %s without a readable batch report" % code
    return judge(code, json.dumps(child), project)


def run_probe(route, project, doc, name):
    if route == CNCF:
        path = os.path.join(qalib.TMP, "floors", name + ".json")
        qalib.write_private(path, json.dumps(doc))
        cmd = [qalib.BIN, "check", "cncf", "--project", project, "--input", path]
    else:
        root = os.path.realpath(os.path.join(qalib.TMP, "floors", name))
        qalib.write_private(os.path.join(root, "input.json"), json.dumps(doc))
        versions = [doc[side]["components"][0]["version"] for side in ("current", "proposed")]
        plan = {"schema": PLAN_SCHEMA, "authority": PLAN_AUTHORITY, "knowledge": {"mode": "embedded_only"},
                "items": [{"id": "floor", "kind": COMMUNITY, "project": project, "from": versions[0], "to": versions[1],
                           "inputPath": "input.json"}]}
        qalib.write_private(os.path.join(root, "plan.json"), json.dumps(plan))
        cmd = [qalib.BIN, "check", "batch", "--plan", os.path.join(root, "plan.json"), "--root", root]
    cmd += ["--now", qalib.NOW, "--format", "json"]
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
        floors, sources = parse(floors_path)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        return [broken("list-unreadable", repr(e)[:300])]
    try:
        unchecked = [broken("source|" + rel, why[:300]) for rel, why in inventory(src, floors, sources)]
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        unchecked = [broken("sources-unreadable", repr(e)[:300])]
    try:
        knowledge = read_knowledge(src, sources)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        return unchecked + [broken("rules-unreadable", repr(e)[:300])]
    out = static_cases(floors, knowledge)
    if unchecked:  # an unchecked source could reach any floor: none is reported clean
        out = unchecked + [c for c in out if c["wrongpass"] or c["error"]]
    if not qalib.NOW:
        return out + [broken("no-clock", "QA_NOW is not set")]
    for floor in floors:
        pinned = pinned_pairs(floor)
        routes = {}
        for rel, entries, _ in knowledge:
            route = sources["rules"][rel]
            try:
                found = planned(floor, entries)
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                out.append(broken("%s|rules|%s" % (floor["id"], route), repr(e)[:300]))
                routes.setdefault(route, {}).update(pinned)  # the pinned pairs still run
                continue
            if found is not None:
                routes.setdefault(route, {}).update(found)
        if not routes:
            out.append(broken(floor["id"] + "|rules", "no rule of project %s names component %s"
                              % (floor["project"], floor["component"])))
            routes = {route: pinned for route in ROUTES}
        probes = sorted((route, pair) for route, pairs in routes.items() for pair in pairs)
        for i, (route, (source, target)) in enumerate(probes):
            key = "floor|%s|%s->%s" % (floor["id"], source, target)
            if len(routes) > 1:
                key += "|" + route
            data = document(dict(floor, safeFacts=routes[route][(source, target)]), source, target)
            try:
                code, stdout, cmd = runner(route, floor["project"], data, "%s-%d" % (floor["id"], i))
            except OSError as e:
                out.append(qalib.case("rules", key, error=True, why="probe did not run: %r" % e))
                continue
            wrong, why = (judge if route == CNCF else judge_batch)(code, stdout, floor["project"])
            detail = dict(limit(floor), project=floor["project"], route=route, exit=code)
            if wrong or why:
                detail.update(why=why or "an upgrade upstream does not allow passes", citations=floor["citations"],
                              input=json.dumps(data), command="prufyx " + " ".join(cmd[1:]))
            out.append(qalib.case("rules", key, wrongpass=wrong, mismatch=wrong, error=bool(why), **detail))
    return out
