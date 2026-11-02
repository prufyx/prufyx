"""Wrapper/obfuscation corpus for the qa-auto "rules" suite. Python 3 stdlib only, deterministic, no network.

A trigger is the declared-constraint input document (a dict) that makes one rule BLOCK. variants() returns semantically
equal (or deliberately mis-scoped) rewrites of it; the caller requires every one of them to be non-PASS (BLOCK, UNKNOWN
or an explicit reject all count; only a PASS is wrong).

Variant ids start with the class: enc. (encoding), struct. (structure), val. (value), wrap. (wrapper), scope. (scoping).
Value variants end in @cond (the condition fact) or @when (all appliesWhen facts together).
A variant is {"id", "data": bytes, "project": None | str}. The Helm values / ConfigMap / Secret wrappers of the design
apply to the scan-style inputs and are not part of this input shape.
"""
import base64, copy, json

# Variants that legitimately PASS in some cases (prerelease sorts below the bound; a side swap is a downgrade, both-sides
# a no-op upgrade): a PASS is acceptable there, a crash or hang is still a mismatch.
PASS_OK = {"val.version-prerelease@current", "val.version-prerelease@proposed", "scope.side-swap", "scope.both-sides"}


class Anchor:
    def __init__(self, name, obj):
        self.name, self.obj = name, obj


class Alias:
    def __init__(self, name):
        self.name = name


def _scalar(v):
    return json.dumps(v, ensure_ascii=False) if not isinstance(v, bool) and v is not None else {True: "true", False: "false", None: "null"}[v]


def yaml_emit(obj, ind=0):
    """Block-style YAML (strings double-quoted); Anchor/Alias nodes give anchors, aliases and merge keys."""
    pad = "  " * ind
    out = []
    if isinstance(obj, dict):
        if not obj:
            return pad + "{}\n"
        for k, v in obj.items():
            key = k if k == "<<" else json.dumps(k)
            if isinstance(v, Anchor):
                out.append(f"{pad}{key}: &{v.name}\n" + yaml_emit(v.obj, ind + 1))
            elif isinstance(v, Alias):
                out.append(f"{pad}{key}: *{v.name}\n")
            elif isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{key}:\n" + yaml_emit(v, ind + 1))
            elif isinstance(v, (dict, list)):
                out.append(f"{pad}{key}: {'{}' if isinstance(v, dict) else '[]'}\n")
            else:
                out.append(f"{pad}{key}: {_scalar(v)}\n")
    else:
        for v in obj:
            if isinstance(v, Alias):
                out.append(f"{pad}- *{v.name}\n")
            elif isinstance(v, (dict, list)) and v:
                body = yaml_emit(v, ind + 1)
                out.append(f"{pad}- " + body[len(pad) + 2:])
            elif isinstance(v, (dict, list)):
                out.append(f"{pad}- {'{}' if isinstance(v, dict) else '[]'}\n")
            else:
                out.append(f"{pad}- {_scalar(v)}\n")
    return "".join(out)


def _rev(o):
    if isinstance(o, dict):
        return {k: _rev(o[k]) for k in reversed(list(o))}
    if isinstance(o, list):
        return [_rev(x) for x in o]
    return o


def _facts(doc, side=None):
    for s in ([side] if side else ["current", "proposed"]):
        for comp in doc[s]["components"]:
            for f in comp["facts"]:
                yield s, comp, f


def _lookalike(s):
    for a, b in (("o", "о"), ("a", "а"), ("e", "е"), ("i", "і")):
        if a in s:
            return s.replace(a, b, 1)
    return s + "о"


def _text_variants(s):
    return [("case", s.capitalize() if s != s.capitalize() else s.upper()), ("upper", s.upper()), ("lead-space", " " + s),
            ("trail-space", s + " "), ("cyrillic", _lookalike(s)), ("trail-nul", s + "\x00"), ("zwsp", s[:1] + "​" + s[1:])]


def variants(doc, side, cond_id, when_ids, project):
    """doc: trigger input; side: side that holds the rule's facts; cond_id/when_ids: fact ids of the condition and the
    appliesWhen facts; project: the --project value. Returns a list of variant dicts."""
    out = []

    def add(vid, data, proj=None):
        if isinstance(data, str):
            data = data.encode("utf-8")
        out.append({"id": vid, "data": data, "project": proj})

    pretty = json.dumps(doc, indent=2, ensure_ascii=False)
    compact = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
    other = "current" if side == "proposed" else "proposed"

    # encoding
    add("enc.bom", b"\xef\xbb\xbf" + compact.encode())
    add("enc.crlf", pretty.replace("\n", "\r\n") + "\r\n")
    add("enc.tabs", json.dumps(doc, indent="\t"))
    add("enc.trailing-nul", compact.encode() + b"\x00")
    add("enc.utf16-bom", b"\xff\xfe" + compact.encode("utf-16-le"))
    add("enc.trailing-garbage", compact + "\n{}")
    add("enc.no-final-newline", compact)

    # structure
    add("struct.key-order-reversed", json.dumps(_rev(doc)))
    r = copy.deepcopy(doc)
    for _, comp, _f in _facts(r):
        comp["facts"] = list(reversed(comp["facts"]))
    add("struct.facts-reversed", json.dumps(r))
    body = compact[1:-1]
    add("struct.dup-key-first-empty", '{"%s":{"components":[]},%s}' % (side, body))
    add("struct.dup-key-last-empty", '{%s,"%s":{"components":[]}}' % (body, side))
    r = copy.deepcopy(doc)
    r["x-extra"] = {"unknown": 1}
    add("struct.extra-field", json.dumps(r))
    r = copy.deepcopy(doc)
    for _, _c, f in _facts(r):
        f["x-extra"] = "v"
    add("struct.extra-fact-field", json.dumps(r))
    r = copy.deepcopy(doc)
    for comp in r[side]["components"]:
        comp["facts"] = [dict(f) for f in comp["facts"]] + [dict(f) for f in comp["facts"]]
    add("struct.facts-duplicated", json.dumps(r))
    r = copy.deepcopy(doc)
    r[side]["components"] = [{"component": "pkg:github/qa/decoy", "version": "1.0.0", "facts": []}] + r[side]["components"]
    add("struct.decoy-component-first", json.dumps(r))
    r = copy.deepcopy(doc)
    r[side]["components"] = r[side]["components"] + [{"component": "pkg:github/qa/decoy", "version": "1.0.0", "facts": []}]
    add("struct.decoy-component-last", json.dumps(r))
    add("struct.yaml-block", yaml_emit(doc))
    add("struct.yaml-flow", compact.replace('":', '": '))
    r = copy.deepcopy(doc)
    first = r[side]["components"][0]["facts"][0]
    r[side]["components"][0]["facts"][0] = Alias("f0")
    add("struct.yaml-anchor-alias", yaml_emit({"x-defs": {"f0": Anchor("f0", first)}, **r}))
    r = copy.deepcopy(doc)
    first = r[side]["components"][0]["facts"][0]
    r[side]["components"][0]["facts"][0] = {"<<": Alias("f0"), "state": first["state"]}
    add("struct.yaml-merge-key", yaml_emit({"x-defs": {"f0": Anchor("f0", first)}, **r}))
    add("struct.yaml-multidoc-trigger-second", "{}\n---\n" + yaml_emit(doc))
    add("struct.yaml-multidoc-trigger-first", yaml_emit(doc) + "---\n{}\n")

    # value (condition fact alone, and all appliesWhen facts together)
    def mod(ids, fn):
        r = copy.deepcopy(doc)
        hit = False
        for _, _c, f in _facts(r, side):
            if f["id"] in ids:
                hit = fn(f) or hit
        return json.dumps(r) if hit else None

    for tag, ids in (("cond", {cond_id}), ("when", set(when_ids))):
        if not ids:
            continue
        def put(vid, fn):
            d = mod(ids, fn)
            if d is not None:
                add(f"val.{vid}@{tag}", d)

        def setbool(val):
            def fn(f):
                if "boolValue" not in f:
                    return False
                f["boolValue"] = val
                return True
            return fn
        for vid, val in (("bool-str-true", "true"), ("bool-str-TRUE", "TRUE"), ("bool-str-True", "True"), ("bool-int-1", 1),
                         ("bool-str-1", "1"), ("bool-str-yes", "yes"), ("bool-null", None)):
            put(vid, setbool(val))

        def strmod(key, fn2):
            def fn(f):
                if key == "members":
                    sv = f.get("setValue")
                    if not sv or not sv["members"]:
                        return False
                    sv["members"] = [fn2(sv["members"][0])] + sv["members"][1:]
                    return True
                if key not in f:
                    return False
                f[key] = fn2(f[key])
                return True
            return fn
        for key in ("enumValue", "members"):
            sample = next((f.get("enumValue") if key == "enumValue" else (f.get("setValue") or {"members": [None]})["members"][0]
                           for _, _c, f in _facts(doc, side) if f["id"] in ids and (f.get("enumValue") if key == "enumValue" else f.get("setValue"))), None)
            if not sample:
                continue
            pre = "enum" if key == "enumValue" else "set"
            for name, _ in _text_variants(sample):
                if name in ("case", "upper") and len(sample) == 1:
                    continue  # one-letter flags are case-sensitive options of their own (falco -m vs -M): not the same input
                put(f"{pre}-{name}", strmod(key, lambda s, n=name: dict(_text_variants(s))[n]))
        def setmore(f):
            sv = f.get("setValue")
            if not sv:
                return False
            sv["members"] = sorted(sv["members"] + ["qa-benign-member"])
            return True
        put("set-extra-member", setmore)
        def setincomplete(f):
            sv = f.get("setValue")
            if not sv:
                return False
            sv["complete"] = False
            return True
        put("set-incomplete", setincomplete)
        if tag == "cond":
            put("state-missing", lambda f: f.update(state="missing") or True)
            put("state-unknown", lambda f: f.update(state="unknown") or True)
            put("state-upper", lambda f: f.update(state="DECLARED") or True)

    # versions (both sides, each way)
    for vid, fn in (("v-prefix", lambda v: "v" + v), ("trailing-dot", lambda v: v + "."), ("build-meta", lambda v: v + "+qa.1"),
                    ("prerelease", lambda v: v + "-rc.1"), ("leading-space", lambda v: " " + v), ("zero-pad", lambda v: ".".join(
                        p.zfill(2) for p in v.split(".")))):
        for s in ("current", "proposed"):
            r = copy.deepcopy(doc)
            for comp in r[s]["components"]:
                comp["version"] = fn(comp["version"])
            add(f"val.version-{vid}@{s}", json.dumps(r))

    # wrapper
    add("wrap.list", json.dumps([doc]))
    add("wrap.items", json.dumps({"items": [doc]}))
    add("wrap.kind-list", json.dumps({"apiVersion": "v1", "kind": "List", "items": [doc]}))
    add("wrap.under-key", json.dumps({"spec": doc}))
    add("wrap.string-embedded", json.dumps(compact))
    add("wrap.configmap-data", json.dumps({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "qa"}, "data": {"input.json": compact}}))
    add("wrap.secret-base64", json.dumps({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "qa"},
                                          "data": {"input.json": base64.b64encode(compact.encode()).decode()}}))
    add("wrap.empty-doc", "{}")
    add("wrap.empty-input", "")

    # scoping
    r = copy.deepcopy(doc)
    r[other]["components"], r[side]["components"] = r[side]["components"], r[other]["components"]
    add("scope.side-swap", json.dumps(r))
    r = copy.deepcopy(doc)
    r[other] = copy.deepcopy(r[side])
    add("scope.both-sides", json.dumps(r))
    r = copy.deepcopy(doc)
    for s in ("current", "proposed"):
        for comp in r[s]["components"]:
            comp["component"] = comp["component"].upper()
    add("scope.component-upper", json.dumps(r))
    r = copy.deepcopy(doc)
    for s in ("current", "proposed"):
        for comp in r[s]["components"]:
            comp["component"] = comp["component"].replace("pkg:", "pkg:/", 1)
    add("scope.component-purl-slash", json.dumps(r))
    r = copy.deepcopy(doc)
    r["schema"] = r["schema"].replace("v1alpha1", "v1alpha2")
    add("scope.schema-other-version", json.dumps(r))
    r = copy.deepcopy(doc)
    r["authority"] = "OBSERVED"
    add("scope.authority-other", json.dumps(r))
    add("scope.project-upper", compact, project.upper())
    add("scope.project-capitalized", compact, project.capitalize() if project != project.capitalize() else project + "x")
    add("scope.project-underscore", compact, project.replace("-", "_") if "-" in project else project + "_")
    add("scope.project-trailing-space", compact, project + " ")
    return out
