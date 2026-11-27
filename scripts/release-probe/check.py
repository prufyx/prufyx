#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Recomputes every classification from the raw records and requires the full
product of releases x cases x repeats. Records are untrusted text: parsed,
never executed. Exit 1 when the records are incomplete or inconsistent; a
pair that fails on complete records is a result, not a checker error."""

import argparse
import glob
import json
import lzma
import os
import sys

import fetch
import judge
import spec


def load(directory):
    metas, rows = [], []
    for path in sorted(glob.glob(os.path.join(directory, "**", "*.meta.json"), recursive=True)):
        with open(path, encoding="utf-8") as f:
            metas.append(json.load(f))
    for path in sorted(glob.glob(os.path.join(directory, "**", "*.cases.jsonl.xz"),
                                 recursive=True)):
        with lzma.open(path, "rt", encoding="utf-8") as f:
            rows.extend(json.loads(line) for line in f)
    return metas, rows


def check_pair(pair, metas, rows, releases, snapshot_sha256=None, arches=spec.ARCHES):
    """The verdict of one pair from its records."""
    conf = spec.PAIRS[pair]
    sides = {side: releases[conf["project"]][conf[side]] for side in ("from", "to")}
    errors = []          # incomplete or inconsistent records
    refusals = []        # reasons that withhold the whole pair
    not_published = []
    item_fail = {i["name"]: [] for i in conf["items"]}

    metas = [m for m in metas if m.get("pair") == pair]
    rows = [r for r in rows if r.get("pair") == pair]
    for extra in sorted({m.get("arch") for m in metas} | {r.get("arch") for r in rows}):
        if extra not in arches:
            errors.append("records for an unexpected platform %r" % extra)

    for arch in arches:
        fetched = {}
        group = [m for m in metas if m.get("arch") == arch]
        shards = {m.get("shards") for m in group}
        if len(shards) != 1 or sorted(m.get("shard") for m in group) != list(range(
                next(iter(shards)) if shards else 0)):
            errors.append("%s: shard set is incomplete or duplicated" % arch)
        for meta in group:
            for tag, record in meta["releases"].items():
                if tag in fetched:
                    errors.append("%s %s: fetched twice" % (arch, tag))
                fetched[tag] = record
            listed = meta["release_set"]
            if snapshot_sha256 and listed.get("snapshot_sha256") != snapshot_sha256:
                errors.append("%s: records used another lines snapshot" % arch)
            for side in ("from", "to"):
                line = listed["lines"].get(conf[side])
                if line is None:
                    errors.append("%s: release set lacks line %s" % (arch, conf[side]))
                    continue
                refusals.extend(fetch.release_set_problems(
                    sides[side], line["snapshot"], line["live"]))
        wanted = {r["tag"] for side in sides for r in sides[side]}
        for tag in sorted(set(fetched) - wanted):
            errors.append("%s %s: release outside the pinned set" % (arch, tag))

        index = {}
        for row in (r for r in rows if r.get("arch") == arch):
            key = (row.get("tag"), row.get("case"), row.get("rep"))
            if key in index:
                errors.append("%s %s: duplicate record" % (arch, key))
            index[key] = row

        for side in ("from", "to"):
            for release in sides[side]:
                tag = release["tag"]
                record = fetched.get(tag)
                if record is None:
                    errors.append("%s %s: release missing from the records" % (arch, tag))
                    continue
                if record.get("commit") != release["commit"] or record.get("side") != side:
                    errors.append("%s %s: fetch record names another commit or side" % (arch, tag))
                    continue
                status = record.get("status")
                if status == "not-published" and arch != "amd64":
                    not_published.append("%s %s: %s" % (arch, tag, record.get("reason")))
                    continue
                if status != "ok":
                    refusals.append("%s %s: no accepted artifact: %s" % (
                        arch, tag, record.get("reason")))
                    continue
                problem = _artifact_problem(record)
                if problem:
                    refusals.append("%s %s: %s" % (arch, tag, problem))
                for case in spec.cases(pair, side):
                    _check_case(conf, pair, arch, side, release, record, case, index,
                                errors, refusals, item_fail)
        for key in sorted(index, key=repr):
            errors.append("%s %s: unexpected record" % (arch, key))

    refusals = sorted(set(refusals))
    items = {}
    for name, failures in item_fail.items():
        items[name] = {"survives": not (failures or refusals or errors),
                       "probe_cases_clean": not (failures or errors),
                       "failures": len(failures), "first_failures": failures[:12]}
    return {"pair": pair,
            "survives": any(i["survives"] for i in items.values()),
            "survivors": sorted(n for n, i in items.items() if i["survives"]),
            "complete": not errors, "errors": errors[:200], "error_count": len(errors),
            "refusals": refusals, "not_published": not_published,
            "excluded": conf["excluded"], "items": items,
            "records": len(rows)}


def _artifact_problem(record):
    if record.get("route") == "asset":
        if record.get("checksum_result") != "match" or not record.get("artifact_sha256") \
                or record["artifact_sha256"] != record.get("checksum_listed"):
            return "asset digest is not matched against the upstream checksum"
    elif record.get("route") == "image":
        digest = record.get("image", {}).get("platform_digest", "")
        if not digest.startswith("sha256:") or not record.get("artifact_url", "").endswith(
                "@" + digest):
            return "image is not pinned by manifest digest"
    else:
        return "unknown artifact route"
    return None


def _check_case(conf, pair, arch, side, release, record, case, index, errors, refusals,
                item_fail):
    tag = release["tag"]
    env = spec.case_env(pair, side, arch)
    seen = []
    failures = []
    for rep in range(1, spec.REPEATS + 1):
        row = index.pop((tag, case["id"], rep), None)
        label = "%s %s %s #%d" % (arch, tag, case["id"], rep)
        if row is None:
            errors.append(label + ": missing")
            continue
        obs = row["observation"]
        if row["argv"] != case["argv"] or row["env"] != env or row["side"] != side \
                or row["commit"] != release["commit"]:
            errors.append(label + ": record does not describe the pinned case")
            continue
        if obs.get("error") is None:
            options = obs.get("options") or {}
            broken = judge.option_problems(options, env)
            if options.get("image") != record.get("image_id"):
                broken.append("container ran another image")
            if broken:
                errors.append(label + ": " + "; ".join(broken))
                continue
        if case["expect"] == "version":
            problem = judge.version_problem(conf["project"], tag, release["commit"], obs)
            result = {"class": "VERSION_OK" if problem is None else "VERSION_BAD"}
        else:
            result = judge.classify(conf["parser"], conf["ready"], obs)
            problem = judge.case_problem(conf["parser"], case, result)
        if row["result"] != result or row["problem"] != problem:
            errors.append(label + ": recorded classification differs from the recomputed one")
        seen.append(result)
        if problem:
            failures.append("%s: %s" % (label, problem))
    if len(seen) == spec.REPEATS and any(s != seen[0] for s in seen[1:]):
        failures.append("%s %s %s: repeats differ" % (arch, tag, case["id"]))
    if not failures:
        return
    if case["expect"] == "version":
        refusals.extend(failures)
    elif case["item"] is None:   # a broken control drops every item
        for name in item_fail:
            item_fail[name].extend(failures)
    else:
        item_fail[case["item"]].extend(failures)


def render(verdicts):
    out = []
    for v in verdicts:
        out.append("## %s: %s (records %d, complete %s)" % (
            v["pair"], "PASS (probe)" if v["survives"] else "FAIL", v["records"],
            v["complete"]))
        for name, item in v["items"].items():
            out.append("- %s: %s; probe cases %s (%d failures)" % (
                name, "survives" if item["survives"] else "dropped",
                "clean" if item["probe_cases_clean"] else "not clean", item["failures"]))
            out.extend("    - " + f for f in item["first_failures"][:6])
        for key in ("refusals", "errors"):
            if v[key]:
                out.append("- %s (%d):" % (key, len(v[key])))
                out.extend("    - " + r for r in v[key][:25])
        if v["not_published"]:
            out.append("- platform not published for %d releases, first: %s" % (
                len(v["not_published"]), v["not_published"][0]))
    out.append("")
    out.append("Pairs surviving the probe: %d of %d. The static source reading and the "
               "second-machine rerun are not part of this run." % (
                   sum(v["survives"] for v in verdicts), len(verdicts)))
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", required=True)
    ap.add_argument("--summary", required=True)
    args = ap.parse_args(argv)
    metas, rows = load(args.records)
    releases = fetch.load_releases()
    _, digest = fetch.load_snapshot()
    verdicts = [check_pair(p, metas, rows, releases, digest) for p in sorted(spec.PAIRS)]
    unknown = {r.get("pair") for r in metas + rows} - set(spec.PAIRS)
    with open(args.summary, "w", encoding="utf-8") as f:
        json.dump({"pairs": verdicts}, f, indent=1, sort_keys=True)
    print(render(verdicts))
    if unknown:
        print("records for unknown pairs: %s" % sorted(map(repr, unknown)))
    return 0 if not unknown and all(v["complete"] for v in verdicts) else 1


if __name__ == "__main__":
    sys.exit(main())
