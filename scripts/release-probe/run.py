#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Probes one shard of one pair on one platform and writes the raw records.
Run it only on a disposable machine that holds no credentials."""

import argparse
import concurrent.futures
import json
import lzma
import os
import platform
import sys

import engine
import fetch
import judge
import spec

MACHINES = {"x86_64": "amd64", "aarch64": "arm64"}


def shard_releases(pair, shard, shards):
    """[(side, release)] of this shard; shards partition the whole list."""
    conf = spec.PAIRS[pair]
    releases = fetch.load_releases()[conf["project"]]
    rows = [(side, r) for side in ("from", "to") for r in releases[conf[side]]]
    return [row for i, row in enumerate(rows) if i % shards == shard]


def require_disposable_runner():
    """Refuses to execute upstream binaries anywhere but a hosted, ephemeral
    CI runner."""
    if os.environ.get("GITHUB_ACTIONS") != "true" \
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("refused: upstream binaries run only on a hosted ephemeral runner")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pair", required=True, choices=sorted(spec.PAIRS))
    ap.add_argument("--arch", required=True, choices=spec.ARCHES)
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    require_disposable_runner()
    if MACHINES.get(platform.machine()) != args.arch:
        raise SystemExit("refused: the machine is not native " + args.arch)
    if not 0 <= args.shard < args.shards:
        raise SystemExit("bad shard")
    conf = spec.PAIRS[args.pair]
    project = conf["project"]
    os.makedirs(args.out, exist_ok=True)
    stem = "%s.%s.%d-of-%d" % (args.pair, args.arch, args.shard, args.shards)

    # Phase 1: fetch and verify, network, no credentials.
    rows = shard_releases(args.pair, args.shard, args.shards)
    meta = {"pair": args.pair, "arch": args.arch, "shard": args.shard,
            "shards": args.shards, "source_commit": os.environ.get("GITHUB_SHA"),
            "harness_sha256": harness_digests(),
            "engine_version": engine.docker("version", "--format", "{{.Server.Version}}")
            .stdout.strip(),
            "release_set": fetch.release_set(args.pair), "releases": {}}
    files = fetch.synthetic_files(project)
    notes, notes_error = {}, None
    if project == "vitess":
        try:
            notes = fetch.vitess_checksum_note([r["tag"] for _, r in rows])
        except fetch.Withhold as exc:
            notes_error = str(exc)
    ready = []
    for side, release in rows:
        tag = release["tag"]
        try:
            if notes_error:
                raise fetch.Withhold(notes_error)
            record = fetch.prepare(project, tag, args.arch, files, notes)
            ready.append((side, release, record))
        except fetch.NotPublished as exc:
            record = {"status": "not-published", "reason": str(exc)}
        except Exception as exc:  # any fetch failure withholds the release
            record = {"status": "withheld", "reason": "%s: %s" % (type(exc).__name__, exc)}
        record.update({"side": side, "commit": release["commit"]})
        meta["releases"][tag] = record
        print("fetch %s %s: %s %s" % (side, tag, record["status"], record.get("reason", "")),
              flush=True)
    with open(os.path.join(args.out, stem + ".meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1, sort_keys=True)

    # Phase 2: run, one new container without network per case.
    def one(job):
        side, release, record, case, rep = job
        env = spec.case_env(args.pair, side, args.arch)
        marker = None if case["expect"] == "version" else conf["ready"]
        obs = engine.run_case(record["image_id"], conf["entrypoint"], case["argv"], env,
                              marker, unset=record["unset_env"], tmpfs=record["tmpfs"])
        if case["expect"] == "version":
            problem = judge.version_problem(project, release["tag"], release["commit"], obs)
            result = {"class": "VERSION_OK" if problem is None else "VERSION_BAD"}
        else:
            result = judge.classify(conf["parser"], conf["ready"], obs)
            problem = judge.case_problem(conf["parser"], case, result)
        return {"pair": args.pair, "arch": args.arch, "side": side, "tag": release["tag"],
                "commit": release["commit"], "case": case["id"], "rep": rep,
                "argv": case["argv"], "env": env, "observation": obs, "result": result,
                "problem": problem}

    jobs = [(side, release, record, case, rep)
            for rep in range(1, spec.REPEATS + 1)
            for side, release, record in ready
            for case in spec.cases(args.pair, side)]
    print("running %d cases" % len(jobs), flush=True)
    failed = errors = 0
    with lzma.open(os.path.join(args.out, stem + ".cases.jsonl.xz"), "wt",
                   encoding="utf-8", preset=3) as out, \
            concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        for n, row in enumerate(pool.map(one, jobs), 1):
            out.write(json.dumps(row, sort_keys=True) + "\n")
            if row["observation"]["error"]:
                errors += 1
                if errors <= 20:
                    print("harness error %s %s: %s" % (
                        row["tag"], row["case"], row["observation"]["error"]), flush=True)
            if row["problem"]:
                failed += 1
                if failed <= 60:
                    print("case fail %s %s: %s" % (row["tag"], row["case"], row["problem"]),
                          flush=True)
            if n % 1000 == 0:
                print("%d/%d" % (n, len(jobs)), flush=True)
    print("done: %d cases, %d not as expected, %d harness errors" % (len(jobs), failed, errors))
    return 0


def harness_digests():
    here = os.path.dirname(os.path.abspath(__file__))
    out = {}
    for name in sorted(os.listdir(here)):
        path = os.path.join(here, name)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                out[name] = fetch.sha256(f.read())
    return out


if __name__ == "__main__":
    sys.exit(main())
