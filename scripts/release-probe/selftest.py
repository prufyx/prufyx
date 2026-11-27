#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Runs the real container path against the stand-in program and requires
every fault to fail. No upstream artifact is touched."""

import json
import os
import platform
import subprocess
import sys
import tempfile
import uuid

import engine
import fetch
import judge

MARKER = "probe-ready"
ENTRY = "/probe/fakeprobe"


def build():
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(tempfile.mkdtemp(), "fakeprobe")
    subprocess.run(["go", "build", "-trimpath", "-o", out,
                    os.path.join(here, "fakeprobe", "main.go")],
                   check=True, env={**os.environ, "CGO_ENABLED": "0"})
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    with open(out, "rb") as f:
        return fetch.build_image("scratch", arch, {ENTRY: (f.read(), 0o755)}, "selftest")


def main():
    image = build()
    failures = []

    def probe(name, argv, expect, token, must_pass, want_class):
        obs = engine.run_case(image, ENTRY, argv, {}, MARKER, time_limit=5)
        result = judge.classify("goflag", MARKER, obs)
        case = {"expect": expect, "token": token, "style": "long"}
        problem = judge.case_problem("goflag", case, result)
        ok = (problem is None) == must_pass and result["class"] == want_class
        print("%s %s: %s %s" % ("ok " if ok else "BAD", name, result["class"],
                                problem or obs["error"] or ""))
        if not ok:
            failures.append(name)

    # Sanity: without these the failures below would prove nothing.
    probe("control ready passes", ["--base"], "ready", None, True, "READY")
    probe("unknown item rejected passes", ["--base", "--gone=1"], "rejected", "gone",
          True, "REJECTED")
    # Each of these must fail.
    probe("retained item judged as removed", ["--base", "--kept=1"], "rejected", "kept",
          False, "READY")
    probe("broken control", ["--base", "--broken"], "ready", None, False, "OTHER")
    probe("message names another token", ["--base", "--wrong-token"], "rejected",
          "wrong-token", False, "REJECTED")
    probe("time limit", ["--base", "--hang"], "rejected", "hang", False, "TIMEOUT")
    probe("truncated output", ["--base", "--flood"], "rejected", "flood", False, "TRUNCATED")

    # Missing release and wrong digest are refused by the checker and fetch code.
    unit = subprocess.run([sys.executable, "-B", "-m", "unittest", "-v",
                           "test_probe.CheckerTest.test_missing_release_fails",
                           "test_probe.FetchTest.test_wrong_digest_refused"],
                          cwd=os.path.dirname(os.path.abspath(__file__)))
    if unit.returncode != 0:
        failures.append("missing release / wrong digest")

    # A container that breaks isolation is reported, so it is never started.
    name = "probe-selftest-" + uuid.uuid4().hex
    engine.docker("create", "--name", name, "--entrypoint", ENTRY, image)
    try:
        info = json.loads(engine.docker("inspect", name).stdout)[0]
        problems = judge.option_problems(engine.options_from_inspect(info), {})
    finally:
        engine.docker("rm", "-f", "-v", name, check=False)
    print("%s default container refused: %s" % ("ok " if problems else "BAD", problems))
    if not problems:
        failures.append("isolation check")

    if failures:
        print("self-test failed: %s" % failures)
        return 1
    print("self-test passed: every fault was refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
