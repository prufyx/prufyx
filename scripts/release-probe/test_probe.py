# SPDX-License-Identifier: AGPL-3.0-only
"""Unit checks of the harness on synthetic records. Nothing upstream runs."""

import copy
import unittest

import check
import fetch
import judge
import run
import spec

PAIR = "etcd-3.3-3.4"
RELEASES = {"etcd": {
    "3.3": [{"tag": "v3.3.0", "commit": "a" * 40}, {"tag": "v3.3.1", "commit": "b" * 40}],
    "3.4": [{"tag": "v3.4.0", "commit": "c" * 40}, {"tag": "v3.4.1", "commit": "d" * 40}]}}
OPTIONS = {"network_mode": "none", "mounts": [], "binds": None, "volumes_from": None,
           "devices": [], "user": spec.UID, "cap_drop": ["ALL"], "cap_add": None,
           "privileged": False, "security_opt": ["no-new-privileges"], "pid_mode": "",
           "ipc_mode": "private", "memory": 1, "nano_cpus": 1, "pids_limit": 1,
           "env": ["PATH=/bin"], "image": "sha256:img"}


def obs(**changes):
    base = {"exit_code": 0, "timed_out": False, "truncated": False, "oom": False,
            "stdout": "", "stderr": "", "error": None, "options": copy.deepcopy(OPTIONS)}
    base.update(changes)
    return base


def good_obs(case, release):
    if case["expect"] == "version":
        return obs(stdout="etcd Version: %s\nGit SHA: %s\n" % (
            release["tag"][1:], release["commit"][:9]))
    if case["expect"] == "ready":
        return obs(exit_code=137, stderr="embed: ready to serve client requests\n")
    return obs(exit_code=2,
               stderr="flag provided but not defined: -%s\nUsage:\n" % case["token"])


def records(arches=("amd64",)):
    conf = spec.PAIRS[PAIR]
    metas, rows = [], []
    for arch in arches:
        meta = {"pair": PAIR, "arch": arch, "shard": 0, "shards": 1, "releases": {},
                "release_set": {"lines": {}}}
        for side in ("from", "to"):
            line = RELEASES["etcd"][conf[side]]
            meta["release_set"]["lines"][conf[side]] = {
                "snapshot": [r["tag"][1:] for r in line],
                "live": {r["tag"]: r["commit"] for r in line}}
            for release in line:
                meta["releases"][release["tag"]] = {
                    "status": "ok", "side": side, "commit": release["commit"],
                    "route": "asset", "checksum_result": "match", "artifact_sha256": "e",
                    "checksum_listed": "e", "image_id": "sha256:img"}
                for case in spec.cases(PAIR, side):
                    for rep in (1, 2):
                        env = spec.case_env(PAIR, side, arch)
                        o = good_obs(case, release)
                        o["options"]["env"] += ["%s=%s" % kv for kv in env.items()]
                        row = {"pair": PAIR, "arch": arch, "side": side,
                               "tag": release["tag"], "commit": release["commit"],
                               "case": case["id"], "rep": rep, "argv": case["argv"],
                               "env": env, "observation": o}
                        rejudge(row, case, release)
                        rows.append(row)
        metas.append(meta)
    return metas, rows


def rejudge(row, case, release):
    if case["expect"] == "version":
        problem = judge.version_problem("etcd", release["tag"], release["commit"],
                                        row["observation"])
        row["result"] = {"class": "VERSION_OK" if problem is None else "VERSION_BAD"}
    else:
        row["result"] = judge.classify("goflag", spec.PAIRS[PAIR]["ready"], row["observation"])
        problem = judge.case_problem("goflag", case, row["result"])
    row["problem"] = problem


def change(rows, side, tag, case_id, observation, reps=(1, 2)):
    case = next(c for c in spec.cases(PAIR, side) if c["id"] == case_id)
    release = next(r for line in RELEASES["etcd"].values() for r in line if r["tag"] == tag)
    hit = 0
    for row in rows:
        if row["tag"] == tag and row["case"] == case_id and row["rep"] in reps:
            row["observation"] = observation
            rejudge(row, case, release)
            hit += 1
    assert hit == len(reps)


def verdict(metas, rows, arches=("amd64",)):
    return check.check_pair(PAIR, metas, rows, RELEASES, arches=arches)


T1 = "base/T1/ca-file/ca-file/long-eq/last"
REJECT = "flag provided but not defined: -ca-file\n"
READY = "ready to serve client requests\n"


class ClassifyTest(unittest.TestCase):
    def outcome(self, token="ca-file", **changes):
        result = judge.classify("goflag", spec.PAIRS[PAIR]["ready"], obs(**changes))
        case = {"expect": "rejected", "token": token, "style": "long"}
        return result["class"], judge.case_problem("goflag", case, result)

    def test_exact_rejection_passes(self):
        self.assertEqual(self.outcome(exit_code=2, stderr=REJECT), ("REJECTED", None))

    def test_everything_else_fails(self):
        for name, changes in {
                "exit code alone": dict(exit_code=2),
                "crash": dict(exit_code=2, stderr="panic: boom\n" + REJECT),
                "help dump": dict(exit_code=2, stderr="Usage:\n  -ca-file string\n"),
                "other token": dict(exit_code=2, stderr="flag provided but not defined: -x\n"),
                "longer token": dict(exit_code=2,
                                     stderr="flag provided but not defined: -ca-file2\n"),
                "two tokens": dict(exit_code=2, stderr=REJECT +
                                   "flag provided but not defined: -x\n"),
                "exit zero": dict(exit_code=0, stderr=REJECT),
                "ready as well": dict(exit_code=2, stderr=REJECT + READY),
                "ready only": dict(stderr=READY),
                "timeout": dict(exit_code=137, timed_out=True, stderr=REJECT),
                "truncated": dict(exit_code=2, truncated=True, stderr=REJECT),
                "oom": dict(exit_code=137, oom=True, stderr=REJECT),
                "engine error": dict(error="x", stderr=REJECT)}.items():
            with self.subTest(name):
                self.assertIsNotNone(self.outcome(**changes)[1])

    def test_pflag_templates(self):
        long = judge.unknown_tokens("pflag", "Error: unknown flag: --a_b\n")
        short = judge.unknown_tokens("pflag", "unknown shorthand flag: 't' in -tx=1\n")
        odd = judge.unknown_tokens("pflag", "unknown shorthand flag: 'q' in -tx\n")
        self.assertEqual(long, [["long", "a_b"]])
        self.assertEqual(short, [["short", "tx"]])
        self.assertEqual(odd, [["short", "?tx"]])
        case = {"expect": "rejected", "token": "tx", "style": "long"}
        self.assertIsNotNone(judge.case_problem(
            "pflag", case, {"class": "REJECTED", "tokens": short}))

    def test_ready_needs_the_marker(self):
        result = judge.classify("goflag", "MARK", obs(stderr="almost\n"))
        self.assertIsNotNone(judge.case_problem("goflag", {"expect": "ready"}, result))

    def test_version(self):
        commit = "0123456789" * 4

        def problem(text, **changes):
            return judge.version_problem("etcd", "v3.4.0", commit, obs(stdout=text, **changes))

        good = "etcd Version: 3.4.0\nGit SHA: 012345678\n"
        self.assertIsNone(problem(good))
        for text in ("etcd Version: 3.4.1\nGit SHA: 012345678\n",
                     "etcd Version: 3.4.0\nGit SHA: fffffffff\n",
                     "etcd Version: 3.4.0\nGit SHA: 0123\n",
                     "etcd Version: 3.4.0\n", ""):
            self.assertIsNotNone(problem(text), text)
        self.assertIsNotNone(problem(good, exit_code=1))
        vt = "vttablet version Version: 21.0.0 (Git revision 012345678 branch 'x') built\n"
        self.assertIsNone(judge.version_problem("vitess", "v21.0.0", commit, obs(stdout=vt)))
        self.assertIsNotNone(judge.version_problem(
            "vitess", "v21.0.1", commit, obs(stdout=vt)))

    def test_isolation_violations(self):
        self.assertEqual(judge.option_problems(OPTIONS, {}), [])
        for key, bad in {"network_mode": "bridge", "mounts": [{"Type": "volume"}],
                         "binds": ["/a:/b"], "devices": [{}], "user": "0",
                         "cap_drop": None, "cap_add": ["NET_ADMIN"], "privileged": True,
                         "security_opt": ["no-new-privileges", "seccomp=unconfined"],
                         "pid_mode": "host", "ipc_mode": "host", "memory": 0,
                         "nano_cpus": 0, "pids_limit": None, "env": ["TOKEN=x"],
                         "volumes_from": ["x"]}.items():
            with self.subTest(key):
                self.assertTrue(judge.option_problems({**OPTIONS, key: bad}, {}))
        self.assertTrue(judge.option_problems(OPTIONS, {"NEEDED": "1"}))


class SpecTest(unittest.TestCase):
    def test_spellings(self):
        self.assertEqual(spec.spellings("debug"), ["debug"])
        self.assertEqual(sorted(spec.spellings("a_b_c")),
                         sorted(["a_b_c", "a-b-c", "a-b_c", "a_b-c"]))
        self.assertEqual(len(spec.spellings("experimental-backend-bbolt-freelist-type")), 16)

    def test_case_ids_unique_and_forms_present(self):
        for pair, conf in spec.PAIRS.items():
            for side in ("from", "to"):
                ids = [c["id"] for c in spec.cases(pair, side)]
                self.assertEqual(len(ids), len(set(ids)))
            argv = [c["argv"] for c in spec.cases(pair, "to") if c["kind"] == "T1"]
            for item in conf["items"]:
                flag = "-" + item["name"]
                self.assertTrue(any(a[0] == "-" + flag for a in argv))
                self.assertTrue(any(a[-1] == flag for a in argv))

    def test_shards_partition(self):
        whole = run.shard_releases("etcd-3.4-3.5", 0, 1)
        parts = [row for i in range(6) for row in run.shard_releases("etcd-3.4-3.5", i, 6)]
        key = sorted(r["tag"] for _, r in whole)
        self.assertEqual(sorted(r["tag"] for _, r in parts), key)

    def test_runner_guard(self):
        saved = dict(run.os.environ)
        try:
            for env in ({}, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}):
                run.os.environ.clear()
                run.os.environ.update(env)
                with self.assertRaises(SystemExit):
                    run.require_disposable_runner()
        finally:
            run.os.environ.clear()
            run.os.environ.update(saved)


class FetchTest(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(fetch.Withhold):
            fetch.verify_sha256(b"data", "0" * 64)
        self.assertEqual(fetch.verify_sha256(b"data", fetch.sha256(b"data")),
                         fetch.sha256(b"data"))

    def test_checksum_file(self):
        digest = "1" * 64
        self.assertEqual(fetch.parse_sums(digest + "  a.tar.gz\n", "a.tar.gz"), digest)
        self.assertIsNone(fetch.parse_sums(digest + "  b.tar.gz\n", "a.tar.gz"))
        with self.assertRaises(fetch.Withhold):
            fetch.parse_sums("%s  a\n%s  a\n" % (digest, "2" * 64), "a")

    def test_release_set(self):
        pinned = [{"tag": "v1.0.0", "commit": "a"}]
        good = (pinned, ["1.0.0"], {"v1.0.0": "a"})
        self.assertEqual(fetch.release_set_problems(*good), [])
        for name, args in {
                "empty": ([], [], {}),
                "missing upstream": (pinned, ["1.0.0"], {}),
                "moved": (pinned, ["1.0.0"], {"v1.0.0": "b"}),
                "newer": (pinned, ["1.0.0"], {"v1.0.0": "a", "v1.0.1": "c"}),
                "snapshot newer": (pinned, ["1.0.0", "1.0.1"], {"v1.0.0": "a"}),
                "snapshot older": (pinned, [], {"v1.0.0": "a"}),
                "duplicate": (pinned * 2, ["1.0.0"], {"v1.0.0": "a"})}.items():
            with self.subTest(name):
                self.assertTrue(fetch.release_set_problems(*args))

    def test_final_tags_peeled(self):
        text = ("o\trefs/tags/v1.0.0\np\trefs/tags/v1.0.0^{}\nq\trefs/tags/v1.0.1-rc.0\n"
                "r\trefs/tags/v1.0.1\ns\trefs/tags/v1.10.0\n")
        self.assertEqual(fetch.final_tags(text, "1.0"), {"v1.0.0": "p", "v1.0.1": "r"})


class CheckerTest(unittest.TestCase):
    def setUp(self):
        self.metas, self.rows = records()

    def test_clean_records_pass(self):
        v = verdict(self.metas, self.rows)
        self.assertTrue(v["complete"], v["errors"][:3])
        self.assertEqual(v["survivors"], ["ca-file", "peer-ca-file"], v["refusals"])

    def test_missing_release_fails(self):
        del self.metas[0]["releases"]["v3.4.1"]
        rows = [r for r in self.rows if r["tag"] != "v3.4.1"]
        v = verdict(self.metas, rows)
        self.assertFalse(v["complete"])
        self.assertFalse(v["survives"])

    def test_gaps_and_extras_fail(self):
        for name, rows in {
                "gap": self.rows[:-1],
                "duplicate": self.rows + self.rows[-1:],
                "extra": self.rows + [{**self.rows[-1], "rep": 3}],
                "none": []}.items():
            with self.subTest(name):
                v = verdict(self.metas, rows)
                self.assertFalse(v["complete"])
                self.assertFalse(v["survives"])
        self.assertFalse(verdict([], [])["survives"])

    def test_missing_platform_and_shard_fail(self):
        self.assertFalse(verdict(self.metas, self.rows, ("amd64", "arm64"))["complete"])
        self.metas[0]["shards"] = 2
        self.assertFalse(verdict(self.metas, self.rows)["complete"])

    def test_accepted_on_to_drops_only_that_item(self):
        change(self.rows, "to", "v3.4.1", T1, obs(exit_code=137, stderr=READY))
        v = verdict(self.metas, self.rows)
        self.assertEqual(v["survivors"], ["peer-ca-file"])

    def test_retained_failure_drops_item(self):
        change(self.rows, "to", "v3.4.0", "base/T3/ca-file",
               obs(exit_code=2, stderr="flag provided but not defined: -trusted-ca-file\n"))
        self.assertEqual(verdict(self.metas, self.rows)["survivors"], ["peer-ca-file"])

    def test_one_broken_repeat_drops_item(self):
        change(self.rows, "to", "v3.4.0", T1, obs(exit_code=137, timed_out=True), reps=(2,))
        self.assertEqual(verdict(self.metas, self.rows)["survivors"], ["peer-ca-file"])

    def test_broken_control_drops_all(self):
        for side, tag, case_id in (("from", "v3.3.0", "base/F0"),
                                   ("to", "v3.4.0", "config-file/T0"),
                                   ("to", "v3.4.0", "base/T2/long")):
            with self.subTest(case_id):
                metas, rows = records()
                change(rows, side, tag, case_id, obs(exit_code=1, stderr="no\n"))
                self.assertEqual(verdict(metas, rows)["survivors"], [])

    def test_wrong_version_refuses_pair(self):
        change(self.rows, "from", "v3.3.1", "version", obs(stdout="etcd Version: 9\n"))
        v = verdict(self.metas, self.rows)
        self.assertFalse(v["survives"])
        self.assertTrue(v["refusals"])

    def test_forged_classification_fails(self):
        row = next(r for r in self.rows if r["case"] == T1)
        row["observation"] = obs(exit_code=137, stderr=READY)
        self.assertFalse(verdict(self.metas, self.rows)["complete"])

    def test_isolation_and_image_and_argv_checked(self):
        for name, mutate in {
                "network": lambda r: r["observation"]["options"].update(network_mode="bridge"),
                "image": lambda r: r["observation"]["options"].update(image="sha256:other"),
                "argv": lambda r: r.update(argv=["--other"]),
                "options gone": lambda r: r["observation"].update(options=None)}.items():
            with self.subTest(name):
                metas, rows = records()
                mutate(rows[1])
                self.assertFalse(verdict(metas, rows)["complete"])

    def test_artifact_refusals(self):
        for name, changes in {
                "withheld": {"status": "withheld"},
                "not published on amd64": {"status": "not-published"},
                "digest": {"artifact_sha256": "f"},
                "route": {"route": "mirror"},
                "unpinned image": {"route": "image", "artifact_url": "repo:tag",
                                   "image": {"platform_digest": "sha256:1"}}}.items():
            with self.subTest(name):
                metas, rows = records()
                metas[0]["releases"]["v3.4.0"].update(changes)
                self.assertFalse(verdict(metas, rows)["survives"])

    def test_release_set_refusal(self):
        self.metas[0]["release_set"]["lines"]["3.4"]["live"]["v3.4.2"] = "f" * 40
        self.assertFalse(verdict(self.metas, self.rows)["survives"])

    def test_arm64_unpublished_is_listed_not_refused(self):
        metas, rows = records(("amd64", "arm64"))
        arm = next(m for m in metas if m["arch"] == "arm64")
        for tag, record in arm["releases"].items():
            arm["releases"][tag] = {"status": "not-published", "side": record["side"],
                                    "commit": record["commit"]}
        rows = [r for r in rows if r["arch"] == "amd64"]
        v = verdict(metas, rows, ("amd64", "arm64"))
        self.assertTrue(v["survives"], v["errors"][:3])
        self.assertEqual(len(v["not_published"]), 4)


if __name__ == "__main__":
    unittest.main()
