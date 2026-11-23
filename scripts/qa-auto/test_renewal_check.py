import copy, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import qa_batch_scope
from select_projects import selection, PRULES, PATTEST

RULES = "cli/internal/projectcheck/data/rules.json"
ATT = "cli/internal/projectcheck/data/corpus-attestation.json"
KEYS = "cli/knowledge/trust/web-approval-keys.json"
APPR = "cli/knowledge/approvals/community/"
OLD = ("2026-09-11T20:30:00Z", "2026-12-10T20:30:00Z")
NEW = ("2026-11-18T09:58:00Z", "2027-01-05T09:00:00Z")
IDS = ["ceph.a.1-to-2", "ceph.b.1-to-2", "loki.a.1-to-2"]

# a stand-in for prufyx-maintainer: it only decides exit codes from env, the real verifiers are Go and are not reimplemented
FAKE = """#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
if a[:2] == ["approval", "keys-digest"]:
    print("sha256:" + "0" * 64); sys.exit(0)
if a[:2] == ["approval", "verify"]:
    rule = a[a.index("--rule") + 1]
    if rule in os.environ.get("FAKE_REFUSE", "").split(","): sys.exit(1)
    if rule in os.environ.get("FAKE_BROKEN", "").split(","): sys.exit(2)
    sys.exit(0)
if a[:2] == ["corpus-attestation", "check"]:
    sys.exit(int(os.environ.get("FAKE_ATT", "0")))
sys.exit(9)
"""


def entry(rid, window):
    return {"project": rid.split(".")[0], "description": "d",
            "rule": {"id": rid, "nextAction": "n", "evidence": {"state": "active", "reviewedAt": window[0], "validUntil": window[1], "sources": [{"id": "s"}]}}}


def rules(windows=None, mutate=None):
    es = [entry(i, (windows or {}).get(i, OLD)) for i in IDS]
    if mutate:
        mutate(es)
    return {"schema": "s", "revision": "r", "policyId": "p", "policyDigest": "sha256:" + "0" * 64, "entries": es}


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True).stdout.strip()


class RenewalCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = os.path.join(self.tmp.name, "r")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        self.fake = os.path.join(self.tmp.name, "fake")
        Path(self.fake).write_text(FAKE)
        os.chmod(self.fake, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, files, msg):
        for path, value in files.items():
            full = os.path.join(self.repo, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            if value is None:
                if os.path.exists(full):
                    os.remove(full)
            else:
                Path(full).write_text(value if isinstance(value, str) else json.dumps(value, indent=1))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", msg)
        return git(self.repo, "rev-parse", "HEAD")

    def check(self, new_rules, approvals=IDS, env=None, att=("a", "b"), now="2026-11-24T00:00:00Z"):
        base = self.commit({RULES: rules(), ATT: {"packDigest": "x"}, KEYS: {"keys": []}}, "base")
        files = {RULES: new_rules, ATT: {"packDigest": att[0], "ruleSetDigest": att[1]}}
        for i in approvals:
            files[APPR + i + ".json"] = {"schema": "prufyx.io/knowledge-approval/v2", "record": {"ruleId": i}}
        head = self.commit(files, "head")
        out = os.path.join(self.tmp.name, "out.json")
        e = dict(os.environ, **(env or {}))
        subprocess.run([sys.executable, "-I", str(HERE / "renewal_check.py"), "--src", self.repo, "--base", base, "--head", head,
                        "--maintainer", self.fake, "--now", now, "--out", out], check=True, env=e, capture_output=True)
        cases = json.load(open(out))
        return {c["key"]: c for c in cases}

    def renewed(self, ids=IDS):
        return rules({i: NEW for i in ids})

    def assert_bad(self, cases, key, field="mismatch"):
        self.assertTrue(cases[key][field], cases[key])
        self.assertTrue(cases["renewal|summary"][field], cases["renewal|summary"])

    def test_positive_renewal(self):
        cases = self.check(self.renewed())
        self.assertEqual(len(cases), len(IDS) + 2)
        self.assertFalse(any(c["mismatch"] or c["error"] or c["wrongpass"] for c in cases.values()), cases)
        self.assertTrue(all(c["suite"] == "rules" for c in cases.values()))

    def test_extra_field_changed(self):
        def mut(es): es[0]["description"] = "changed"
        self.assert_bad(self.check(self.renewed_with(mut)), "renewal|ceph.a.1-to-2")

    def renewed_with(self, mut):
        r = self.renewed(); mut(r["entries"]); return r

    def test_evidence_source_changed(self):
        def mut(es): es[1]["rule"]["evidence"]["sources"] = [{"id": "other"}]
        self.assert_bad(self.check(self.renewed_with(mut)), "renewal|ceph.b.1-to-2")

    def test_date_backwards(self):
        r = rules({"ceph.a.1-to-2": ("2026-09-01T00:00:00Z", "2026-11-01T00:00:00Z")})
        self.assert_bad(self.check(r, approvals=["ceph.a.1-to-2"]), "renewal|ceph.a.1-to-2")

    def test_only_valid_until_moved(self):
        r = rules({"ceph.a.1-to-2": (OLD[0], "2026-12-20T20:30:00Z")})
        self.assert_bad(self.check(r, approvals=["ceph.a.1-to-2"]), "renewal|ceph.a.1-to-2")

    def test_window_too_long(self):
        r = rules({"ceph.a.1-to-2": ("2026-11-18T00:00:00Z", "2027-03-01T00:00:00Z")})
        self.assert_bad(self.check(r, approvals=["ceph.a.1-to-2"]), "renewal|ceph.a.1-to-2")

    def test_valid_until_before_reviewed(self):
        r = rules({"ceph.a.1-to-2": ("2026-11-18T00:00:00Z", "2026-11-17T00:00:00Z")})
        self.assert_bad(self.check(r, approvals=["ceph.a.1-to-2"]), "renewal|ceph.a.1-to-2")

    def test_reviewed_in_the_future(self):
        self.assert_bad(self.check(self.renewed(), now="2026-11-01T00:00:00Z"), "renewal|ceph.a.1-to-2")

    def test_bad_timestamp_shape(self):
        r = rules({"ceph.a.1-to-2": ("yesterday", "2027-01-01T00:00:00Z")})
        self.assert_bad(self.check(r, approvals=["ceph.a.1-to-2"]), "renewal|ceph.a.1-to-2")

    def test_missing_approval(self):
        cases = self.check(self.renewed(), approvals=["ceph.a.1-to-2", "ceph.b.1-to-2"])
        self.assert_bad(cases, "renewal|loki.a.1-to-2")
        self.assertFalse(cases["renewal|ceph.a.1-to-2"]["mismatch"])

    def test_bad_signature_or_digest_refused_by_verifier(self):
        cases = self.check(self.renewed(), env={"FAKE_REFUSE": "ceph.b.1-to-2"})
        self.assert_bad(cases, "renewal|ceph.b.1-to-2")
        self.assertFalse(cases["renewal|ceph.a.1-to-2"]["mismatch"])

    def test_verifier_crash_is_error_not_pass(self):
        cases = self.check(self.renewed(), env={"FAKE_BROKEN": "loki.a.1-to-2"})
        self.assert_bad(cases, "renewal|loki.a.1-to-2", "error")

    def test_attestation_digest_mismatch(self):
        self.assert_bad(self.check(self.renewed(), env={"FAKE_ATT": "1"}), "renewal|attestation")

    def test_rule_added_or_removed(self):
        def mut(es): es.append(entry("ceph.new.1-to-2", NEW))
        r = self.renewed_with(mut)
        self.assert_bad(self.check(r, approvals=IDS + ["ceph.new.1-to-2"]), "renewal|ceph.new.1-to-2")

    def test_no_change_is_not_a_renewal(self):
        base = self.commit({RULES: rules(), ATT: {"a": 1}, KEYS: {}}, "base")
        head = self.commit({"README.md": "x"}, "head")
        out = os.path.join(self.tmp.name, "o.json")
        subprocess.run([sys.executable, "-I", str(HERE / "renewal_check.py"), "--src", self.repo, "--base", base, "--head", head,
                        "--maintainer", self.fake, "--out", out], check=True, capture_output=True)
        cases = {c["key"]: c for c in json.load(open(out))}
        self.assertTrue(cases["renewal|summary"]["mismatch"])

    def test_unreadable_inputs_error_with_one_summary(self):
        out = os.path.join(self.tmp.name, "o.json")
        subprocess.run([sys.executable, "-I", str(HERE / "renewal_check.py"), "--src", self.repo, "--base", "0" * 40, "--head", "1" * 40,
                        "--maintainer", self.fake, "--out", out], check=True, capture_output=True)
        cases = json.load(open(out))
        self.assertEqual([c["key"] for c in cases if c["key"].endswith("summary")], ["renewal|summary"])
        self.assertTrue(all(c["error"] for c in cases))

    def test_missing_maintainer_is_error(self):
        base = self.commit({RULES: rules(), ATT: {"a": 1}, KEYS: {}}, "base")
        head = self.commit({RULES: self.renewed()}, "head")
        out = os.path.join(self.tmp.name, "o.json")
        subprocess.run([sys.executable, "-I", str(HERE / "renewal_check.py"), "--src", self.repo, "--base", base, "--head", head,
                        "--maintainer", "/nonexistent/maintainer", "--out", out], check=True, capture_output=True)
        cases = {c["key"]: c for c in json.load(open(out))}
        self.assertTrue(cases["renewal|summary"]["error"])


class RenewalRequiredInScope(unittest.TestCase):
    """A diff that renews project-check rules must carry the renewal result: select flags it, validate demands it."""
    SLUGS = ["ceph"]

    def test_selection_flags_renewal_paths(self):
        for path in (PRULES, PATTEST, APPR + "x.json"):
            r = selection([path], self.SLUGS, None, {})
            self.assertTrue(r["renewal_check"], path)
            self.assertEqual(r["mode"], "full")
        self.assertFalse(selection(["README.md"], self.SLUGS, None, {})["renewal_check"])

    def test_untargeted_projects_are_listed(self):
        old = {"schema": "s", "revision": "r", "policyDigest": "a", "entries": [
            {"project": "kibana", "rule": {"id": "kibana.r"}, "requiredFacts": []}]}
        new = copy.deepcopy(old); new["entries"][0]["description"] = "x"
        raw = lambda d: json.dumps(d).encode()
        r = selection([PRULES], self.SLUGS, lambda p: (raw(old), raw(new)), {})
        self.assertEqual(r["mode"], "none")
        self.assertTrue(r["renewal_check"])
        self.assertIn("kibana", r["reasons"][0])

    def test_other_approval_paths_are_full(self):
        for p in ("cli/knowledge/approvals/cncf/ceph.x.json", "cli/knowledge/approvals/community/sub/ceph.x.json"):
            r = selection([p], ["ceph"], lambda q: (None, b"{}"), {})
            self.assertEqual(r["mode"], "full", p)

    def contract(self, **kw):
        c = {"head": "a" * 40, "base": "b" * 40, "run_id": "r", "envelopes": [], "projects": [], "suites": [], "renewal_check": True}
        c.update(kw)
        return c

    def errors(self, cases):
        import qa_scope
        orig = qa_scope.bundle_errors
        qa_scope.bundle_errors = lambda *a: []
        try:
            return qa_batch_scope.validate(self.contract(), {}, cases, {})
        finally:
            qa_scope.bundle_errors = orig

    def test_validate_requires_exactly_one_clean_summary(self):
        ok = {"suite": "rules", "key": "renewal|summary", "wrongpass": False, "mismatch": False, "error": False}
        self.assertEqual(self.errors([ok]), [])
        self.assertTrue(self.errors([]))
        self.assertTrue(self.errors([ok, ok]))
        self.assertTrue(self.errors([dict(ok, error=True)]))
        self.assertTrue(self.errors([dict(ok, suite="crd")]))


if __name__ == "__main__":
    unittest.main()
