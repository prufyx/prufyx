"""The kind probe reads a cached clone only for a strictly loaded target whose repository is the clone's origin."""
import json, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

import crd_oracle as oracle
import kind_probe
import test_target_gaps as gaps

GOOD_ORIGIN = "https://github.com/o/a.git"
REFUSED = "project clone belongs to a different repository"


class KindProbeOrigin(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.crd_cases = self.root / "crd.cases.json"
        self.crd_cases.write_text(json.dumps([{"key": "a|v1.0.0|v1.1.0", "error": False,
                                               "detail": {"nExpect": 1, "expectRemoved": []}}]))

    def write(self, data):
        (self.root / "target-a.json").write_bytes(data)

    def probe(self, origin=GOOD_ORIGIN, code=0):
        """Run the CRD probe with git faked; reading the clone always raises. Returns the one recorded case."""
        self.events = []

        def command(*args, **kwargs):
            self.events.append(args)
            return subprocess.CompletedProcess(args, code, origin + "\n", "")

        def read(*args, **kwargs):
            self.events.append("read")
            raise RuntimeError("clone was read")

        cases = []
        with patch.object(oracle, "TD", self.td.name), patch.object(kind_probe, "CACHE", self.td.name), \
                patch.object(oracle, "sh", side_effect=command), patch.object(kind_probe, "sh", side_effect=command), \
                patch.object(oracle, "crd_text", side_effect=read), \
                patch.object(kind_probe, "dv", side_effect=AssertionError("cluster command")):
            kind_probe.crd(cases, "kubeconfig", str(self.crd_cases))
        self.assertEqual(len(cases), 1, cases)
        self.assertTrue(cases[0]["error"], cases)
        return cases[0]

    def origin_call(self):
        return ("git", "--git-dir", self.td.name + "/git/a.git", "remote", "get-url", "origin")

    def assert_refused(self, case):
        self.assertIn(REFUSED, case["detail"]["why"])
        self.assertEqual(self.events, [self.origin_call()])

    def test_clone_of_another_repo_is_not_read(self):
        self.write(gaps.raw(gaps.spec("o/a")))
        for origin in ("https://github.com/evil/x.git", "https://github.com/o/a", "https://github.com/O/a.git",
                       "https://example.com/o/a.git", ""):
            with self.subTest(origin=origin):
                self.assert_refused(self.probe(origin=origin))

    def test_unreadable_origin_is_not_read(self):
        self.write(gaps.raw(gaps.spec("o/a")))
        self.assert_refused(self.probe(code=128))  # right text, failed command

    def test_same_repo_is_read_after_the_check(self):
        self.write(gaps.raw(gaps.spec("o/a")))
        case = self.probe()
        self.assertEqual(self.events, [self.origin_call(), "read"])
        self.assertIn("clone was read", case["detail"]["why"])

    def test_bad_documents_never_reach_the_clone(self):
        for label, data in gaps.bad_documents().items():
            with self.subTest(doc=label):
                self.write(data)
                case = self.probe()
                self.assertEqual(self.events, [])
                self.assertIn("target rejected", case["detail"]["why"])

    def test_invalid_target_never_reaches_the_clone(self):
        self.write(gaps.raw(gaps.spec("o/a", tagPrefixes=["-x"])))
        case = self.probe()
        self.assertEqual(self.events, [])
        self.assertIn("target rejected", case["detail"]["why"])

    def test_missing_target_never_reaches_the_clone(self):
        case = self.probe()
        self.assertEqual(self.events, [])
        self.assertIn("target rejected", case["detail"]["why"])


if __name__ == "__main__":
    unittest.main()
