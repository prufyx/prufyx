"""A live CRD probe that cannot be set up is an error case, never a skip. No cluster: every command is a stub."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import crd_oracle
import kind_probe


class KindProbeSetupTests(unittest.TestCase):
    def probe(self, dv, helper_rc=0):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "target-sample.json").write_text(json.dumps({"target": {"tagPrefixes": ["v"], "paths": []}}))
            crd_cases = root / "crd.json"
            crd_cases.write_text(json.dumps([{"key": "sample|v1.0.0|v1.1.0", "error": False,
                                              "detail": {"nExpect": 1, "expectRemoved": ["g/v1/K"]}}]))
            cases = []
            with patch.object(crd_oracle, "TD", td), patch.object(crd_oracle, "crd_text", return_value="x"), patch.object(
                    kind_probe, "TMP", str(root / "tmp")), patch.object(kind_probe, "dv", side_effect=dv), patch.object(
                    kind_probe, "sh", return_value=subprocess.CompletedProcess([], helper_rc, "", "refused")), patch.object(
                    kind_probe, "prufyx") as scan:
                kind_probe.crd(cases, "kubeconfig", str(crd_cases))
            scan.assert_not_called()
            return cases

    def assert_error(self, cases):
        self.assertEqual(len(cases), 1, cases)
        self.assertTrue(cases[0]["error"], cases)

    def test_apply_or_wait_failure_is_an_error(self):
        def dv(script, timeout=300):
            return (1, "", "refused") if " apply " in script else (0, "widgets.sample.example,", "")
        self.assert_error(self.probe(dv))

    def test_failure_of_any_setup_step_fails_the_chain(self):
        scripts = []

        def dv(script, timeout=300):
            scripts.append(script)
            return 1, "", "bad"
        self.probe(dv)
        setup = scripts[0]
        self.assertEqual(setup.count(" && "), 2)
        self.assertNotIn(";", setup)
        self.assertNotIn("true", setup)

    def test_no_crd_established_is_an_error(self):
        for listing in ((0, "", ""), (1, "widgets.sample.example,", "unreachable")):
            with self.subTest(listing=listing):
                self.assert_error(self.probe(lambda script, timeout=300: listing if " get crd " in script else (0, "", "")))

    def test_failed_live_dump_is_an_error(self):
        dumped = json.dumps({"items": [{"apiVersion": "g/v1", "kind": "K"}]})
        for failing in ("-o json", "-o yaml"):
            with self.subTest(failing=failing):
                def dv(script, timeout=300):
                    if " -A -o " in script:  # a failed command may still have printed part of the dump
                        return (1 if script.endswith(failing) else 0), dumped, "forbidden"
                    return 0, "widgets.sample.example,", ""
                self.assert_error(self.probe(dv))

    def test_refused_definitions_are_an_error(self):
        self.assert_error(self.probe(lambda script, timeout=300: (0, "", ""), helper_rc=1))


if __name__ == "__main__":
    unittest.main()
