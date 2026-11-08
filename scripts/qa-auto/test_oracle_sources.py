"""Source failures cannot reduce the expected GVK set."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import crd_oracle as oracle
import qalib


class SourceReadTests(unittest.TestCase):
    def test_empty_requested_blob_is_an_error(self):
        for body in ("", " \n\t"):
            with self.subTest(body=body), patch.object(oracle, "sh", return_value=subprocess.CompletedProcess([], 0, body, "")):
                with self.assertRaises(ValueError):
                    oracle.crd_text({"paths": [{"path": "crd.yaml"}]}, "unused", "v1")

    def test_every_helper_row_is_validated_even_when_not_served(self):
        good = dict(G="sample.example", V="v1", K="Widget", Served=True, Store=True)
        bad_rows = [dict(G="sample.example", V="", K="Widget", Served=False, Store=False),
                    dict(G="sample.example", V="v1", Served=False, Store=False),
                    dict(good, Served="false"), dict(good, Store=None), None]
        for bad in bad_rows:
            with self.subTest(row=bad), patch.object(oracle, "crd_text", return_value="kind: CustomResourceDefinition"), patch.object(
                    oracle, "sh", return_value=subprocess.CompletedProcess([], 0, json.dumps([good, bad]), "")):
                with self.assertRaises(ValueError):
                    oracle.served_set({}, "unused", "v1")

    def test_failed_tree_or_blob_prevents_any_candidate_scan(self):
        for failing_command in ("ls-tree", "show"):
            with self.subTest(command=failing_command), tempfile.TemporaryDirectory() as td:
                target = {"target": {"repo": "example/sample", "tagPrefixes": ["v"],
                          "paths": [{"path": "crds", "directory": True, "match": "yaml$"}]}}
                Path(td, "target-sample.json").write_text(json.dumps(target))
                Path(td, "sample.git").mkdir()
                def command(*args, **kwargs):
                    if failing_command in args:
                        return subprocess.CompletedProcess(args, 128, "", "unreadable")
                    output = "v1.0.0\nv1.1.0\n" if "tag" in args else ("crds/a.yaml\n" if "ls-tree" in args else "")
                    return subprocess.CompletedProcess(args, 0, output, "")
                with patch.object(oracle, "TD", td), patch.object(oracle, "GITROOT", td), patch.object(
                        oracle, "sh", side_effect=command), patch.object(oracle, "prufyx") as scan:
                    cases = oracle.run("sample", [{"project": "sample", "pairs": [{"from": "1.0", "to": "1.1"}]}])
                    self.assertEqual(len(cases), 1)
                    self.assertTrue(cases[0]["error"])
                    scan.assert_not_called()

    def test_one_finding_cannot_cover_multiple_removed_gvks(self):
        first, second = ("sample.example", "v1", "Widget"), ("sample.example", "v2", "Widget")
        entry = {"project": "sample", "rule": {"operator": "forbid_set_member", "setCondition": {
            "factId": "component.sample.custom_resource_versions_set", "members": ["/".join(first)]}}}
        report = {"verdict": "UNKNOWN", "paths": [{"component": "sample", "hops": [{"families": [
            {"family": "crd.custom_resource_versions", "status": "PASS"}]}]}], "findings": [
            {"ruleId": "first", "component": "sample", "locations": [{"kind": "Widget", "name": qalib.object_name(*first)}]}]}
        with patch.object(qalib, "claim_registry", return_value={"first": entry}):
            wrongpass, _, missing, _ = qalib.scoped_result(11, report, [first, second], "sample", "crd.custom_resource_versions")
        self.assertTrue(wrongpass)
        self.assertEqual(missing, ["/".join(second)])

    def test_malformed_scan_cannot_hide_removed_object(self):
        first = ("sample.example", "v1", "Widget")
        for report in ({}, {"findings": "malformed"}, {"paths": [None]}):
            with self.subTest(report=report):
                # The project wrapper converts malformed result shapes into an error case.
                with patch.object(oracle, "_run", side_effect=lambda *args: qalib.scoped_result(
                        11, report, [first], "sample", "crd.custom_resource_versions")):
                    result = oracle.run("sample", [])
                if isinstance(result, tuple):
                    self.assertTrue(result[1])
                else:
                    self.assertTrue(result[0]["error"])


class HelperShapeTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("QA_TEST_CRDGVK"), "set QA_TEST_CRDGVK to the built helper")
    def test_legacy_version_and_output_errors_are_fatal(self):
        helper = os.environ["QA_TEST_CRDGVK"]
        prefix = "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nspec:\n  group: sample.example\n  names:\n    kind: Widget\n"
        valid = prefix + "  version: v1\n"
        good = subprocess.run([helper], input=valid, text=True, capture_output=True)
        self.assertEqual(good.returncode, 0)
        self.assertEqual(json.loads(good.stdout)[0]["V"], "v1")
        for value in ("0", "false", "''", "'  '", "[]"):
            for flag in ([], ["-strip"], ["-sample"]):
                with self.subTest(version=value, flag=flag):
                    result = subprocess.run([helper] + flag, input=valid + "---\n" + prefix + "  version: " + value + "\n",
                                            text=True, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
        if Path("/dev/full").exists():
            for flag in ([], ["-strip"], ["-sample"]):
                with self.subTest(write_flag=flag), open("/dev/full", "wb") as full:
                    result = subprocess.run([helper] + flag, input=valid, text=True, stdout=full, stderr=subprocess.PIPE)
                    self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()


class OptionalRemoteTests(unittest.TestCase):
    """Optional/remote semantics mirror the extractor; nothing missing becomes empty truth silently."""
    DIR = {"path": "crds", "directory": True, "match": "yaml$"}

    def fake(self, tree, blobs=None, fail_on=None):
        blobs = blobs or {}

        def run(*a, **k):
            if "ls-tree" in a:
                if fail_on == "ls-tree":
                    return subprocess.CompletedProcess([], 128, "", "bad")
                path = a[-1]
                if "-r" in a:
                    return subprocess.CompletedProcess([], 0, "\n".join(f for f in tree if f.startswith(path)), "")
                return subprocess.CompletedProcess([], 0, "\n".join(f for f in tree if f == path.rstrip("/") or f.startswith(path.rstrip("/") + "/")), "")
            f = a[-1].split(":", 1)[1]
            return subprocess.CompletedProcess([], 0, blobs.get(f, "kind: CustomResourceDefinition\n"), "")
        return patch.object(oracle, "sh", side_effect=run)

    def test_optional_directory_missing_is_ignored(self):
        t = {"paths": [dict(self.DIR, optional=True), {"path": "base", "directory": True, "match": "yaml$"}]}
        with self.fake(["base/a.yaml"], {"base/a.yaml": "A"}):
            self.assertEqual(oracle.crd_text(t, "g", "v1"), "\n---\nA")

    def test_optional_file_missing_is_ignored(self):
        with self.fake(["a.yaml"], {"a.yaml": "A"}):
            t = {"paths": [{"path": "a.yaml"}, {"path": "b.yaml", "optional": True}]}
            self.assertEqual(oracle.crd_text(t, "g", "v1"), "\n---\nA")

    def test_non_optional_missing_is_error(self):
        with self.fake([]):
            with self.assertRaises(ValueError):
                oracle.crd_text({"paths": [self.DIR]}, "g", "v1")

    def test_optional_present_is_read(self):
        with self.fake(["crds/a.yaml"], {"crds/a.yaml": "A"}):
            self.assertEqual(oracle.crd_text({"paths": [dict(self.DIR, optional=True)]}, "g", "v1"), "\n---\nA")

    def test_optional_present_without_matches_is_error(self):
        with self.fake(["crds/readme.md"]):
            with self.assertRaises(ValueError):
                oracle.crd_text({"paths": [dict(self.DIR, optional=True)]}, "g", "v1")

    def test_git_failure_on_optional_probe_is_error_not_absent(self):
        with self.fake([], fail_on="ls-tree"):
            with self.assertRaises(ValueError):
                oracle.crd_text({"paths": [dict(self.DIR, optional=True)]}, "g", "v1")

    def test_remote_line_is_explicit_error(self):
        t = {"paths": [self.DIR], "remote": {"fromLine": "3.4", "repo": "github.com/o/r"}}
        with self.fake(["crds/a.yaml"]):
            for name in ("v3.4.0", "v3.10.2", "v4.0.0"):
                with self.subTest(tag=name), self.assertRaises(ValueError):
                    oracle.crd_text(t, "g", "deadbeef", name)

    def test_before_remote_line_reads_own_paths(self):
        t = {"paths": [self.DIR], "remote": {"fromLine": "3.4", "repo": "github.com/o/r"}}
        with self.fake(["crds/a.yaml"], {"crds/a.yaml": "A"}):
            self.assertEqual(oracle.crd_text(t, "g", "deadbeef", "v3.3.1"), "\n---\nA")

    def test_remote_with_unknown_line_fails_closed(self):
        t = {"paths": [self.DIR], "remote": {"fromLine": "3.4", "repo": "github.com/o/r"}}
        with self.fake(["crds/a.yaml"]):
            with self.assertRaises(ValueError):
                oracle.crd_text(t, "g", "deadbeef")

    def test_validate_target_rejects_non_boolean_optional(self):
        t = {"repo": "o/r", "tagPrefixes": ["v"], "paths": [{"path": "crds", "directory": True, "match": "y$", "optional": "yes"}]}
        self.assertNotEqual(oracle.validate_target(t)[1], "")


class RealGitProbeTests(unittest.TestCase):
    def test_absent_path_is_empty_and_present_path_lists(self):
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e.x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e.x")
            def git(*a):
                subprocess.run(["git", "-C", td, *a], check=True, capture_output=True, env=env)
            git("init", "-q")
            Path(td, "crds").mkdir()
            Path(td, "crds", "a.yaml").write_text("kind: X\n")
            git("add", "."); git("commit", "-qm", "c"); git("tag", "v1")
            self.assertFalse(oracle.path_absent(td + "/.git", "v1", "crds"))
            self.assertFalse(oracle.path_absent(td + "/.git", "v1", "crds/a.yaml"))
            self.assertTrue(oracle.path_absent(td + "/.git", "v1", "nope"))
            self.assertTrue(oracle.path_absent(td + "/.git", "v1", "nope/sub"))
            with self.assertRaises(ValueError):
                oracle.path_absent(td + "/.git", "nosuchtag", "crds")


class ScanVersionTests(unittest.TestCase):
    def commits(self, table):
        def fake(gd, tag):
            if tag not in table:
                raise ValueError("no such tag")
            return table[tag]
        return patch.object(oracle, "tag_commit", fake)

    def test_padded_minor_with_same_commit_is_canonical(self):
        with self.commits({"v25.08.0": "a" * 40, "v25.8.0": "a" * 40}):
            self.assertEqual(oracle.scan_version("gd", "v", "25.08.0"), "25.8.0")

    def test_unpadded_version_unchanged(self):
        self.assertEqual(oracle.scan_version("gd", "v", "25.10.4"), "25.10.4")
        self.assertEqual(oracle.scan_version("gd", "v", "25.8.0"), "25.8.0")

    def test_moved_tag_fails_closed(self):
        with self.commits({"v25.08.0": "a" * 40, "v25.8.0": "b" * 40}):
            self.assertEqual(oracle.scan_version("gd", "v", "25.08.0"), "25.08.0")

    def test_missing_canonical_tag_fails_closed(self):
        with self.commits({"v25.08.0": "a" * 40}):
            self.assertEqual(oracle.scan_version("gd", "v", "25.08.0"), "25.08.0")

    def test_no_repo_fails_closed(self):
        self.assertEqual(oracle.scan_version(None, "v", "25.08.0"), "25.08.0")

    def test_other_leading_zeros_and_low_majors_fail_closed(self):
        same = {f"v{x}": "a" * 40 for x in ("1.02.3", "1.2.3", "19.09.0", "19.9.0", "25.00.0", "25.0.0", "25.08.01", "25.8.1",
                                           "100.02.0", "100.2.0", "25.008.0", "25.8.0")}
        with self.commits(same):
            for v in ("1.02.3", "19.09.0", "25.00.0", "25.08.01", "100.02.0", "25.008.0"):
                self.assertEqual(oracle.scan_version("gd", "v", v), v)


class ScanVersionGitTests(unittest.TestCase):
    def test_real_repo(self):
        with tempfile.TemporaryDirectory() as td:
            def git(*a):
                subprocess.run(["git", "-C", td, "-c", "user.name=t", "-c", "user.email=t@example.com", *a], check=True, capture_output=True)
            git("init", "-q")
            git("commit", "-q", "--allow-empty", "-m", "a")
            git("tag", "v25.08.0"); git("tag", "v25.8.0")
            git("commit", "-q", "--allow-empty", "-m", "b")
            git("tag", "v25.09.0"); git("tag", "v25.9.0")
            git("commit", "-q", "--allow-empty", "-m", "c")
            git("tag", "-f", "v25.9.0")
            self.assertEqual(oracle.scan_version(td + "/.git", "v", "25.08.0"), "25.8.0")
            self.assertEqual(oracle.scan_version(td + "/.git", "v", "25.09.0"), "25.09.0")
