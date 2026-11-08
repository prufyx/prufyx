"""Source failures cannot reduce the expected GVK set."""
import json
import os
import shutil
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

    def test_remote_line_without_remote_clone_is_explicit_error(self):
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


KUST = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
CRD = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"


class RemoteServedTests(unittest.TestCase):
    """Remote-served releases are read from a pinned second clone, mirroring the extractor; every doubt is an error."""
    URL = "https://github.com/o/cfg/config/crd/ic?ref=%s"

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e.x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e.x")

    def tearDown(self):
        self.td.cleanup()

    def git(self, wt, *a):
        return subprocess.run(["git", "-C", str(wt), *a], check=True, capture_output=True, text=True, env=self.env).stdout.strip()

    def repo(self, name, files, tag):
        wt = self.root / name
        shutil.rmtree(wt, ignore_errors=True)
        wt.mkdir()
        self.git(wt, "init", "-q")
        self.commit(wt, files, tag)
        return wt

    def commit(self, wt, files, tag):
        for rel, body in files.items():
            f = wt / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            if f.is_symlink() or f.exists():
                f.unlink()
            if isinstance(body, tuple):
                os.symlink(body[0], f)
            else:
                f.write_text(body)
        self.git(wt, "add", "-A")
        self.git(wt, "commit", "-qm", "c")
        self.git(wt, "tag", "-f", tag)
        return self.git(wt, "rev-parse", "HEAD")

    def world(self, rel_kust=None, dir_files=None, pin=True, ref="v1.0.0"):
        rel_kust = rel_kust if rel_kust is not None else KUST + "- " + self.URL % ref + "\n"
        self.rel = self.repo("rel", {"config/crd/kustomization.yaml": rel_kust}, "v3.4.0")
        files = dir_files if dir_files is not None else {
            "config/crd/ic/kustomization.yaml": KUST + "- a.yaml\n- b.yaml\n",
            "config/crd/ic/a.yaml": CRD + "metadata: {name: a}\n", "config/crd/ic/b.yaml": CRD + "metadata: {name: b}\n",
            "config/crd/ic/unlisted.yaml": "not read\n"}
        self.cfg = self.repo("cfg", files, ref)
        commit = self.git(self.cfg, "rev-parse", "HEAD")
        self.tj = {"paths": [{"path": "config/crd/bases", "directory": True, "match": "yaml$"}], "remote": {
            "fromLine": "3.4", "kustomization": "config/crd/kustomization.yaml", "repo": "github.com/o/cfg",
            "directory": "config/crd/ic", "pins": [{"tag": ref, "commit": commit}] if pin else []}}
        return str(self.rel / ".git"), str(self.cfg / ".git")

    def text(self, gd, rgd, tag="v3.4.0", name="v3.4.0"):
        return oracle.crd_text(self.tj, gd, tag, name, rgd)

    def test_reads_listed_files_at_the_pinned_commit(self):
        gd, rgd = self.world()
        t = self.text(gd, rgd)
        self.assertEqual(t.count("CustomResourceDefinition"), 2)
        self.assertNotIn("not read", t)

    def test_release_before_the_line_is_not_remote(self):
        gd, rgd = self.world()
        with self.assertRaises(ValueError):  # own path absent: error, and never the remote files
            oracle.crd_text(self.tj, gd, "v3.4.0", "v3.3.0", rgd)

    def test_no_pin_is_error(self):
        gd, rgd = self.world(pin=False)
        with self.assertRaises(ValueError):
            self.text(gd, rgd)

    def test_pin_for_another_tag_is_error(self):
        gd, rgd = self.world()
        self.tj["remote"]["pins"][0]["tag"] = "v1.0.1"
        with self.assertRaises(ValueError):
            self.text(gd, rgd)

    def test_moved_tag_is_error(self):
        gd, rgd = self.world()
        self.commit(self.cfg, {"config/crd/ic/a.yaml": CRD + "metadata: {name: moved}\n"}, "v1.0.0")
        with self.assertRaises(ValueError):
            self.text(gd, rgd)

    def test_missing_or_unreadable_remote_clone_is_error(self):
        gd, _ = self.world()
        for rgd in (None, "", str(self.root / "absent.git"), str(self.root)):
            with self.subTest(rgd=rgd), self.assertRaises(ValueError):
                self.text(gd, rgd)

    def test_extra_key_in_either_kustomization_is_error(self):
        extra = "namePrefix: x-\n"
        gd, rgd = self.world(rel_kust=KUST + "- " + self.URL % "v1.0.0" + "\n" + extra)
        with self.assertRaises(ValueError):
            self.text(gd, rgd)
        gd, rgd = self.world(dir_files={"config/crd/ic/kustomization.yaml": KUST + "- a.yaml\n" + "patches:\n- x.yaml\n",
                                        "config/crd/ic/a.yaml": CRD})
        with self.assertRaises(ValueError):
            self.text(gd, rgd)

    def test_release_resource_must_be_exactly_the_declared_remote(self):
        for res in ("https://github.com/o/other/config/crd/ic?ref=v1.0.0", "http://github.com/o/cfg/config/crd/ic?ref=v1.0.0",
                    "https://github.com/o/cfg/config/crd/ic", "https://github.com/o/cfg/config/crd/ic?ref=main",
                    "https://github.com/o/cfg/config/crd/ic?ref=v1.0.0&x=y", "https://github.com/o/cfg/config/crd/ic?ref=v1.0.0#f",
                    "https://u@github.com/o/cfg/config/crd/ic?ref=v1.0.0", "../x.yaml"):
            with self.subTest(res=res):
                gd, rgd = self.world(rel_kust=KUST + "- " + res + "\n")
                with self.assertRaises(ValueError):
                    self.text(gd, rgd)
        gd, rgd = self.world(rel_kust=KUST + "- " + self.URL % "v1.0.0" + "\n- local.yaml\n")
        with self.assertRaises(ValueError):
            self.text(gd, rgd)

    def test_symlink_resource_is_error(self):
        gd, rgd = self.world(dir_files={"config/crd/ic/kustomization.yaml": KUST + "- a.yaml\n", "config/crd/ic/real.yaml": CRD,
                                        "config/crd/ic/a.yaml": ("real.yaml",)})
        with self.assertRaises(ValueError):
            self.text(gd, rgd)

    def test_listed_but_missing_or_non_plain_names_are_errors(self):
        for names in ("- gone.yaml\n", "- ../a.yaml\n", "- sub/a.yaml\n", "- a.yaml\n- a.yaml\n", "- kustomization.yaml\n", "- a.json\n"):
            with self.subTest(names=names):
                gd, rgd = self.world(dir_files={"config/crd/ic/kustomization.yaml": KUST + names, "config/crd/ic/a.yaml": CRD})
                with self.assertRaises(ValueError):
                    self.text(gd, rgd)

    def test_oversized_definition_blob_is_error_remote_and_local(self):
        limit = oracle.MAX_DEFINITION_BYTES
        self.assertEqual(limit, 8 << 20)
        for size, ok in ((limit, True), (limit + 1, False)):
            body = CRD + "#" * (size - len(CRD.encode()) - 1) + "\n"
            self.assertEqual(len(body.encode()), size)
            with self.subTest(size=size, where="remote"):
                gd, rgd = self.world(dir_files={"config/crd/ic/kustomization.yaml": KUST + "- a.yaml\n", "config/crd/ic/a.yaml": body})
                if ok:
                    self.assertIn("CustomResourceDefinition", self.text(gd, rgd))
                else:
                    with self.assertRaises(ValueError):
                        self.text(gd, rgd)
            with self.subTest(size=size, where="local"):
                gd = str(self.repo("loc", {"crds/a.yaml": body}, "v1.0.0") / ".git")
                tj = {"paths": [{"path": "crds/a.yaml"}]}
                if ok:
                    self.assertIn("CustomResourceDefinition", oracle.crd_text(tj, gd, "v1.0.0", "v1.0.0"))
                else:
                    with self.assertRaises(ValueError):
                        oracle.crd_text(tj, gd, "v1.0.0", "v1.0.0")

    def test_empty_blob_and_template_are_errors(self):
        gd, rgd = self.world(dir_files={"config/crd/ic/kustomization.yaml": KUST + "- a.yaml\n", "config/crd/ic/a.yaml": "\n"})
        with self.assertRaises(ValueError):
            self.text(gd, rgd)
        gd, rgd = self.world(dir_files={"config/crd/ic/kustomization.yaml": KUST + "- '{{ x }}.yaml'\n", "config/crd/ic/a.yaml": CRD})
        with self.assertRaises(ValueError):
            self.text(gd, rgd)

    def test_missing_release_kustomization_is_error(self):
        gd, rgd = self.world()
        with self.assertRaises(ValueError):
            oracle.crd_text(self.tj, gd, "nosuchtag", "v3.4.0", rgd)

    def test_kustomization_reader_is_strict(self):
        ok = oracle.kustomization_resources("k", "# c\n---\n" + KUST + "  - a.yaml # c\n  - 'b.yaml'\n  - \"c.yaml\" # d\n")
        self.assertEqual(ok, ["a.yaml", "b.yaml", "c.yaml"])
        for bad in ("", KUST, KUST + "- a.yaml\n" + "kind: Kustomization\n", "kind: Kustomization\nresources:\n- a.yaml\n",
                    KUST.replace("v1beta1", "v1") + "- a.yaml\n", KUST + "- &a a.yaml\n", KUST + "- a.yaml#c\n", KUST + "- 'a.yaml\n",
                    KUST + "- {a: b}\n", KUST + "- a.yaml\n---\n" + KUST + "- b.yaml\n", "resources: [a.yaml]\n" + KUST,
                    KUST.replace("resources:", "resources: x") + "- a.yaml\n", KUST + "- a.yaml\n\tx: y\n",
                    KUST + "- a.yaml\n  - b.yaml\n", KUST + "  - a.yaml\n- b.yaml\n", KUST + "  - a.yaml\n    - b.yaml\n",
                    KUST + "  - a.yaml\n - b.yaml\n", KUST + "- a.yaml\n\t- b.yaml\n", KUST + "  - a.yaml\n\t- b.yaml\n",
                    KUST + "- " + "\n- ".join("f%d.yaml" % i for i in range(513)) + "\n"):
            with self.subTest(bad=bad[:40]), self.assertRaises(ValueError):
                oracle.kustomization_resources("k", bad)

    def test_validate_target_checks_the_remote_block(self):
        base = {"repo": "o/r", "tagPrefixes": ["v"], "paths": [{"path": "crds"}]}
        rm = {"fromLine": "3.4", "kustomization": "k/kustomization.yaml", "repo": "github.com/o/cfg", "directory": "d",
              "pins": [{"tag": "v1.0.0", "commit": "a" * 40}]}
        self.assertEqual(oracle.validate_target(dict(base, remote=rm))[1], "")
        for bad in (dict(rm, pins=[{"tag": "main", "commit": "a" * 40}]), dict(rm, pins=[{"tag": "v1.0.0", "commit": "abc"}]),
                    dict(rm, pins=[]), dict(rm, directory="../x"), dict(rm, repo="o"), dict(rm, kustomization="-x")):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                self.assertEqual(oracle.validate_target(dict(base, remote=bad))[1], "")


@unittest.skipUnless(os.environ.get("QA_GOLDEN_JSONL"), "needs QA_GOLDEN_JSONL, QA_GOLDEN_REL and QA_GOLDEN_REMOTE (bare clones, network to fetch them)")
class RemoteGoldenTests(unittest.TestCase):
    """Rows the extractor's remote reader yields per release (one JSON object per line: tag, rows "G|V|K|served") must
    equal the rows the oracle derives from the same two clones; a release either side refuses fails the test."""

    def test_oracle_rows_equal_the_extractor_reader(self):
        tj = json.loads(Path(oracle.TD, "target-kong-ingress-controller.json").read_text())["target"]
        rel, rem = os.environ["QA_GOLDEN_REL"], os.environ["QA_GOLDEN_REMOTE"]
        n = 0
        for line in Path(os.environ["QA_GOLDEN_JSONL"]).read_text().splitlines():
            g = json.loads(line)
            with self.subTest(tag=g["tag"]):
                self.assertNotIn("err", g)
                rows = oracle.crd_rows(tj, rel, g["tag"], g["tag"], rem)
                self.assertEqual(sorted("%s|%s|%s|%s" % (r["G"], r["V"], r["K"], str(r["Served"]).lower()) for r in rows), sorted(g["rows"]))
                n += 1
        self.assertGreater(n, 0)


if __name__ == "__main__":
    unittest.main()
