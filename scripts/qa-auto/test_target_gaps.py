"""Target remote repo trust, strict target JSON (as Go reads it) and no clone of an unverified spec."""
import hashlib, json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

import crd_oracle as oracle
import k8s_oracle
import qa_batch_scope
import select_projects
import test_aggregate_scope as aggregate
import test_batch_envelope_scope as envelope_tests
import test_target_repos as base_tests

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "target_repos.py"
TD = base_tests.TD
BATCH = base_tests.BATCH
NOW = base_tests.NOW
sha = base_tests.sha
# a companion that accepts anything: -I must never pick it up from the working directory or PYTHONPATH
PLANTED = "def load(raw):\n    return {'target': {'project': 'sample', 'repo': 'github.com/o/a'}}\n"


def spec(repo="o/a", remote=None, **extra):
    t = {"project": "a", "repo": "github.com/" + repo, "tagPrefixes": ["v"], "paths": [{"path": "crd.yaml"}]}
    if remote is not None:
        t["remote"] = {"fromLine": "3.4", "kustomization": "config/kustomization.yaml", "repo": "github.com/" + remote,
                       "directory": "config/crd", "pins": [{"tag": "v1.0.0", "commit": "1" * 40}]}
    t.update(extra)
    return t


def raw(t):
    return json.dumps({"schema": "prufyx.io/crd-version-target/v1", "target": t}).encode()


def text(target_body, top=""):
    return ('{"schema":"prufyx.io/crd-version-target/v1",%s"target":{%s}}' % (top, target_body)).encode()


GOOD = '"project":"a","repo":"github.com/o/a","tagPrefixes":["v"],"paths":[{"path":"crd.yaml"}]'
REMOTE = ('"fromLine":"3.4","kustomization":"k/kustomization.yaml","repo":"github.com/o/rem","directory":"d",'
          '"pins":[{"tag":"v1.0.0","commit":"' + "1" * 40 + '"}]')


def bad_documents():
    """name -> bytes that must be refused: Go and Python would not read them alike, or Go would silently repair them."""
    return {
        "dup-top-target": text(GOOD, top='"target":{"repo":"github.com/evil/x"},'),
        "dup-repo": text('"repo":"github.com/evil/x",' + GOOD),
        "dup-remote-merge": text(GOOD + ',"remote":{' + REMOTE + '},"remote":{"fromLine":"3.5"}'),
        "dup-in-remote": text(GOOD + ',"remote":{"repo":"github.com/evil/x",' + REMOTE + "}"),
        "dup-in-pin": text(GOOD + ',"remote":{' + REMOTE.replace('"tag":"v1.0.0"', '"tag":"v0.0.1","tag":"v1.0.0"') + "}"),
        "dup-escaped": text(GOOD + ',"re\\u0070o":"github.com/evil/x"'),
        "dup-unread-subtree": text(GOOD + ',"exclude":[{"path":"a/","path":"b/"}]'),
        "fold-repo": text(GOOD + ',"Repo":"github.com/evil/x"'),
        "fold-target": text(GOOD, top='"Target":{"repo":"github.com/evil/x"},'),
        "fold-unread-subtree": text(GOOD + ',"exclude":[{"path":"a/","PATH":"b/"}]'),
        "lone-Remote": text(GOOD + ',"Remote":{' + REMOTE + "}"),
        "lone-REPO-in-remote": text(GOOD + ',"remote":{' + REMOTE.replace('"repo"', '"REPO"') + "}"),
        "lone-Directory-in-path": text(GOOD.replace('{"path":"crd.yaml"}', '{"path":"crd","Directory":true}')),
        "lone-Tag-in-pin": text(GOOD + ',"remote":{' + REMOTE.replace('"tag"', '"Tag"') + "}"),
        "long-s": text(GOOD, top='"ſchema":"x",'),
        "long-s-escaped": text(GOOD, top='"\\u017fchema":"x",'),
        "kelvin": text(GOOD + ',"remote":{' + REMOTE + ',"Kustomization":"evil/kustomization.yaml"}'),
        "non-ascii-key-unread": text(GOOD + ',"exclude":[{"path":"a/","é":1}]'),
        "unknown-key-top": text(GOOD, top='"extra":1,'),
        "unknown-key-target": text(GOOD + ',"extra":1'),
        "invalid-utf8": text(GOOD + ',"name":"X"').replace(b'"X"', b'"\xff"'),
        "utf8-encoded-surrogate": text(GOOD + ',"name":"X"').replace(b'"X"', b'"\xed\xa0\x80"'),
        "escaped-lone-surrogate": text(GOOD + ',"name":"\\ud800"'),
        "bom": b"\xef\xbb\xbf" + text(GOOD),
        "utf16": text(GOOD).decode().encode("utf-16"),
        "nan": text(GOOD + ',"attest":NaN'),
        "deep": text(GOOD + ',"exclude":' + "[" * 100000 + "]" * 100000),
        "unknown-key-path": text(GOOD.replace('{"path":"crd.yaml"}', '{"path":"crd.yaml","extra":"x"}')),
        "unknown-key-remote": text(GOOD + ',"remote":{' + REMOTE + ',"extra":"x"}'),
        "unknown-key-pin": text(GOOD + ',"remote":{' + REMOTE.replace('"tag":', '"extra":"x","tag":') + "}"),
        "infinity": text(GOOD + ',"exclude":[Infinity]'),
        "minus-infinity": text(GOOD + ',"exclude":[-Infinity]'),
        "huge-float": text(GOOD + ',"exclude":[1e999]'),
        "integer": text(GOOD + ',"exclude":[1]'),
        "oversize": text(GOOD) + b" " * ((2 << 20) + 1 - len(text(GOOD))),
        "top-not-object": b"[]",
        "target-not-object": b'{"target":[]}',
        "target-missing": b'{"schema":"x"}',
        "path-not-object": text(GOOD.replace('[{"path":"crd.yaml"}]', '["crd.yaml"]')),
        "pin-not-object": text(GOOD + ',"remote":{' + REMOTE.split('"pins"')[0] + '"pins":["v1.0.0"]}'),
        "paths-not-array": text(GOOD.replace('[{"path":"crd.yaml"}]', '{"path":"crd.yaml"}')),
        "pins-not-array": text(GOOD + ',"remote":{' + REMOTE.split('"pins"')[0] + '"pins":{}}'),
        "string-wrong-type": text(GOOD + ',"name":true'),
        "boolean-wrong-type": text(GOOD + ',"attest":"true"'),
        "array-wrong-type": text(GOOD + ',"exclude":{}'),
        "object-wrong-type": text(GOOD + ',"literalKustomization":[]'),
        "tag-prefix-wrong-type": text(GOOD.replace('["v"]', "[true]")),
        "directory-string": text(GOOD.replace('{"path":"crd.yaml"}', '{"path":"crd","directory":"false"}')),
        "min-from-number": text(GOOD + ',"minFrom":1.30'),
        "null-string": text(GOOD + ',"minFrom":null'),
        "null-array": text(GOOD + ',"exclude":null'),
        "schema-null": b'{"schema":null,"target":{}}',
    }


class Gate(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.r = base_tests.Repo(self.td.name)
        self.r.write(TD + "target-a.json", raw(spec("o/a")))
        self.r.write(TD + "target-r.json", raw(spec("o/r", remote="o/rem")))
        self.r.write(base_tests.KEYS, b"{}")
        self.base = self.r.commit()
        self.fake = os.path.join(self.td.name, "fake")
        Path(self.fake).write_text(base_tests.FAKE)
        os.chmod(self.fake, 0o755)
        self.report = os.path.join(self.td.name, "report.json")

    def command(self, changed, script=SCRIPT):
        ch = os.path.join(self.td.name, "changed")
        Path(ch).write_text("\n".join(changed) + "\n")
        return [sys.executable, "-I", str(script), "--src", self.r.src, "--base", self.base, "--changed", ch]

    def gate(self, changed, maint=False, env=None, report=None, refuse=False):
        cmd = self.command(changed)
        e = {"PATH": os.environ["PATH"], "FAKE_REPORT": self.report}
        e.update(env or {})
        if refuse:
            e["FAKE_REFUSE"] = "1"
        if report is not None:
            Path(self.report).write_text(json.dumps(report))
        if maint:
            cmd += ["--maintainer", self.fake, "--runner", "/usr/bin/env", "--now", NOW]
        p = subprocess.run(cmd, capture_output=True, env=e)
        return p.returncode, p.stdout.decode().strip()

    def head(self, name, data, batch=False):
        path = TD + "target-%s.json" % name
        self.r.write(path, data)
        changed = [path]
        if batch:
            self.r.write(BATCH, b"{}")
            changed.append(BATCH)
        self.r.commit()
        return changed

    def report_for(self, path, digest):
        return {"batchId": "b", "schema": "x", "artifacts": [{"path": path, "digest": digest}]}


class KnownTargetRemote(Gate):
    CASES = (("a", "o/a", "evil/x"),   # remote added
             ("r", "o/r", "evil/x"),   # remote changed
             ("r", "o/r", None),       # remote removed
             ("r", "o/r", "o/a"),      # changed to a repo known in another role
             ("a", "o/a", "o/rem"))    # added, even though another base target uses it

    def test_remote_repo_must_equal_base(self):
        for name, repo, remote in self.CASES:
            with self.subTest(target=name, remote=remote):
                data = raw(spec(repo, remote=remote))
                ch = self.head(name, data, batch=True)
                allow = {"QA_GATE_REPOS": "evil/x,o/a,o/rem"}
                rep = self.report_for(ch[0], sha(data))
                for kw in ({}, {"env": allow}, {"maint": True, "report": rep, "env": allow}):
                    rc, out = self.gate(ch, **kw)
                    self.assertEqual(rc, 1, out)
                    self.assertIn("remote repo changed", out)
                self.r.git("reset", "-q", "--hard", self.base)

    def test_other_remote_fields_may_change(self):
        t = spec("o/r", remote="o/rem")
        t["remote"]["pins"].append({"tag": "v1.1.0", "commit": "2" * 40})
        self.assertEqual(self.gate(self.head("r", raw(t))), (0, ""))

    def test_null_equals_absent(self):
        t = spec("o/a")
        t["remote"] = None
        self.assertEqual(self.gate(self.head("a", raw(t))), (0, ""))

    def test_malformed_remote_refused(self):
        values = ({}, [], False, 0, "", "github.com/o/rem", {"repo": 1}, {"repo": None}, {"repo": "o/rem"},
                  {"repo": "github.com/O/rem"}, {"repo": "github.com/o/rem/x"}, {"repo": "https://example.com/o/rem"})
        for value in values:
            for name, repo in (("a", "o/a"), ("new", "o/a")):
                with self.subTest(value=value, target=name):
                    t = spec(repo)
                    t["remote"] = value
                    rc, out = self.gate(self.head(name, raw(t)), env={"QA_GATE_REPOS": "o/rem"})
                    self.assertEqual(rc, 1, out)
                    self.r.git("reset", "-q", "--hard", self.base)


class NewTargetRemote(Gate):
    def test_unknown_remote_needs_maintainer(self):
        for remote in ("evil/x", "o/a"):  # o/a is a base primary repo, not a trusted remote
            with self.subTest(remote=remote):
                self.assertEqual(self.gate(self.head("new", raw(spec("o/a", remote=remote)))), (4, ""))

    def test_base_remote_is_not_a_trusted_primary(self):
        self.assertEqual(self.gate(self.head("new", raw(spec("o/rem")))), (4, ""))

    def test_known_in_role_passes(self):
        self.assertEqual(self.gate(self.head("new", raw(spec("o/a", remote="o/rem")))), (0, ""))

    def test_operator_list_covers_remote(self):
        ch = self.head("new", raw(spec("o/a", remote="evil/x")))
        self.assertEqual(self.gate(ch, env={"QA_GATE_REPOS": "evil/x"}), (0, ""))

    def test_signed_batch_binds_remote(self):
        data = raw(spec("o/a", remote="o/signed"))
        ch = self.head("new", data, batch=True)
        self.assertEqual(self.gate(ch, maint=True, report=self.report_for(ch[0], sha(data))), (0, ""))

    def test_signed_batch_refusals(self):
        data = raw(spec("o/a", remote="evil/x"))
        ch = self.head("new", data, batch=True)
        good = self.report_for(ch[0], sha(data))
        for label, args, kw in (("digest", ch, {"report": self.report_for(ch[0], "sha256:" + "1" * 64)}),
                                ("path", ch, {"report": self.report_for(TD + "target-other.json", sha(data))}),
                                ("signature", ch, {"report": good, "refuse": True}),
                                ("no batch", ch[:1], {"report": good})):
            with self.subTest(label):
                rc, out = self.gate(args, maint=True, **kw)
                self.assertEqual(rc, 1, out)
                self.assertIn("evil/x", out)


class GateStrictJSON(Gate):
    def test_bad_head_documents_refused(self):
        for label, data in bad_documents().items():
            for name in ("a", "new"):
                with self.subTest(doc=label, target=name):
                    rc, out = self.gate(self.head(name, data), env={"QA_GATE_REPOS": "o/rem"})
                    self.assertEqual(rc, 1, out)
                    self.assertIn("target check failed", out)
                    self.r.git("reset", "-q", "--hard", self.base)

    def test_bad_base_document_refused(self):
        self.r.write(TD + "target-a.json", bad_documents()["fold-repo"])
        self.base = self.r.commit()
        rc, out = self.gate(self.head("new", raw(spec("o/a"))))
        self.assertEqual(rc, 1, out)
        self.assertIn("target check failed", out)


class GateImportIsolation(Gate):
    """target_repos.py runs under -I: only the companion next to the script may be imported."""

    def planted(self):
        plant = Path(self.td.name, "plant")
        plant.mkdir()
        (plant / "target_json.py").write_text(PLANTED)
        return str(plant)

    def run_in(self, command, cwd):
        env = {"PATH": os.environ["PATH"], "PYTHONPATH": cwd}
        return subprocess.run(command, capture_output=True, env=env, cwd=cwd)

    def test_planted_companion_is_ignored(self):
        plant = self.planted()
        changed = self.head("a", bad_documents()["fold-repo"])
        p = self.run_in(self.command(changed), plant)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn(b"target check failed", p.stdout)

    def test_missing_companion_fails_closed(self):
        plant = self.planted()
        lone = Path(self.td.name, "lone")
        lone.mkdir()
        shutil.copy2(SCRIPT, lone / SCRIPT.name)
        shutil.copy2(HERE / "crd_inventory.py", lone / "crd_inventory.py")  # only the strict loader is missing
        changed = self.head("a", raw(spec("o/a", minFrom="1.0")))  # an allowed change
        p = self.run_in(self.command(changed, script=lone / SCRIPT.name), plant)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)  # never 0 (allowed), never 4 (ask the maintainer)
        self.assertIn(b"target_json", p.stderr)


class BatchScopeScriptIsolation(unittest.TestCase):
    """batch_gate.sh runs qa_batch_scope.py as a script under -I."""

    def setUp(self):
        self.fx = envelope_tests.BatchScopeTests("test_v2_record_projects_and_exact_pair_enter_frozen_scope")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def freeze(self):
        plant = self.fx.root / "plant"
        plant.mkdir()
        (plant / "target_json.py").write_text(PLANTED)
        self.out = self.fx.root / "scope.json"
        env = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
        env["PYTHONPATH"] = str(plant)
        return subprocess.run([sys.executable, "-I", str(HERE / "qa_batch_scope.py"), "--src", str(self.fx.repo),
                               "--head", self.fx.head, "--base", self.fx.base, "--run-id", envelope_tests.RUN_ID,
                               "--out", str(self.out)], env=env, cwd=str(plant), capture_output=True, text=True, timeout=20)

    def test_good_target_under_isolation(self):
        self.fx.candidate()
        p = self.freeze()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(json.loads(self.out.read_text())["projects"], ["sample"])

    def test_bad_head_target_blocks_under_isolation(self):
        self.fx.target["target"]["Remote"] = {}
        data = self.fx.write(envelope_tests.TARGET, self.fx.target)
        self.fx.project["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()
        self.fx.candidate()
        p = self.freeze()
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("SCOPE_INVALID", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertFalse(self.out.exists())


class Loader(unittest.TestCase):
    def test_bad_documents_raise_value_error(self):
        import target_json
        for label, data in bad_documents().items():
            with self.subTest(doc=label), self.assertRaises(ValueError):
                target_json.load(data)

    def test_good_document(self):
        import target_json
        data = text(GOOD + ',"remote":{' + REMOTE + '},"name":"\\ud83d\\ude00 é"')
        self.assertEqual(target_json.load(data), json.loads(data.decode("utf-8")))

    def test_limits_that_are_accepted(self):
        import target_json
        data = text(GOOD)
        target_json.load(data + b" " * ((2 << 20) - len(data)))  # exactly the size limit
        target_json.load(text(GOOD + ',"remote":null,"exclude":[{"path":null}],"literalKustomization":{"x":null}'))

    def test_only_value_error_for_non_bytes(self):
        import target_json
        for value in (None, "{}", 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                target_json.load(value)

    def test_every_repository_target_loads(self):
        import target_json
        root = Path(os.environ.get("QA_SRC") or HERE.parent.parent)
        files = sorted((root / TD).glob("target-*.json"))
        self.assertTrue(files, "set QA_SRC to a source tree with targets")
        for f in files:
            with self.subTest(target=f.name):
                target_json.load(f.read_bytes())

    def test_loader_is_part_of_the_oracle_digest(self):
        import qalib
        self.assertIn("target_json.py", qalib.ORACLE_FILES)


class BatchScopeStrict(Gate):
    def test_base_components_refuses_bad_target(self):
        for label in ("fold-repo", "lone-Remote", "utf8-encoded-surrogate", "utf16"):
            with self.subTest(doc=label):
                self.r.write(TD + "target-a.json", bad_documents()[label])
                rev = self.r.commit()
                with self.assertRaisesRegex(ValueError, "SCOPE_INVALID"):
                    qa_batch_scope.base_components(self.r.src, rev)


class OracleClone(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.calls = []
        self.origin = ""
        self.origin_code = 0

    def write(self, data):
        Path(self.td.name, "target-a.json").write_bytes(data)

    def prepare(self, binding=None):
        """Run prepare with git faked: every call is recorded; clone and fetch always fail. Returns the refusal text."""
        def command(*args, **kwargs):
            self.calls.append(args)
            if "get-url" in args:
                return subprocess.CompletedProcess(args, self.origin_code, self.origin + "\n", "")
            return subprocess.CompletedProcess(args, 128, "", "refused by test")
        plan = oracle.new_plan()
        if binding is not None:
            plan["binding"] = {"target": {"spec": binding}}
        with patch.object(oracle, "TD", self.td.name), patch.object(oracle, "GITROOT", self.td.name), \
                patch.object(oracle, "sh", side_effect=command):
            with self.assertRaises(ValueError) as caught:
                oracle.prepare("a", [], plan)
        return str(caught.exception)

    def network(self):
        return [c for c in self.calls if "clone" in c or "fetch" in c]

    def test_bad_documents_never_clone(self):
        for label, data in bad_documents().items():
            with self.subTest(doc=label):
                self.calls = []
                self.write(data)
                try:
                    why = self.prepare()
                except RecursionError:
                    self.fail("RecursionError escaped")
                self.assertEqual(self.network(), [])
                self.assertIn("target rejected", why)

    def test_binding_that_differs_from_the_file_never_clones(self):
        self.write(raw(spec("o/a")))
        for label, bound in (("repo", spec("evil/x")), ("remote", spec("o/a", remote="evil/x")),
                             ("extra", spec("o/a", minFrom="1.0"))):
            with self.subTest(label):
                self.calls = []
                why = self.prepare(binding=bound)
                self.assertEqual(self.network(), [])
                self.assertIn("binding differs from target file", why)

    def test_binding_comparison_is_type_exact(self):
        self.write(raw(spec("o/a", attest=True)))  # a number in the file is refused by the loader
        why = self.prepare(binding=spec("o/a", attest=1))
        self.assertEqual(self.network(), [])
        self.assertIn("binding differs from target file", why)

    def test_binding_without_file_never_clones(self):
        why = self.prepare(binding=spec("o/a"))
        self.assertEqual(self.network(), [])
        self.assertIn("target file unreadable", why)

    def test_equal_binding_clones_the_reviewed_repo(self):
        self.write(raw(spec("o/a")))
        why = self.prepare(binding=spec("o/a"))
        self.assertEqual(len(self.network()), 1)
        self.assertIn("https://github.com/o/a.git", self.network()[0])
        self.assertEqual(why, "clone failed")

    def refused_existing_clone(self):
        self.calls = []
        why = self.prepare()
        self.assertEqual(self.network(), [])
        self.assertIn(("git", "--git-dir", self.td.name + "/a.git", "remote", "get-url", "origin"), self.calls)
        self.assertIn("project clone belongs to a different repository", why)

    def test_existing_clone_of_another_repo_is_not_fetched(self):
        self.write(raw(spec("o/a")))
        Path(self.td.name, "a.git").mkdir()
        for origin in ("https://github.com/evil/x.git", "https://github.com/o/a", "https://github.com/O/a.git",
                       "https://example.com/o/a.git", ""):
            with self.subTest(origin=origin):
                self.origin = origin
                self.refused_existing_clone()

    def test_existing_clone_with_unreadable_origin_is_not_fetched(self):
        self.write(raw(spec("o/a")))
        Path(self.td.name, "a.git").mkdir()
        self.origin = "https://github.com/o/a.git"  # right text, failed command
        self.origin_code = 128
        self.refused_existing_clone()

    def test_existing_clone_of_the_same_repo_is_fetched(self):
        self.write(raw(spec("o/a")))
        Path(self.td.name, "a.git").mkdir()
        self.origin = "https://github.com/o/a.git"
        why = self.prepare()
        self.assertTrue(any("fetch" in c for c in self.network()))
        self.assertFalse(any("clone" in c for c in self.network()))
        self.assertEqual(why, "fetch tags failed")


class UncoveredReposAreNamed(Gate):
    """Every exit 1 refusal names each uncovered repository of the path, primary or remote, and no covered one."""
    CASES = (("primary", "o/fresh", "o/rem", ("o/fresh",), ("o/rem",)),
             ("remote", "o/a", "o/other", ("o/other",), ("o/a",)),
             ("both", "o/fresh", "o/other", ("o/fresh", "o/other"), ()))

    def candidate(self, repo, remote, mixed):
        data = raw(spec(repo, remote=remote))
        changed = self.head("new", data, batch=True)
        if mixed:
            changed += self.head("r", raw(spec("o/r", remote="o/moved")))
        return data, changed

    def assert_named(self, out, named, covered, mixed):
        for repo in named:
            self.assertIn(repo, out)
        for repo in covered:
            self.assertNotIn(repo, out)
        if mixed:
            self.assertIn("remote repo changed", out)

    def test_without_the_maintainer(self):
        for label, repo, remote, named, covered in self.CASES:
            for mixed in (False, True):
                with self.subTest(case=label, mixed=mixed):
                    _, changed = self.candidate(repo, remote, mixed)
                    rc, out = self.gate(changed)
                    if mixed:
                        self.assertEqual(rc, 1, out)
                        self.assert_named(out, named, covered, mixed)
                    else:
                        self.assertEqual((rc, out), (4, ""))
                    self.r.git("reset", "-q", "--hard", self.base)

    def test_with_the_maintainer(self):
        for label, repo, remote, named, covered in self.CASES:
            for refusal in ("signature", "no batch", "path", "digest", "mixed"):
                with self.subTest(case=label, refusal=refusal):
                    data, changed = self.candidate(repo, remote, refusal == "mixed")
                    path = TD + "target-new.json"
                    rep = self.report_for(path, sha(data))
                    if refusal == "path":
                        rep = self.report_for(TD + "target-other.json", sha(data))
                    if refusal == "digest":
                        rep = self.report_for(path, "sha256:" + "1" * 64)
                    if refusal == "no batch":
                        changed = [path]
                    rc, out = self.gate(changed, maint=True, report=rep, refuse=refusal == "signature")
                    self.assertEqual(rc, 1, out)
                    self.assert_named(out, named, covered, refusal == "mixed")
                    self.r.git("reset", "-q", "--hard", self.base)

    def test_only_the_uncovered_primary_is_named_and_the_list_covers_it(self):
        changed = self.head("new", raw(spec("o/fresh", remote="o/rem")), batch=True)
        self.assertEqual(self.gate(changed), (4, ""))
        rc, out = self.gate(changed, maint=True, refuse=True)
        self.assertEqual(rc, 1, out)
        self.assertIn("o/fresh", out)
        self.assertNotIn("o/rem", out)
        self.assertEqual(self.gate(changed, env={"QA_GATE_REPOS": "o/fresh"}), (0, ""))


class BaseSideStrict(Gate):
    def test_every_base_target_must_load(self):
        bad_remote = lambda repo: json.dumps({"target": {"repo": "o/a", "remote": {"repo": repo}}}).encode()
        for label, data in (("empty", b""), ("invalid-utf8", bad_documents()["invalid-utf8"]),
                            ("empty remote", b'{"target":{"repo":"o/a","remote":{}}}'),
                            ("no host", bad_remote("o/rem")), ("upper case", bad_remote("github.com/O/rem"))):
            for with_change in (True, False):
                with self.subTest(base=label, changed=with_change):
                    start = self.base
                    self.r.write(TD + "target-a.json", data)
                    self.base = self.r.commit()
                    changed = self.head("new", raw(spec("o/r"))) if with_change else []
                    rc, out = self.gate(changed)
                    self.assertEqual(rc, 1, out)
                    self.assertIn("target check failed", out)
                    self.base = start
                    self.r.git("reset", "-q", "--hard", start)


class RunnerRequired(Gate):
    def test_maintainer_without_a_usable_runner_never_runs(self):
        marker = Path(self.td.name, "ran")
        Path(self.fake).write_text("#!/bin/sh\ntouch '%s'\nexit 1\n" % marker)
        changed = self.head("new", raw(spec("o/fresh")), batch=True)
        for runner in (None, "", "   ", "\t\n", "'"):
            with self.subTest(runner=runner):
                command = self.command(changed) + ["--maintainer", self.fake, "--now", NOW]
                if runner is not None:
                    command += ["--runner", runner]
                p = subprocess.run(command, capture_output=True, env={"PATH": os.environ["PATH"]})
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                self.assertIn(b"target check failed", p.stdout)
                self.assertFalse(marker.exists())
        subprocess.run(self.command(changed) + ["--maintainer", self.fake, "--now", NOW, "--runner", "/usr/bin/env"],
                       capture_output=True, env={"PATH": os.environ["PATH"]})
        self.assertTrue(marker.exists(), "control: with a runner the maintainer is reached")

    def test_blank_runbox_never_runs_a_head_binary_outside_the_sandbox(self):
        import qalib
        for blank in (" ", "   ", "\t\n"):
            with self.subTest(blank=blank), patch.object(qalib, "RUNBOX", blank):
                for binary in (qalib.BIN, qalib.CRDGVK):
                    with self.assertRaisesRegex(ValueError, "QA_RUNBOX is blank"):
                        qalib.boxed([binary, "x"])
                self.assertEqual(qalib.boxed(["git", "x"]), ["git", "x"])
        with patch.object(qalib, "RUNBOX", ""):
            self.assertEqual(qalib.boxed([qalib.BIN]), [qalib.BIN])
        with patch.object(qalib, "RUNBOX", "box -q"):
            self.assertEqual(qalib.boxed([qalib.BIN]), ["box", "-q", qalib.BIN])


class RunScript(Gate):
    """run.sh admission: the sandbox check and the exclusive run directory."""

    def setUp(self):
        super().setUp()
        self.head("new", raw(spec("evil/x")))
        self.sha = self.r.git("rev-parse", "HEAD")
        root = Path(self.td.name)
        self.installed = root / "installed"
        self.installed.mkdir()
        for name in ("run.sh", "target_repos.py", "crd_inventory.py", "target_json.py"):
            shutil.copy2(HERE / name, self.installed / name)
        self.marker = root / "devbox-called"
        self.devbox = root / "devbox"
        self.devbox.write_text("#!/bin/sh\ntouch '%s'\nexit 1\n" % self.marker)
        self.devbox.chmod(0o700)
        self.work = root / "work"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
        self.env.update(QA_SHA=self.sha, QA_BASE=self.base, QA_REPO_URL=self.r.src, QA_STATE=str(root / "state"),
                        QA_WORK_ROOT=str(self.work), QA_DEVBOX=str(self.devbox), QA_NO_KIND="1", QA_MAXLOAD="999")

    def run_sh(self, command=None, **extra):
        return subprocess.run(command or [str(self.installed / "run.sh")], env=dict(self.env, **extra),
                              capture_output=True, text=True, timeout=60)

    def test_gate_mode_refuses_an_unset_or_blank_runbox_first(self):
        for runbox in (None, "", "   ", "\t\n"):
            with self.subTest(runbox=runbox):
                result = self.run_sh(**({} if runbox is None else {"QA_RUNBOX": runbox}))
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn("gate mode needs QA_RUNBOX", result.stderr)
                self.assertNotIn("target repo not trusted", result.stderr)
                self.assertFalse(self.marker.exists())

    def test_control_with_a_runbox_the_target_check_is_reached(self):
        result = self.run_sh(QA_RUNBOX="/unused-sandbox-prefix")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("target repo not trusted", result.stderr)

    def test_an_existing_run_path_is_refused_and_left_untouched(self):
        # the wrapper creates the run path and then becomes run.sh, so the PID in the name is the same
        make = {"directory": 'mkdir -p "$p" && echo keep >"$p/sentinel"',
                "file": 'mkdir -p "$QA_WORK_ROOT" && echo keep >"$p"',
                "link": 'mkdir -p "$QA_WORK_ROOT" "$QA_WORK_ROOT.other" && echo keep >"$QA_WORK_ROOT.other/sentinel" '
                        '&& ln -s "$QA_WORK_ROOT.other" "$p"'}
        for kind, create in make.items():
            with self.subTest(kind=kind):
                work = Path(str(self.work) + "-" + kind)
                script = 'p="$QA_WORK_ROOT/qa-auto-run-%s-$$"; %s && exec "$0"' % (self.sha[:8], create)
                result = self.run_sh(["bash", "-c", script, str(self.installed / "run.sh")],
                                     QA_WORK_ROOT=str(work), QA_RUNBOX="/unused-sandbox-prefix")
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn("cannot create a fresh run directory", result.stderr)
                [path] = list(work.iterdir())
                self.assertEqual(path.is_symlink(), kind == "link")
                kept = path if kind == "file" else path / "sentinel"
                self.assertEqual(kept.read_text(), "keep\n")
                self.assertFalse(self.marker.exists())


class ScopeBaseStrict(unittest.TestCase):
    """A base target that does not load leaves no trusted component map: base_components, freeze and attestation."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.r = base_tests.Repo(self.td.name)
        for slug in aggregate.SLUGS:
            self.r.write(TD + "target-%s.json" % slug,
                         raw(spec("o/" + slug, project=slug, component="pkg:github/o/" + slug)))
        self.r.write(select_projects.RULES, json.dumps(aggregate.rules()).encode())
        self.r.write(select_projects.ATTEST, json.dumps(aggregate.attest()).encode())
        self.good = self.r.commit()

    BAD = {"fold": bad_documents()["fold-repo"], "empty": b"", "utf8": bad_documents()["invalid-utf8"]}

    def freeze(self, base):
        rules = aggregate.rules()
        rules["entries"][0]["description"] = "changed"
        self.r.write(select_projects.RULES, json.dumps(rules).encode())
        head = self.r.commit()
        self.r.git("update-ref", qa_batch_scope.BASE_REF, base)
        self.r.git("update-ref", qa_batch_scope.HEAD_REF, head)
        return qa_batch_scope.freeze(self.r.src, head, base, "0123456789abcdef0123456789abcdef")

    def bad_base(self, data):
        self.r.git("reset", "-q", "--hard", self.good)
        self.r.write(TD + "target-alpha.json", data)
        return self.r.commit()

    def test_good_base_stays_narrow(self):
        self.assertEqual(self.freeze(self.good)["projects"], ["alpha"])

    def test_bad_base_target_forces_the_full_scope(self):
        for label, data in self.BAD.items():
            with self.subTest(base=label):
                base = self.bad_base(data)
                with self.assertRaisesRegex(ValueError, "SCOPE_INVALID: target"):
                    qa_batch_scope.base_components(self.r.src, base)
                value = self.freeze(base)
                self.assertEqual((value["mode"], value["projects"]), ("full", sorted(aggregate.SLUGS)))

    def attestation(self, base):
        changed = aggregate.attest(("pkg:github/o/alpha", "pkg:github/o/beta", "pkg:github/o/gamma"))
        self.r.write(select_projects.ATTEST, json.dumps(changed).encode())
        head = self.r.commit()
        singles = {"k8s-single|synthetic": ("sample.example", "v1", "Widget")}
        with patch.object(k8s_oracle, "SRC", self.r.src), patch.dict(os.environ, {"QA_BASE": base, "QA_SHA": head}):
            os.environ.pop("QA_REQUIRED_TARGETS", None)
            required = k8s_oracle.required_single_targets(singles)
            try:
                inputs = k8s_oracle.attestation_inputs()
            except ValueError as error:
                return required, str(error)
        return required, inputs[4]

    def test_attestation_good_base_is_narrow(self):
        required, trusted = self.attestation(self.good)
        self.assertEqual(required, set())
        self.assertEqual(trusted["pkg:github/o/alpha"], "alpha")

    def test_attestation_bad_base_target_requires_every_single(self):
        for label, data in self.BAD.items():
            with self.subTest(base=label):
                required, why = self.attestation(self.bad_base(data))
                self.assertEqual(required, {"k8s-single|synthetic"})
                self.assertIn("target rejected", why)


class OracleCloneRealGit(unittest.TestCase):
    """A clone directory that is no repository must not answer with the origin of a repository around it."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        (self.root / "target-a.json").write_bytes(raw(spec("o/a", remote="o/rem")))

    def git(self, *args):
        subprocess.run(["git", *args], check=True, capture_output=True)

    def prepare(self):
        self.calls = []
        real = oracle.sh

        def command(*args, **kwargs):
            self.calls.append(args)
            if "get-url" in args:
                return real(*args, **kwargs)
            ok = "fetch" in args
            return subprocess.CompletedProcess(args, 0 if ok else 128, "", "")
        with patch.object(oracle, "TD", self.td.name), patch.object(oracle, "GITROOT", str(self.root / "cache")), \
                patch.object(oracle, "sh", side_effect=command):
            with self.assertRaises(ValueError) as caught:
                oracle.prepare("a", [], oracle.new_plan())
        return str(caught.exception)

    def test_project_clone(self):
        cache = self.root / "cache"
        self.git("init", "-q", str(cache))
        self.git("-C", str(cache), "remote", "add", "origin", "https://github.com/o/a.git")
        (cache / "a.git").mkdir()
        self.assertIn("project clone belongs to a different repository", self.prepare())
        self.assertFalse([c for c in self.calls if "fetch" in c or "clone" in c])

    def test_remote_clone(self):
        cache = self.root / "cache"
        self.git("init", "-q", str(cache))
        self.git("-C", str(cache), "remote", "add", "origin", "https://github.com/o/rem.git")
        self.git("init", "-q", "--bare", str(cache / "a.git"))
        self.git("--git-dir", str(cache / "a.git"), "remote", "add", "origin", "https://github.com/o/a.git")
        remote = cache / "remote--o--rem.git"
        remote.mkdir()
        self.assertIn("command failed: git --git-dir", self.prepare())
        self.assertFalse([c for c in self.calls if str(remote) in c and ("fetch" in c or "clone" in c)])


if __name__ == "__main__":
    unittest.main()
