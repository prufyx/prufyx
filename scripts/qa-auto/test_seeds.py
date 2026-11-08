"""Seeded wrong-PASS cases: every injected wrong PASS must be caught before the real corpus counts; each detection is proven by
breaking it by hand (a weakened classifier must leave its seed uncaught), and every acceptance path has a refusal test."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import crd_oracle
import k8s_oracle
import qalib
import seeds
from seeded_support import STUB_SEEDS, write_seeded
from test_batch_envelope_scope import gate_source

HERE = Path(__file__).resolve().parent
SEED_BY_ID = {s["id"]: s for s in seeds.SEEDS}
WEAK_PAIR = (False, False, [], [], False, "OK")
WEAK_SCOPED = (False, False, [], [])


def by_kind(*kinds):
    return [s["id"] for s in seeds.SEEDS if s["kind"] in kinds]


class SeedDefinition(unittest.TestCase):
    def test_all_seeds_caught_by_the_real_classifier(self):
        caught, uncaught = seeds.run_all()
        self.assertEqual(uncaught, [])
        self.assertEqual(len(caught), len(seeds.SEEDS))

    def test_minimum_and_span(self):
        self.assertGreaterEqual(len(seeds.SEEDS), 6)
        self.assertTrue(seeds.check_unique_ids())
        kinds = {s["kind"] for s in seeds.SEEDS}
        self.assertTrue({"crd_pair", "k8s_scan", "k8s_stage", "k8s_overall", "rules_control", "rules_variant"} <= kinds)
        crd_ids = by_kind("crd_pair")
        whole = [i for i in crd_ids if SEED_BY_ID[i]["whole"] and len(SEED_BY_ID[i]["whole"]) == len(SEED_BY_ID[i]["removed"])]
        version = [i for i in crd_ids if not SEED_BY_ID[i]["whole"]]
        mixed = [i for i in crd_ids if SEED_BY_ID[i]["whole"] and len(SEED_BY_ID[i]["whole"]) < len(SEED_BY_ID[i]["removed"])]
        self.assertTrue(whole and version and mixed)

    def test_every_seed_has_a_real_expected_removal_or_is_a_rules_seed(self):
        for s in seeds.SEEDS:
            if s["kind"].startswith("rules"):
                continue
            self.assertTrue(s["removed"], s["id"])
            self.assertTrue(all(len(x) == 3 and all(isinstance(p, str) and p for p in x[1:]) for x in s["removed"]), s["id"])

    def test_fabricated_results_are_pass_like(self):
        for s in seeds.SEEDS:
            if "report" not in s:
                continue
            report = s["report"]
            text = json.dumps(report)
            self.assertTrue(s["code"] == 0 or "PASS" in text or s["kind"] == "k8s_stage", s["id"])
            self.assertEqual(report.get("findings", []), [], s["id"])

    def test_an_uncaught_clean_result_is_not_counted_as_caught(self):
        # a clean control is not flagged: the evaluation is not "flag everything"
        clean = {"id": "ctl", "kind": "crd_pair", "code": 11, "removed": [seeds.WHOLE], "whole": [seeds.WHOLE],
                 "report": {"verdict": "UNKNOWN", "findings": [], "paths": [{"component": seeds.CRD_PROJECT, "hops": [
                     {"status": "NO_DATA", "reasons": ["COMPONENT_NOT_COVERED"]}]}],
                     "gaps": [{"component": seeds.CRD_PROJECT, "reason": "COMPONENT_NOT_COVERED"}]}}
        self.assertFalse(seeds.evaluate(clean))


class MutationChecks(unittest.TestCase):
    """The seed test fails when the detection is broken by hand: a weakened classifier leaves the seed uncaught."""

    def assert_uncaught(self, ids):
        for i in ids:
            self.assertFalse(seeds.evaluate(SEED_BY_ID[i]), i)

    def test_weakened_crd_classifier_misses_every_crd_seed(self):
        self.assertTrue(all(seeds.evaluate(SEED_BY_ID[i]) for i in by_kind("crd_pair")))
        with mock.patch.object(crd_oracle, "classify_pair", return_value=WEAK_PAIR):
            self.assert_uncaught(by_kind("crd_pair"))

    def test_weakened_scoped_result_misses_scan_and_scan_bound_stage_seeds(self):
        with mock.patch.object(qalib, "scoped_result", return_value=WEAK_SCOPED), \
                mock.patch.object(k8s_oracle, "scoped_result", return_value=WEAK_SCOPED):
            self.assert_uncaught(by_kind("k8s_scan") + ["k8s-plan-stage-scan-pass"])
            self.assertTrue(seeds.evaluate(SEED_BY_ID["k8s-plan-stage-verdict-pass"]))  # caught by the stage's own verdict term

    def test_weakened_plan_stage_check_misses_both_stage_seeds(self):
        with mock.patch.object(k8s_oracle, "plan_stage_outcome", return_value=(False, False, [], [], True)):
            self.assert_uncaught(by_kind("k8s_stage"))

    def test_weakened_plan_overall_check_misses_the_overall_seed(self):
        with mock.patch.object(k8s_oracle, "plan_overall_wrongpass", return_value=False):
            self.assert_uncaught(by_kind("k8s_overall"))

    def test_weakened_rules_checks_miss_the_rules_seeds(self):
        with mock.patch.object(qalib, "rules_control_wrongpass", return_value=False):
            self.assert_uncaught(by_kind("rules_control"))
        with mock.patch.object(qalib, "rules_variant_wrongpass", return_value=False):
            self.assert_uncaught(by_kind("rules_variant"))

    def test_scanner_pass_blind_classifier_leaves_exactly_the_exit_pass_seeds_uncaught(self):
        blind = lambda code, report: False
        masked = {"crd-whole-unknown-family-pass-masked", "crd-mixed-blocked-family-pass", "k8s-range-family-pass-masked",
                  "k8s-plan-stage-verdict-pass"}
        with mock.patch.object(qalib, "is_pass", blind), mock.patch.object(crd_oracle, "is_pass", blind), \
                mock.patch.object(k8s_oracle, "is_pass", blind):
            for s in seeds.SEEDS:
                if s["kind"].startswith("rules"):
                    continue
                self.assertEqual(seeds.evaluate(s), s["id"] in masked, s["id"])

    def test_run_all_reports_uncaught_ids_and_a_crash_is_uncaught(self):
        with mock.patch.object(crd_oracle, "classify_pair", return_value=WEAK_PAIR):
            caught, uncaught = seeds.run_all()
        self.assertEqual(sorted(uncaught), sorted(by_kind("crd_pair")))
        self.assertEqual(len(caught) + len(uncaught), len(seeds.SEEDS))
        with mock.patch.object(crd_oracle, "classify_pair", side_effect=RuntimeError("boom")):
            _caught, uncaught = seeds.run_all()
        self.assertEqual(sorted(uncaught), sorted(by_kind("crd_pair")))

    def test_candidate_rules_cannot_change_what_a_seed_means(self):
        # the classifier is handed the frozen registry, never SRC/rules.json: an empty candidate registry changes nothing
        with mock.patch.object(qalib, "SRC", "/nonexistent"):
            self.assertEqual(seeds.run_all()[1], [])


class RunnerRefusals(unittest.TestCase):
    def run_main(self, out, *extra, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
        e.update(env or {})
        script = extra[0] if extra else str(HERE / "seeds.py")
        args = [sys.executable, "-I", script, "--out", str(out)] + list(extra[1:])
        r = subprocess.run(args, capture_output=True, text=True, env=e)
        return r, (json.loads(Path(out).read_text()) if Path(out).exists() else None)

    def test_clean_run_writes_all_caught(self):
        with tempfile.TemporaryDirectory() as td:
            r, d = self.run_main(Path(td) / "s.json")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual((d["caught"], d["total"], d["uncaught"], d["error"]), (len(seeds.SEEDS), len(seeds.SEEDS), [], None))
            self.assertEqual(d["digest"], seeds.seeds_file_digest())
            self.assertIn("SEEDED=%d/%d" % (len(seeds.SEEDS), len(seeds.SEEDS)), r.stdout)

    def test_seeds_inside_the_candidate_tree_are_refused(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "src"
            (src / "scripts/qa-auto").mkdir(parents=True)
            head_copy = src / "scripts/qa-auto/seeds.py"
            shutil.copy2(HERE / "seeds.py", head_copy)
            for extra, env in (([str(head_copy), "--src", str(src)], {}), ([str(head_copy)], {"QA_SRC": str(src)}),
                               ([str(head_copy)], {"QA_BOX_DIR": str(src)})):
                out = Path(td) / "o.json"
                out.unlink(missing_ok=True)
                r, d = self.run_main(out, *extra, env=env)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertEqual(d["caught"], 0)
                self.assertIn("candidate tree", d["error"])

    def test_seeds_from_the_base_directory_are_accepted_next_to_a_src(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "src").mkdir()
            r, d = self.run_main(Path(td) / "o.json", str(HERE / "seeds.py"), "--src", str(Path(td) / "src"))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_pinned_digest_mismatch_is_refused_and_match_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            r, d = self.run_main(Path(td) / "a.json", env={"QA_SEEDS_DIGEST": "0" * 64})
            self.assertEqual(r.returncode, 3)
            self.assertEqual(d["caught"], 0)
            self.assertIn("pinned", d["error"])
            r, d = self.run_main(Path(td) / "b.json", env={"QA_SEEDS_DIGEST": seeds.seeds_file_digest()})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_missed_seed_is_exit_2_and_not_all_caught(self):
        with tempfile.TemporaryDirectory() as td:
            # a classifier that never flags anything, injected into the real runner module
            code = ("import sys, json; sys.path.insert(0, %r); import crd_oracle, seeds; "
                    "crd_oracle.classify_pair = lambda *a, **k: (False, False, [], [], False, 'OK'); "
                    "sys.exit(seeds.main(['--out', %r]))" % (str(HERE), str(Path(td) / "m.json")))
            r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                               env={k: v for k, v in os.environ.items() if not k.startswith("QA_")})
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            d = json.loads((Path(td) / "m.json").read_text())
            self.assertEqual(sorted(d["uncaught"]), sorted(by_kind("crd_pair")))
            self.assertLess(d["caught"], d["total"])


class DigestBinding(unittest.TestCase):
    def digest_in_copy(self, td, mutate):
        d = Path(td)
        for name in qalib.ORACLE_FILES:
            shutil.copy2(HERE / name, d / name)
        mutate(d)
        r = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); import qalib; print(qalib.oracle_digest())" % str(d)],
                           capture_output=True, text=True, env={k: v for k, v in os.environ.items() if not k.startswith("QA_")})
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_seeds_file_is_part_of_the_oracle_digest(self):
        self.assertIn("seeds.py", qalib.ORACLE_FILES)
        self.assertIn("k8s_oracle.py", qalib.ORACLE_FILES)

    def test_tampered_seeds_file_changes_the_oracle_and_seeds_digest(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            plain = self.digest_in_copy(a, lambda d: None)
            tampered = self.digest_in_copy(b, lambda d: (d / "seeds.py").write_text((d / "seeds.py").read_text() + "\n# x\n"))
            self.assertNotEqual(plain, tampered)
            self.assertEqual(plain, qalib.oracle_digest())
        tampered_text = (HERE / "seeds.py").read_text().replace('"code": 0', '"code": 1', 1)
        self.assertNotEqual(hashlib.sha256(tampered_text.encode()).hexdigest(), seeds.seeds_file_digest())

    def test_dropping_a_seed_is_visible_in_the_digest(self):
        text = (HERE / "seeds.py").read_text()
        dropped = text.replace('    {"id": "crd-version-exit0-pass"', '    # dropped {"id": "crd-version-exit0-pass"', 1)
        self.assertNotEqual(dropped, text)
        self.assertNotEqual(hashlib.sha256(dropped.encode()).hexdigest(), seeds.seeds_file_digest())


def summarize(directory, state, *extra, mode="full"):
    r = subprocess.run([sys.executable, str(HERE / "summarize.py"), "--dir", str(directory), "--state", str(state), "--sha", "a" * 40,
                        "--mode", mode, "--adhoc"] + list(extra), capture_output=True, text=True,
                       env={k: v for k, v in os.environ.items() if not k.startswith("QA_")})
    summary = Path(directory, "summary.json")
    return r, (json.loads(summary.read_text()) if summary.exists() else None)


def suite_cases(directory):
    cases = [dict(suite=s, key="synthetic", wrongpass=False, mismatch=False, error=False, detail={}) for s in ("crd", "k8s", "bp325", "review", "rules")]
    Path(directory, "real.cases.json").write_text(json.dumps(cases))


class SummaryPlumbing(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name, "out")
        self.state = Path(self.td.name, "state")
        self.dir.mkdir()
        self.state.mkdir()

    def test_all_caught_prints_seeded_field_and_summary_object(self):
        write_seeded(self.dir, total=len(seeds.SEEDS))
        suite_cases(self.dir)
        r, s = summarize(self.dir, self.state, "--require-seeded")
        self.assertRegex(r.stdout, r" SEEDED=%d/%d sha=" % (len(seeds.SEEDS), len(seeds.SEEDS)))
        self.assertEqual(s["seeded"]["caught"], len(seeds.SEEDS))
        self.assertEqual(s["seeded"]["total"], len(seeds.SEEDS))

    def test_uncaught_seed_alarms_and_the_real_corpus_is_not_trusted(self):
        write_seeded(self.dir, total=14, uncaught=["crd-whole-exit0-pass"])
        suite_cases(self.dir)  # a green-looking corpus must not rescue the run
        r, s = summarize(self.dir, self.state, "--require-seeded")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(s["wrongpass"], 1)
        self.assertIn("SEEDED=13/14", r.stdout)
        self.assertEqual(s["wrongpass_cases"][0]["suite"], "seeds")
        self.assertEqual(s["state"], "ALARM")
        self.assertTrue((self.state / "alarms").exists())
        self.assertEqual(s["cases"], 1)

    def test_missing_seeded_result_is_an_error_when_required(self):
        suite_cases(self.dir)
        r, s = summarize(self.dir, self.state, "--require-seeded")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("SEEDED=none", r.stdout)
        self.assertNotIn("GREEN", r.stdout.split("sha=")[-1].replace("GREEN-PARTIAL", ""))
        self.assertIsNone(s["seeded"])
        self.assertGreaterEqual(s["errors"], 1)

    def test_forged_or_foreign_seeded_results_are_errors(self):
        suite_cases(self.dir)
        forged = (dict(digest="f" * 64),                    # not the installed seeds.py
                  dict(caught=5, total=3),                  # more caught than run
                  dict(caught=3, total=3, uncaught=["x"]),  # disagreement
                  dict(error="boom"),                       # the seeds run itself failed
                  dict(total=0, caught=0))
        for patch in forged:
            with self.subTest(patch=patch):
                write_seeded(self.dir, total=3)
                d = json.loads((self.dir / "seeded.json").read_text())
                d.update(patch)
                (self.dir / "seeded.json").write_text(json.dumps(d))
                r, s = summarize(self.dir, self.state, "--require-seeded")
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertNotEqual(s["state"], "GREEN")
        (self.dir / "seeded.json").write_text("not json")
        r, s = summarize(self.dir, self.state, "--require-seeded")
        self.assertEqual(r.returncode, 3)

    def test_failed_seed_run_does_not_reset_baselines_in_status(self):
        (self.state / "status.json").write_text(json.dumps({"design_unknown_whole_crd_baseline": 30, "unsupported_community": 4,
                                                           "oracle_digest": qalib.oracle_digest(), "mode": "full"}))
        write_seeded(self.dir, total=14, uncaught=["crd-whole-exit0-pass"])
        suite_cases(self.dir)
        r = subprocess.run([sys.executable, str(HERE / "summarize.py"), "--dir", str(self.dir), "--state", str(self.state),
                            "--sha", "a" * 40, "--mode", "full", "--require-seeded"],
                           capture_output=True, text=True, env={k: v for k, v in os.environ.items() if not k.startswith("QA_")})
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        status = json.loads((self.state / "status.json").read_text())
        self.assertEqual(status["design_unknown_whole_crd_baseline"], 30)
        self.assertEqual(status["unsupported_community"], 4)
        self.assertEqual(status["seeded"], "13/14")
        self.assertEqual(status["state"], "ALARM")

    def test_mode_none_is_not_an_oracle_run(self):
        (self.dir / "none.cases.json").write_text("[]")
        r, s = summarize(self.dir, self.state, mode="none")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("SEEDED", r.stdout)
        self.assertIsNone(s["seeded"])

    def test_without_the_flag_a_result_is_still_validated_when_present(self):
        write_seeded(self.dir, total=3, digest="e" * 64)
        suite_cases(self.dir)
        r, s = summarize(self.dir, self.state)
        self.assertEqual(r.returncode, 3, r.stdout)


def fake_runner(root, seeded_expr):
    runner = root / "runner"
    runner.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
sys.path.insert(0, %r)
import qa_scope, qalib
p = Path(os.environ['QA_STATE']) / 'results' / ('test-' + os.environ['QA_SHA'][:8])
p.mkdir(parents=True)
s = dict(sha=os.environ['QA_SHA'], base=os.environ['QA_BASE'], run_id=os.environ['QA_RUN_ID'],
         wrongpass=0, mismatch=0, errors=0, cases=5, skipped=[], mode='full', wrongpass_cases=[], error_cases=[])
%s
json.dump([dict(suite=x, key='synthetic', wrongpass=False, mismatch=False, error=False, detail={}) for x in ('crd','k8s','bp325','review','rules')], open(p / 'control.cases.json', 'w'))
scope = qa_scope.declare(os.environ['QA_SHA'], os.environ['QA_BASE'], os.environ['QA_RUN_ID'], ['k8s-range|test'], [], [])
scope.update(executed=['k8s-range|test'], state='COMPLETE')
crd = qa_scope.declare(os.environ['QA_SHA'], os.environ['QA_BASE'], os.environ['QA_RUN_ID'], ['crd-project|test'], [], [], qa_scope.CRD_PROFILE)
crd.update(executed=['crd-project|test'], state='COMPLETE')
s['scopes'] = dict(k8s=scope, crd=crd)
json.dump([], open(Path(os.environ['QA_STATE']) / 'known-mismatch.json', 'w'))
json.dump(s, open(p / 'summary.json', 'w'))
raise SystemExit(0)
''' % (str(HERE), seeded_expr))
    runner.chmod(0o700)
    return runner


# the line shape private readers match, with SEEDED as an optional trailing field
OLD_READER = re.compile(r"GATE ([0-9a-f]{8}) WRONGPASS=(\d+) MISMATCH=(\d+) ERR=(\d+) cases=(\d+) base=([0-9a-f]{8})")
NEW_READER = re.compile(OLD_READER.pattern + r" SEEDED=(\d+)/(\d+)$")


class GateVerdictLine(unittest.TestCase):
    def gate(self, seeded_expr, env_extra=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runner = fake_runner(root, seeded_expr)
            remote, head, base = gate_source(root)
            env = dict(os.environ, QA_STATE=str(root / "state"), QA_GATE_RUN=str(runner), QA_GATE_TRIES="1", QA_REPO_URL=remote)
            env.update(env_extra or {})
            r = subprocess.run([str(HERE / "batch_gate.sh"), "--trust-operator", head, base], env=env, capture_output=True, text=True, timeout=30)
            return r, json.loads((root / "state/gate" / (head + ".json")).read_text()) if (root / "state/gate" / (head + ".json")).exists() else None

    OK = "s['seeded'] = dict(caught=3, total=3, uncaught=[], error=None, digest=qalib.seeds_digest())"

    def test_all_caught_line_has_trailing_seeded_and_old_readers_still_match(self):
        r, rec = self.gate(self.OK)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        line = r.stdout.strip().splitlines()[-1]
        self.assertTrue(line.endswith(" SEEDED=3/3"), line)
        self.assertIsNotNone(OLD_READER.match(line))
        m = NEW_READER.fullmatch(line)
        self.assertIsNotNone(m, line)
        self.assertEqual(m.group(2, 3, 4), ("0", "0", "0"))
        self.assertEqual(rec["seeded"]["caught"], 3)
        self.assertEqual(rec["state"], "GREEN")

    def test_uncaught_seed_is_wrongpass_class_exit_2(self):
        expr = "s['seeded'] = dict(caught=2, total=3, uncaught=['crd-whole-exit0-pass'], error=None, digest=qalib.seeds_digest())"
        r, rec = self.gate(expr)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        line = r.stdout.strip().splitlines()[-1]
        self.assertIn("SEEDED=2/3", line)
        self.assertNotIn("WRONGPASS=0", line)
        self.assertEqual(rec["state"], "WRONGPASS")

    def test_uncaught_seed_cannot_be_hidden_by_a_zero_wrongpass_summary(self):
        # the summary claims wrongpass=0 but its seeded block says a seed slipped through
        expr = "s['seeded'] = dict(caught=0, total=3, uncaught=['a', 'b', 'c'], error=None, digest=qalib.seeds_digest())"
        r, _ = self.gate(expr)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("WRONGPASS=3", r.stdout)

    def test_missing_or_malformed_seeded_block_is_never_green(self):
        for expr in ("pass", "s['seeded'] = None", "s['seeded'] = dict(caught='3', total=3, uncaught=[], digest='x')",
                     "s['seeded'] = dict(caught=3, total=3, uncaught=[], error=None, digest='0'*64)",   # foreign seeds file
                     "s['seeded'] = dict(caught=4, total=3, uncaught=[], error=None, digest=qalib.seeds_digest())",
                     "s['seeded'] = dict(caught=3, total=3, uncaught=[], error='crash', digest=qalib.seeds_digest())"):
            with self.subTest(expr=expr):
                r, _ = self.gate(expr)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertNotIn("ERR=0", r.stdout)

    def test_missing_seeded_block_line_is_marked_none(self):
        r, _ = self.gate("pass")
        self.assertTrue(r.stdout.strip().splitlines()[-1].endswith(" SEEDED=none"), r.stdout)

    def test_pinned_seeds_digest_in_the_gate_environment_must_match(self):
        r, _ = self.gate(self.OK, {"QA_SEEDS_DIGEST": "1" * 64})
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        r, _ = self.gate(self.OK, {"QA_SEEDS_DIGEST": seeds.seeds_file_digest()})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class RunShSeedFirst(unittest.TestCase):
    """The real run.sh: seeds run before the build and the suites; a failed seed run skips them and never ends green."""

    def setup_world(self, root, seeds_body):
        source, installed = root / "source", root / "installed"
        source.mkdir()
        installed.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(source)] + list(args), check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q")
        git("config", "user.name", "Spas Atanasov")
        git("config", "user.email", "11156623+airstand@users.noreply.github.com")
        files = {"cli/internal/extract/crdversions/target-sample.json": '{"target":{"repo":"example/sample"}}',
                 "cli/internal/cncfcheck/data/rules.json": '{"entries":[]}',
                 "cli/internal/maintainer/coveragereport/testdata/lines-synthetic.json": '{}'}
        for name, content in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        git("add", ".")
        git("commit", "-qm", "Synthetic base")
        base = git("rev-parse", "HEAD")
        (source / "cli/internal/cncfcheck/data/rules.json").write_text('{"entries":[{"project":"sample","rule":{"id":"sample.control"}}]}')
        git("add", ".")
        git("commit", "-qm", "Synthetic data change")
        head = git("rev-parse", "HEAD")
        for name in ("run.sh", "select_projects.py", "crdgvk.go") + tuple(qalib.ORACLE_FILES):
            shutil.copy2(HERE / name, installed / name)
        (installed / "seeds.py").write_text(seeds_body)
        marker = root / "devbox-called"
        devbox = root / "devbox"
        devbox.write_text('#!/bin/sh\ntouch %s\nexit 1\n' % marker)
        devbox.chmod(0o700)
        env = dict(os.environ, QA_SHA=head, QA_BASE=base, QA_RUN_ID="seeded-first", QA_REPO_URL=str(source),
                   QA_STATE=str(root / "state"), QA_WORK_ROOT=str(root / "work"), QA_DEVBOX=str(devbox),
                   QA_RUNBOX="/unused-sandbox-prefix", QA_NO_KIND="1", QA_MAXLOAD="999")
        return installed, env, marker

    def run_it(self, seeds_body):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            installed, env, marker = self.setup_world(root, seeds_body)
            r = subprocess.run([str(installed / "run.sh")], env=env, capture_output=True, text=True, timeout=60)
            summaries = list((root / "state/results").glob("*/summary.json"))
            return r, marker.exists(), (json.loads(summaries[0].read_text()) if summaries else None)

    UNCAUGHT = STUB_SEEDS.replace('"total": 1, "caught": 1, "uncaught": []', '"total": 1, "caught": 0, "uncaught": ["stub"]').replace(
        'print("SEEDED=1/1")', 'print("SEEDED=0/1"); sys.exit(2)')

    def test_uncaught_seed_stops_before_the_build_and_alarms(self):
        r, built, s = self.run_it(self.UNCAUGHT)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(built, "build/suites must not run after an uncaught seed")
        self.assertIn("SEEDED=0/1", r.stdout)
        self.assertEqual(s["wrongpass"], 1)
        self.assertEqual(s["seeded"]["uncaught"], ["stub"])

    def test_crashed_seed_run_is_inconclusive_never_green(self):
        r, built, s = self.run_it("import sys\nsys.exit(1)\n")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertFalse(built)
        self.assertIn("SEEDED=none", r.stdout)

    def test_seed_run_that_claims_all_caught_but_exits_nonzero_is_not_trusted(self):
        r, built, _ = self.run_it(STUB_SEEDS + "sys.exit(7)\n")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(built)

    def test_all_caught_runs_on_to_the_build(self):
        r, built, _ = self.run_it(STUB_SEEDS)
        self.assertTrue(built, "after all seeds are caught the real run proceeds (to the stubbed build)")


if __name__ == "__main__":
    unittest.main()
