"""Actual run.sh admission boundary, with trusted build/oracle companions stubbed."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from seeded_support import install_stub_seeds


HERE = Path(__file__).resolve().parent


class RunAdmissionTests(unittest.TestCase):
    def test_executable_diff_rejected_and_data_diff_runs_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, installed = root / "source", root / "installed"
            source.mkdir()
            installed.mkdir()
            def git(*args):
                return subprocess.run(["git", "-C", str(source)] + list(args), check=True, capture_output=True, text=True).stdout.strip()
            git("init", "-q")
            git("config", "user.name", "Spas Atanasov")
            git("config", "user.email", "11156623+airstand@users.noreply.github.com")
            files = {
                "cli/internal/extract/crdversions/target-sample.json": '{"target":{"repo":"example/sample"}}',
                "cli/internal/extract/crdversions/target-required.json": '{"target":{"repo":"example/required"}}',
                "cli/internal/cncfcheck/data/rules.json": '{"entries":[]}',
                "cli/internal/maintainer/coveragereport/testdata/lines-synthetic.json": '{}',
            }
            for name, content in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            git("add", ".")
            git("commit", "-qm", "Synthetic base")
            base = git("rev-parse", "HEAD")
            rules = source / "cli/internal/cncfcheck/data/rules.json"
            rules.write_text('{"entries":[{"project":"sample","rule":{"id":"sample.control"}}]}')
            git("add", ".")
            git("commit", "-qm", "Synthetic data control")
            data_head = git("rev-parse", "HEAD")
            git("checkout", "--detach", base)
            for project in ("sample", "required"):
                target = source / ("cli/internal/extract/crdversions/target-" + project + ".json")
                target.write_text(json.dumps({"target": {"repo": "example/" + project}, "note": "changed pair"}))
            git("add", ".")
            git("commit", "-qm", "Synthetic project scope control")
            scope_head = git("rev-parse", "HEAD")
            git("checkout", "--detach", base)
            executable = source / "cli/cmd/control.go"
            executable.parent.mkdir(parents=True)
            executable.write_text("package control\n")
            git("add", ".")
            git("commit", "-qm", "Synthetic code control")
            code_head = git("rev-parse", "HEAD")
            for name in ("run.sh", "select_projects.py", "summarize.py", "qalib.py", "qa_scope.py", "qa_batch_scope.py", "crdgvk.go"):
                shutil.copy2(HERE / name, installed / name)
            # Companion stubs prove admission, not compatibility or sandbox fidelity.
            companion = '''import json, os, sys
from pathlib import Path
import qa_scope
name = Path(sys.argv[0]).stem
suite = {'crd_oracle':'crd','k8s_oracle':'k8s','bp325':'bp325','review_cases':'review','rules_oracle':'rules'}[name]
flag = '--cases' if name == 'bp325' else '--out'
output = Path(sys.argv[sys.argv.index(flag)+1])
projects = ['sample', 'required'] if '--all' in sys.argv else (sys.argv[sys.argv.index('--projects')+1].split(',') if '--projects' in sys.argv else [])
Path(os.environ['ADMISSION_COMPANIONS'], suite+'.json').write_text(json.dumps(dict(projects=projects, qa_projects=os.environ.get('QA_PROJECTS', ''))))
failed = suite == 'crd' and 'required' in projects and os.environ.get('ADMISSION_BAD_PROJECT') == 'required'
output.write_text(json.dumps([dict(suite=suite, key='synthetic', wrongpass=failed, mismatch=False, error=False, detail={})]))
if suite in ('crd','k8s'):
    targets = ['crd-project|'+p for p in projects] if suite == 'crd' else ['k8s-range|synthetic']
    profile = qa_scope.CRD_PROFILE if suite == 'crd' else qa_scope.PROFILE
    scope = qa_scope.declare(os.environ['QA_SHA'], os.environ['QA_BASE'], os.environ['QA_RUN_ID'], targets, targets if suite == 'crd' else [], [], profile)
    scope.update(executed=targets, state='COMPLETE')
    output.with_name(suite+'.scope.json').write_text(json.dumps(scope))
'''
            for name in ("crd_oracle.py", "k8s_oracle.py", "bp325.py", "review_cases.py", "rules_oracle.py"):
                (installed / name).write_text(companion)
            install_stub_seeds(installed)
            devbox = root / "devbox"
            devbox.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ['ADMISSION_MARKER']).write_text('trusted build companion reached')
if 'coverage report' in ' '.join(sys.argv):
    Path(sys.argv[-1]).write_text(json.dumps({'projects':[]}))
''')
            devbox.chmod(0o700)
            for name, head, expected in (("data", data_head, 0), ("code", code_head, 3),
                                         ("scope-clean", scope_head, 0), ("scope-failure", scope_head, 2)):
                with self.subTest(diff=name):
                    marker = root / (name + "-build")
                    companions = root / (name + "-companions")
                    companions.mkdir()
                    env = dict(os.environ, QA_SHA=head, QA_BASE=base, QA_RUN_ID="synthetic-" + name,
                               QA_REPO_URL=str(source), QA_STATE=str(root / (name + "-state")),
                               QA_WORK_ROOT=str(root / (name + "-work")), QA_DEVBOX=str(devbox),
                               QA_RUNBOX="/unused-sandbox-prefix", QA_NO_KIND="1", QA_MAXLOAD="999",
                               QA_MODE="auto", ADMISSION_MARKER=str(marker), ADMISSION_COMPANIONS=str(companions),
                               QA_PROJECTS="sample" if name.startswith("scope-") or name == "data" else "",
                               ADMISSION_BAD_PROJECT="required" if name == "scope-failure" else "")
                    result = subprocess.run([str(installed / "run.sh")], env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    self.assertEqual(marker.exists(), name != "code")
                    if name == "code":
                        self.assertIn("code change in bot batch", result.stderr)
                    elif name != "scope-failure":
                        self.assertIn("WRONGPASS=0", result.stdout)
                    else:
                        self.assertIn("WRONGPASS=1", result.stdout)
                    if name != "code":
                        crd = json.loads((companions / "crd.json").read_text())
                        self.assertEqual(set(crd["projects"]), {"sample", "required"})
                        self.assertEqual(crd["qa_projects"], "")
                        if name == "data":
                            self.assertEqual(json.loads((companions / "rules.json").read_text())["qa_projects"], "")
                        results = list((root / (name + "-state/results")).glob("*/summary.json"))
                        summary = json.loads(results[0].read_text())
                        self.assertEqual(set(summary["scopes"]["crd"]["required"]),
                                         {"crd-project|sample", "crd-project|required"})


if __name__ == "__main__":
    unittest.main()
