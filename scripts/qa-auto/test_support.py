"""Test helper: complete the other mandatory suites and the declared scopes so a full run is clean (no error case)."""
import json
import os

import qa_scope


def complete_full_run(run_dir, sha, run_id="", base=""):
    others = [dict(suite=s, key="synthetic", wrongpass=False, mismatch=False, error=False, detail={})
              for s in ("k8s", "bp325", "review", "rules")]
    with open(os.path.join(run_dir, "others.cases.json"), "w") as f:
        json.dump(others, f)
    for suite, profile in (("k8s", qa_scope.PROFILE), ("crd", qa_scope.CRD_PROFILE)):
        scope = qa_scope.declare(sha, base, run_id, [suite + "-project|x"], [], [], profile)
        scope.update(executed=[suite + "-project|x"], state="COMPLETE")
        with open(os.path.join(run_dir, suite + ".scope.json"), "w") as f:
            json.dump(scope, f)
