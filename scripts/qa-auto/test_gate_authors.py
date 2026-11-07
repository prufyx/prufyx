"""QA_GATE_AUTHORS semantics for batch_gate.sh: --poll --dry and the explicit <sha> form (stubbed gh, no network)."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_batch_envelope_scope import gate_source

HERE = Path(__file__).resolve().parent
REPO = "prufyx/prufyx"
SHA = "a" * 40
FAKE_GH = """#!/usr/bin/env bash
case "$1 $2" in
  "pr list") cat "$FAKE_DIR/prs.json" ;;
  "api repos/prufyx/prufyx/commits/"*) cat "$FAKE_DIR/pulls.json" ;;
  *) exit 1 ;;
esac
"""
RUNNER = """#!/usr/bin/env bash
touch "$FAKE_DIR/ran"
exit 3
"""


class AuthorAllowlistTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        self.runner = self.root / "run.sh"
        self.runner.write_text(RUNNER)
        self.runner.chmod(0o755)
        self.fake = self.root / "fake"
        self.fake.mkdir()
        self.remote, self.head, self.base = gate_source(self.root)

    def env(self, authors):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", FAKE_DIR=str(self.fake),
                   QA_STATE=str(self.root / "state"), QA_REPO_URL=self.remote, QA_GATE_RUN=str(self.runner),
                   QA_GATE_TRIES="1")
        env.pop("QA_GATE_AUTHORS", None)
        if authors is not None:
            env["QA_GATE_AUTHORS"] = authors
        return env

    def poll(self, authors, login, cross=False, owner="prufyx"):
        prs = [{"number": 7, "headRefOid": self.head, "headRefName": "bot/data", "labels": [],
                "isCrossRepository": cross, "headRepositoryOwner": {"login": owner}, "author": {"login": login}}]
        (self.fake / "prs.json").write_text(json.dumps(prs))
        r = subprocess.run([str(HERE / "batch_gate.sh"), "--poll", "--dry"], env=self.env(authors),
                           capture_output=True, text=True, timeout=30)
        # "recorded": an earlier explicit run in the same test already wrote this head's record; still accepted by the filter
        return ("would be gated" in r.stdout or "recorded (exit" in r.stdout), r

    def explicit(self, authors, login, repo=REPO, state="open", sha=None):
        sha = sha or self.head
        pulls = [{"state": state, "head": {"sha": sha, "repo": {"full_name": repo}}, "user": {"login": login}}]
        (self.fake / "pulls.json").write_text(json.dumps(pulls))
        (self.fake / "ran").unlink(missing_ok=True)
        r = subprocess.run([str(HERE / "batch_gate.sh"), self.head, self.base], env=self.env(authors),
                           capture_output=True, text=True, timeout=30)
        refused = r.returncode == 1 and "refusing" in r.stderr
        return (not refused), r

    def both(self, authors, login, **kw):
        """(poll accepted, explicit accepted) for a same-repo PR unless kw says otherwise."""
        cross = kw.get("cross", False)
        p, _ = self.poll(authors, login, cross=cross, owner="someone" if cross else "prufyx")
        e, _ = self.explicit(authors, login, repo="someone/prufyx" if cross else REPO)
        return p, e

    AL = "airstand,prufyx-bot"

    def test_allowed_authors_accepted(self):
        for login in ("prufyx-bot", "airstand"):
            self.assertEqual(self.both(self.AL, login), (True, True), login)

    def test_explicit_accept_reaches_the_gate(self):
        ok, _ = self.explicit(self.AL, "prufyx-bot")
        self.assertTrue(ok)
        self.assertTrue((self.fake / "ran").exists())

    def test_other_logins_refused(self):
        for login in ("mallory", "dependabot[bot]", "prufyx-bot2", "prufyx-botx", "prufyx", "bot", "airstand2",
                      "xairstand", "prufyx-bot[bot]", "app/prufyx-bot", ""):
            self.assertEqual(self.both(self.AL, login), (False, False), login)
        self.assertFalse((self.fake / "ran").exists())

    def test_cross_repo_refused_even_for_allowed_author(self):
        for login in ("prufyx-bot", "airstand"):
            self.assertEqual(self.both(self.AL, login, cross=True), (False, False), login)
        self.assertFalse((self.fake / "ran").exists())

    def test_explicit_requires_open_pr_and_exact_head(self):
        self.assertFalse(self.explicit(self.AL, "prufyx-bot", state="closed")[0])
        self.assertFalse(self.explicit(self.AL, "prufyx-bot", sha="b" * 40)[0])

    def test_empty_or_unset_list_refuses_everything(self):
        for authors in (None, "", " ", ",", " , ,"):
            for login in ("prufyx-bot", "airstand"):
                p, pr = self.poll(authors, login)
                e, _ = self.explicit(authors, login)
                self.assertEqual((p, e), (False, False), repr(authors))
                self.assertNotEqual(pr.returncode, 0)
                self.assertIn("QA_GATE_AUTHORS is empty", pr.stderr)

    def test_no_wildcard_semantics(self):
        for authors in ("*", "prufyx-*", "airstand,*", "prufyx-bot*", "?", "prufyx-bo?", ".*", "prufyx-bot.*", "[a-z]*"):
            for login in ("prufyx-bot", "prufyx-botx", "dependabot[bot]", "mallory", "airstand2", "*", "prufyx-*"):
                if login in authors.split(","):
                    continue  # literal login equal to a list entry is an exact match, not a glob
                self.assertEqual(self.both(authors, login), (False, False), f"{authors!r} vs {login!r}")

    def test_logins_compare_case_insensitively(self):
        # documented: both paths lowercase the list and the PR login (GitHub logins are case-insensitive)
        for authors, login in (("Airstand,PRUFYX-BOT", "prufyx-bot"), (self.AL, "Prufyx-Bot"), (self.AL, "AIRSTAND")):
            self.assertEqual(self.both(authors, login), (True, True), f"{authors!r} {login!r}")
        self.assertEqual(self.both("PRUFYX-BOT", "prufyx-bot2"), (False, False))

    def test_list_parsing(self):
        for authors in (" airstand , prufyx-bot ", "airstand,prufyx-bot,", ",airstand,,prufyx-bot,,",
                        "airstand,prufyx-bot,airstand,prufyx-bot", "prufyx-bot,prufyx-bot"):
            self.assertEqual(self.both(authors, "prufyx-bot"), (True, True), repr(authors))
        for authors in (" airstand , prufyx-bot ", "airstand,prufyx-bot,"):
            self.assertEqual(self.both(authors, "mallory"), (False, False), repr(authors))
        # a space inside a login does not split it into two entries
        self.assertEqual(self.both("prufyx bot", "prufyx"), (False, False))
        self.assertEqual(self.both("prufyx bot", "bot"), (False, False))


if __name__ == "__main__":
    unittest.main()
