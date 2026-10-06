# SPDX-License-Identifier: AGPL-3.0-only
"""The corpus validator must not read outside the corpus tree and the
conformance runner must point at this corpus."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import validate  # noqa: E402


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name).resolve()
        self.corpus = base / "corpus"
        (self.corpus / "scenarios").mkdir(parents=True)
        (self.corpus / "scenarios" / "a.json").write_text("{}\n")
        self.secret = base / "secret.txt"
        self.secret.write_text("TOPSECRET\n")

    def test_tree_digest_refuses_a_symlink(self):
        os.symlink(self.secret, self.corpus / "scenarios" / "link.json")
        with self.assertRaises(validate.ValidationError):
            validate.tree_digest(self.corpus)

    def test_tree_digest_refuses_a_symlinked_directory(self):
        os.symlink(self.secret.parent, self.corpus / "linkdir")
        with self.assertRaises(validate.ValidationError):
            validate.tree_digest(self.corpus)

    def test_corpus_files_refuses_a_symlink(self):
        os.symlink(self.secret, self.corpus / "scenarios" / "link.json")
        with self.assertRaises(validate.ValidationError):
            validate.corpus_files(self.corpus)

    def test_safe_child_accepts_a_plain_relative_path(self):
        self.assertEqual(validate.safe_child(self.corpus, "scenarios/a.json"), self.corpus / "scenarios" / "a.json")

    def test_safe_child_refuses_escapes(self):
        os.symlink(self.secret, self.corpus / "scenarios" / "link.json")
        for bad in ("../secret.txt", "scenarios/../../secret.txt", str(self.secret), "scenarios/link.json", "", "a\x00b", "scenarios\\..\\x", 7):
            with self.subTest(bad=bad), self.assertRaises(validate.ValidationError):
                validate.safe_child(self.corpus, bad)

    def test_conformance_runner_targets_this_corpus(self):
        text = (ROOT / "tests" / "run-conformance.sh").read_text()
        self.assertNotIn("/v3", text)
        self.assertIn('dirname -- "$0")/.."', text)


if __name__ == "__main__":
    unittest.main()
