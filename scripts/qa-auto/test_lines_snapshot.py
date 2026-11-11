"""The coverage-report input is the newest DATED full snapshot (lines-YYYY-MM-DD.json), never lines-additions.json:
the additions file sorts after every date name, the report rejects it as an input, and in gate mode that failure
(exit 3) blocks the QA gate of every data PR."""
import os
import re
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def selection_line():
    for line in open(os.path.join(HERE, "run.sh"), encoding="utf-8").read().splitlines():
        if line.startswith("L=$(ls ") and "coveragereport/testdata/lines-" in line:
            return line
    raise AssertionError("no lines selection in run.sh")


def pick(names):
    with tempfile.TemporaryDirectory() as run:
        d = os.path.join(run, "src/cli/internal/maintainer/coveragereport/testdata")
        os.makedirs(d)
        for n in names:
            open(os.path.join(d, n), "w").close()
        out = subprocess.run(["bash", "-c", selection_line() + '\nprintf "%s" "${L##*/}"'], env={"RUN": run, "PATH": os.environ["PATH"]},
                             capture_output=True, text=True, check=True)
        return out.stdout


class LinesSnapshot(unittest.TestCase):
    def test_additions_file_is_never_chosen(self):
        self.assertEqual(pick(["lines-2026-11-07.json", "lines-2026-11-11.json", "lines-additions.json"]), "lines-2026-11-11.json")

    def test_newest_date_wins(self):
        self.assertEqual(pick(["lines-2026-10-08.json", "lines-2026-11-07.json", "lines-2026-10-30.json"]), "lines-2026-11-07.json")

    def test_no_dated_snapshot_is_empty_not_additions(self):
        self.assertEqual(pick(["lines-additions.json", "baseline-crd-lines.json"]), "")

    def test_pattern_is_dated_only(self):
        self.assertIsNotNone(re.search(r"lines-\[0-9\]\[0-9\]\[0-9\]\[0-9\]-\[0-9\]\[0-9\]-\[0-9\]\[0-9\]\.json", selection_line()))


if __name__ == "__main__":
    unittest.main()
