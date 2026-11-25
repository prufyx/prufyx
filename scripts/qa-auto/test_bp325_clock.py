import json, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
# bp325.py runs its cases at import; load only the clock helper from its source
src = Path(__file__).resolve().parent.joinpath("bp325.py").read_text()
ns = {"json": json, "os": os}
start, end = src.index("RULE_ID="), src.index("def _rules_path")
exec(src[start:end], ns)
derive_now, BASE = ns["derive_now"], ns["BASE_NOW"]
RID = ns["RULE_ID"]


def write(evidence, rid=RID, extra=()):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    entries = [{"rule": {"id": rid, "evidence": evidence}}] + [{"rule": {"id": x, "evidence": evidence}} for x in extra]
    with f:
        json.dump({"entries": entries}, f)
    return f.name


class Clock(unittest.TestCase):
    def test_old_rule_keeps_base_clock(self):
        p = write({"reviewedAt": "2026-09-10T16:59:15Z", "validUntil": "2026-12-09T16:59:15Z"})
        self.assertEqual(derive_now(p), BASE)

    def test_renewed_rule_moves_clock_to_reviewed_at(self):
        p = write({"reviewedAt": "2026-11-18T09:49:59Z", "validUntil": "2027-02-09T09:49:59Z"})
        self.assertEqual(derive_now(p), "2026-11-18T09:49:59Z")

    def test_clock_never_reaches_valid_until(self):
        p = write({"reviewedAt": "2026-11-18T09:49:59Z", "validUntil": "2026-11-18T09:49:59Z"})
        self.assertEqual(derive_now(p), BASE)

    def test_unreadable_missing_duplicate_or_malformed_keep_base(self):
        good = {"reviewedAt": "2026-11-18T09:49:59Z", "validUntil": "2027-02-09T09:49:59Z"}
        self.assertEqual(derive_now("/nonexistent/rules.json"), BASE)
        self.assertEqual(derive_now(write(good, rid="other")), BASE)
        self.assertEqual(derive_now(write(good, extra=(RID,))), BASE)
        self.assertEqual(derive_now(write({"reviewedAt": "yesterday", "validUntil": "2027-02-09T09:49:59Z"})), BASE)
        self.assertEqual(derive_now(write({})), BASE)


if __name__ == "__main__":
    unittest.main()
