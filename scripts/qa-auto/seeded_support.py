"""Test support for the seeded wrong-PASS result: a valid seeded.json bound to the installed seeds.py, and a stub seeds.py for tests
that install stub oracles (admission/box tests exercise run.sh plumbing, not the classifier; test_seeds.py covers the real seeds)."""
import hashlib, json
from pathlib import Path

HERE = Path(__file__).resolve().parent

STUB_SEEDS = '''import hashlib, json, sys
from pathlib import Path
out = sys.argv[sys.argv.index("--out") + 1]
digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
json.dump({"digest": digest, "total": 1, "caught": 1, "uncaught": [], "ids": ["stub"], "error": None}, open(out, "w"))
print("SEEDED=1/1")
'''


def write_seeded(directory, caught=None, total=None, uncaught=(), error=None, digest=None):
    """seeded.json as seeds.py writes it, bound to the real installed seeds.py unless digest is given."""
    real = hashlib.sha256((HERE / "seeds.py").read_bytes()).hexdigest()
    total = 14 if total is None else total
    unc = list(uncaught)
    caught = (total - len(unc)) if caught is None else caught
    Path(directory, "seeded.json").write_text(json.dumps({
        "digest": digest or real, "total": total, "caught": caught, "uncaught": unc,
        "ids": ["s%d" % i for i in range(total)], "error": error}))


def install_stub_seeds(installed):
    Path(installed, "seeds.py").write_text(STUB_SEEDS)
