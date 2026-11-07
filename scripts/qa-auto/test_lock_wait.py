"""run.sh lock wait: QA_LOCK_WAIT is bounded, default non-blocking, ignored in poll/gate mode."""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

RUN = Path(__file__).resolve().parent / "run.sh"
BUSY = "another run holds the lock"


class LockWaitTests(unittest.TestCase):
    def run_sh(self, hold, **env):
        """Hold the lock for `hold` seconds (0 = not held); run.sh with QA_MAXLOAD=0 stops right after the lock."""
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "state"
            (state / "results").mkdir(parents=True)
            (state / "cache").mkdir()
            holder = None
            if hold:
                holder = subprocess.Popen(["flock", str(state / "lock"), "sleep", str(hold)])
                for _ in range(100):
                    if (state / "lock").exists():
                        break
                    time.sleep(0.05)
                time.sleep(0.2)
            e = {k: v for k, v in os.environ.items() if not k.startswith("QA_")}
            e.update(QA_STATE=str(state), QA_WORK_ROOT=td, QA_MAXLOAD="0", **env)
            t = time.time()
            p = subprocess.run(["bash", str(RUN)], env=e, capture_output=True, text=True)
            dt = time.time() - t
            if holder:
                holder.kill()
                holder.wait()
            return p.returncode, p.stdout + p.stderr, dt

    def test_default_immediate_busy(self):
        rc, out, dt = self.run_sh(4)
        self.assertEqual((rc, BUSY in out), (75, True))
        self.assertLess(dt, 1.5)

    def test_wait_proceeds_when_released(self):
        rc, out, dt = self.run_sh(1, QA_LOCK_WAIT="3")
        self.assertEqual(rc, 75)
        self.assertNotIn(BUSY, out)
        self.assertIn("load", out)
        self.assertLess(dt, 3)

    def test_wait_times_out_when_held(self):
        rc, out, dt = self.run_sh(5, QA_LOCK_WAIT="2")
        self.assertEqual((rc, BUSY in out), (75, True))
        self.assertGreaterEqual(dt, 1.8)
        self.assertLess(dt, 4.5)

    def test_invalid_values_mean_zero(self):
        for v in ("abc", "-1", "1.5", "7201", "99999", "", "2 "):
            rc, out, dt = self.run_sh(3, QA_LOCK_WAIT=v)
            self.assertEqual((rc, BUSY in out), (75, True), v)
            self.assertLess(dt, 1.5, v)

    def test_poll_and_gate_ignore_wait(self):
        for k, v in (("QA_POLL", "1"), ("QA_BASE", "deadbeef")):
            rc, out, dt = self.run_sh(3, QA_LOCK_WAIT="2", **{k: v})
            self.assertEqual((rc, BUSY in out), (75, True), k)
            self.assertLess(dt, 1.5, k)


if __name__ == "__main__":
    unittest.main()
