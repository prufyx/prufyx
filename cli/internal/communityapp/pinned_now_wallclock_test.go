// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
	"time"
)

// setWallClock fixes the real time the pinned --now guard compares with.
func setWallClock(t *testing.T, at time.Time) {
	t.Helper()
	old := autoClock
	autoClock = func() time.Time { return at }
	t.Cleanup(func() { autoClock = old })
}

func pinnedNowArgs(path, now string) []string {
	return []string{
		"check", "cncf", "--project", "cilium", "--cilium-policy", path,
		"--from", "1.18.13", "--to", "1.19.7", "--complete-cnp-ccnp-set", "true",
		"--now", now, "--format", "json",
	}
}

// A pinned --now inside the validity window keeps passing after the shipped
// knowledge has really expired: the guard must turn that PASS into UNKNOWN.
func TestPinnedNowCannotHideWallClockExpiry(t *testing.T) {
	path := writeCNCFFile(t, "cilium-policy.json", ciliumPolicyNativeResource(t, []any{}), 0o600)
	const pinned = "2026-10-18T00:00:00Z"
	for _, test := range []struct {
		name     string
		wall     time.Time
		format   string
		wantExit int
		warn     bool
	}{
		{"wall clock inside the window", time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), "json", ExitOK, false},
		{"wall clock after the rules expired, json", time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), "json", ExitUnknown, true},
		{"wall clock after the rules expired, human", time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), "human", ExitUnknown, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			setWallClock(t, test.wall)
			args := pinnedNowArgs(path, pinned)
			args[len(args)-1] = test.format
			code, stdout, stderr := runCNCFCLIRaw(t, args...)
			if code != test.wantExit {
				t.Fatalf("code=%d want %d stdout=%q stderr=%q", code, test.wantExit, stdout, stderr)
			}
			if test.wantExit == ExitUnknown && strings.Contains(stdout, `"status":"PASS"`) {
				t.Fatalf("PASS report kept: %q", stdout)
			}
			warned := strings.Contains(stderr, "warning: --now "+pinned+" is earlier than today (") && strings.Contains(stderr, "knowledge rules have expired since")
			if warned != test.warn {
				t.Fatalf("warning=%v want %v stderr=%q", warned, test.warn, stderr)
			}
			if !test.warn && strings.Contains(stderr, "warning") {
				t.Fatalf("unexpected noise: %q", stderr)
			}
		})
	}
}

// A replay keeps its recorded time: a wall clock after expiry changes nothing.
func TestPinnedNowGuardSkipsReplayAndDatabase(t *testing.T) {
	setWallClock(t, time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
	for _, extra := range []string{"replay-report", "knowledge-db"} {
		ran := 0
		code := runtime{}.pinnedNowGuard([]string{"--now", "2026-10-18T00:00:00Z", "--" + extra, "x"}, nil, func(runtime, []string) int { ran++; return ExitOK })
		if code != ExitOK || ran != 1 {
			t.Fatalf("%s: code=%d ran=%d", extra, code, ran)
		}
	}
}

func TestReplaceNow(t *testing.T) {
	for _, test := range []struct{ in, want []string }{
		{[]string{"--now", "a", "--x"}, []string{"--now", "W", "--x"}},
		{[]string{"-now=a"}, []string{"-now=W"}},
	} {
		got, ok := replaceNow(test.in, "W")
		if !ok || strings.Join(got, " ") != strings.Join(test.want, " ") {
			t.Errorf("%v -> %v %v", test.in, got, ok)
		}
	}
	if _, ok := replaceNow([]string{"--x"}, "W"); ok {
		t.Error("no --now should not be replaced")
	}
}
