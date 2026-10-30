// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
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

// A batch of community_project items is evaluated with the project pack: its
// expiry at the real time must not hide behind a pinned --now either.
func TestPinnedNowBatchCommunityProjectCannotHideWallClockExpiry(t *testing.T) {
	root := t.TempDir()
	config := writePrivateProjectFixture(t, "server.host: private-host\n")
	code, prepared, stderr := runCNCFCLIRaw(t, "prepare", "project", "--project", "kibana", "--effective-config", config, "--from", "8.18.0", "--to", "9.0.0", "--effective-config-complete", "--precedence-resolved", "--format", "input")
	if code != ExitOK {
		t.Fatalf("prepare: code=%d stdout=%q stderr=%q", code, prepared, stderr)
	}
	if err := os.WriteFile(filepath.Join(root, "input.json"), []byte(prepared), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"schema": "prufyx.io/batch-check-plan/v1alpha1", "authority": "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS", "knowledge": map[string]any{"mode": "embedded_only"}, "items": []any{map[string]any{"id": "kibana", "kind": "community_project", "project": "kibana", "from": "8.18.0", "to": "9.0.0", "inputPath": "input.json"}}}
	planRaw, _ := json.Marshal(plan)
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, planRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Only the project pack's rules end between the pinned time and the real
	// time (the CNCF pack's evidence is unchanged then), so the guard needs the
	// project pack's end dates; the pinned run must still PASS, as the
	// kibana rule is the one ending at that instant.
	projects, err := projectcheck.EmbeddedKnowledgeAge()
	if err != nil {
		t.Fatal(err)
	}
	cncf, err := cncfcheck.EmbeddedEvidenceAge()
	if err != nil {
		t.Fatal(err)
	}
	ends := append([]time.Time(nil), projects[0].Expiries...)
	sort.Slice(ends, func(i, j int) bool { return ends[i].Before(ends[j]) })
	tested := false
	for _, end := range ends {
		pinned, wall := end.Add(-time.Second), end.Add(time.Second)
		if knowledgeage.Summarize(cncf, wall).Expired != knowledgeage.Summarize(cncf, pinned).Expired {
			continue
		}
		args := []string{"check", "batch", "--plan", planPath, "--root", root, "--now", pinned.Format(time.RFC3339), "--format", "json"}
		setWallClock(t, pinned)
		if code, _, _ := runCNCFCLIRaw(t, args...); code != ExitOK {
			continue
		}
		setWallClock(t, wall)
		code, stdout, stderr := runCNCFCLIRaw(t, args...)
		if code == ExitOK || strings.Contains(stdout, `"aggregateCategory":"PASS"`) || !strings.Contains(stderr, "knowledge rules have expired since") {
			t.Fatalf("pinned PASS kept at %s: code=%d stdout=%q stderr=%q", end, code, stdout, stderr)
		}
		tested = true
		break
	}
	if !tested {
		t.Fatal("no project rule end date isolates the project pack")
	}
}
