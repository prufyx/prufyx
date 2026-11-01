// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func chainInput(from, to, cronJob string) []byte {
	return []byte(`{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + from + `","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + to + `","facts":[{"id":"component.kubernetes.cronjob_v1beta1_removed_gvk_present","state":"declared","boolValue":` + cronJob + `}]}]}}`)
}

func TestCNCFCLIViaChainsTheHops(t *testing.T) {
	t.Parallel()
	const now = "2026-11-20T00:00:00Z"
	blocked := writeCNCFFile(t, "blocked.json", chainInput("1.23.5", "1.25.3", "true"), 0o600)
	clear := writeCNCFFile(t, "clear.json", chainInput("1.23.5", "1.25.3", "false"), 0o600)
	base := func(path string, extra ...string) []string {
		return append([]string{"check", "cncf", "--project", "kubernetes", "--input", path, "--now", now}, extra...)
	}

	code, stdout, stderr := runCNCFCLI(t, base(blocked, "--via", "1.24.17", "--format", "json")...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	var chain struct {
		Schema  string
		Verdict string
		Path    []string
		Hops    []struct {
			From, To, Verdict string
		}
		Whole struct{ From, To string }
	}
	if err := json.Unmarshal([]byte(stdout), &chain); err != nil {
		t.Fatal(err)
	}
	if chain.Schema != "prufyx.io/cncf-chain-check/v1alpha1" || chain.Verdict != "BLOCKED" || len(chain.Hops) != 2 || chain.Hops[1].Verdict != "BLOCKED" || chain.Whole.From != "1.23.5" || chain.Whole.To != "1.25.3" {
		t.Fatalf("chain %+v", chain)
	}

	code, stdout, _ = runCNCFCLI(t, base(blocked, "--via", "1.24.17")...)
	if code != ExitBlocked || !strings.HasPrefix(stdout, "BLOCKED: kubernetes 1.23.5 -> 1.24.17 -> 1.25.3 (2 hops") || !strings.Contains(stdout, "hop 2") || !strings.Contains(stdout, "end-to-end") {
		t.Fatalf("code=%d human output:\n%s", code, stdout)
	}

	code, stdout, _ = runCNCFCLI(t, base(clear, "--via", "1.24.17")...)
	if code != ExitUnknown || !strings.HasPrefix(stdout, "UNKNOWN: ") {
		t.Fatalf("code=%d human output:\n%s", code, stdout)
	}

	// Without --via the single transition is checked exactly as before.
	code, stdout, _ = runCNCFCLI(t, base(blocked, "--format", "json")...)
	if strings.Contains(stdout, "cncf-chain-check") || code == ExitUsage {
		t.Fatalf("code=%d plain check changed: %.200s", code, stdout)
	}

	for name, args := range map[string][]string{
		"descending":           base(blocked, "--via", "1.24.17,1.24.2"),
		"equal to from":        base(blocked, "--via", "1.23.5"),
		"empty":                base(blocked, "--via", ""),
		"with --from":          append(base(blocked, "--via", "1.24.17"), "--from", "1.23.5"),
		"with knowledge-db":    append(base(blocked, "--via", "1.24.17"), "--knowledge-db", t.TempDir()),
		"with replay":          append(base(blocked, "--via", "1.24.17"), "--replay-report", clear),
		"on a native route":    {"check", "cncf", "--project", "kubernetes", "--native-resource", clear, "--from", "1.24.0", "--to", "1.25.0", "--via", "1.24.5", "--now", now},
		"without a declared v": base(blocked, "--via", "1.24.x"),
	} {
		if code, stdout, _ := runCNCFCLI(t, args...); code != ExitUsage || stdout != "" {
			t.Errorf("%s: code=%d stdout=%q, want usage error", name, code, stdout)
		}
	}
}
