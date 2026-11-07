// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckBaseline(t *testing.T) {
	t.Parallel()
	b := Baseline{DecidedPairs: 46, CRDProjects: 19, ProjectPairs: map[string]int{"dapr": 5, "keda": 5}}
	ok := map[string]int{"dapr": 5, "keda": 5}
	if err := CheckBaseline(b, 46, 19, ok); err != nil {
		t.Fatalf("equal numbers: %v", err)
	}
	if err := CheckBaseline(b, 50, 20, map[string]int{"dapr": 5, "keda": 5, "x": 1}); err != nil {
		t.Fatalf("higher numbers: %v", err)
	}
	// The dapr drop: 46 -> 41 decided pairs, 19 -> 18 projects, dapr 5 -> 0.
	drop := map[string]int{"keda": 5}
	if err := CheckBaseline(b, 41, 18, drop); err == nil {
		t.Fatal("a drop without a named withdrawal was accepted")
	}
	if err := CheckBaseline(b, 41, 19, ok); err == nil {
		t.Fatal("a decided-pair drop alone was accepted")
	}
	if err := CheckBaseline(b, 46, 18, ok); err == nil {
		t.Fatal("a covered-project drop alone was accepted")
	}
	if err := CheckBaseline(b, 46, 19, drop); err == nil {
		t.Fatal("a per-project drop alone was accepted")
	}
	b.Withdrawals = []Withdrawal{{Project: "dapr", DecidedPairs: 5, CRDProjects: 1, Reason: "attestations withdrawn"}}
	if err := CheckBaseline(b, 41, 18, drop); err != nil {
		t.Fatalf("named withdrawal: %v", err)
	}
	if err := CheckBaseline(b, 40, 18, drop); err == nil {
		t.Fatal("a drop beyond the named withdrawal was accepted")
	}
	if err := CheckBaseline(b, 41, 18, map[string]int{"dapr": 5}); err == nil {
		t.Fatal("another project's drop hid behind the dapr withdrawal")
	}
}

func TestCheckBaselineMove(t *testing.T) {
	t.Parallel()
	main := Baseline{DecidedPairs: 46, CRDProjects: 19, ProjectPairs: map[string]int{"dapr": 5},
		Withdrawals: []Withdrawal{{Project: "x", DecidedPairs: 2, Reason: "r"}}}
	same := main
	if err := CheckBaselineMove(main, same); err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	raised := Baseline{DecidedPairs: 50, CRDProjects: 20, ProjectPairs: map[string]int{"dapr": 5, "y": 1}}
	if err := CheckBaselineMove(main, raised); err != nil {
		t.Fatalf("raised floors with the withdrawal folded in: %v", err)
	}
	lowered := Baseline{DecidedPairs: 41, CRDProjects: 19, ProjectPairs: map[string]int{"dapr": 5}, Withdrawals: main.Withdrawals}
	if err := CheckBaselineMove(main, lowered); err == nil {
		t.Fatal("a lowered decidedPairs floor was accepted")
	}
	lowered = Baseline{DecidedPairs: 46, CRDProjects: 18, ProjectPairs: map[string]int{"dapr": 5}, Withdrawals: main.Withdrawals}
	if err := CheckBaselineMove(main, lowered); err == nil {
		t.Fatal("a lowered crd floor was accepted")
	}
	lowered = Baseline{DecidedPairs: 46, CRDProjects: 19, Withdrawals: main.Withdrawals}
	if err := CheckBaselineMove(main, lowered); err == nil {
		t.Fatal("a removed project floor was accepted")
	}
	grown := Baseline{DecidedPairs: 46, CRDProjects: 19, ProjectPairs: map[string]int{"dapr": 5}, Withdrawals: []Withdrawal{{Project: "x", DecidedPairs: 3, Reason: "r"}}}
	if err := CheckBaselineMove(main, grown); err == nil {
		t.Fatal("a grown withdrawal was accepted")
	}
	empty := Baseline{DecidedPairs: 46, CRDProjects: 19, ProjectPairs: map[string]int{"dapr": 5}, Withdrawals: []Withdrawal{{Project: "z", Reason: "r"}}}
	if err := CheckBaselineMove(main, empty); err == nil {
		t.Fatal("a withdrawal that drops nothing was accepted")
	}
	added := Baseline{DecidedPairs: 46, CRDProjects: 19, ProjectPairs: map[string]int{"dapr": 5}, Withdrawals: []Withdrawal{{Project: "z", DecidedPairs: 1, Reason: "r"}}}
	if err := CheckBaselineMove(main, added); err != nil {
		t.Fatalf("a new named withdrawal: %v", err)
	}
}

// compareBaselineFiles reads the baseline on main and the baseline of this
// tree and refuses when either is missing, unreadable or invalid, or when
// the second lowers the first. It never treats a missing file as success.
func compareBaselineFiles(mainPath, headPath string) error {
	read := func(p string) (Baseline, error) {
		raw, err := os.ReadFile(p)
		if err != nil {
			return Baseline{}, err
		}
		return ParseBaseline(raw)
	}
	m, err := read(mainPath)
	if err != nil {
		return fmt.Errorf("base baseline: %w", err)
	}
	h, err := read(headPath)
	if err != nil {
		return fmt.Errorf("head baseline: %w", err)
	}
	return CheckBaselineMove(m, h)
}

// TestBaselineNotLowered is the CI step's check: PRUFYX_BASELINE_MAIN names
// a copy of the baseline on main; the baseline of this tree must not lower it.
// With PRUFYX_BASELINE_REQUIRED set (CI) an unset PRUFYX_BASELINE_MAIN fails
// instead of skipping.
func TestBaselineNotLowered(t *testing.T) {
	path := os.Getenv("PRUFYX_BASELINE_MAIN")
	if path == "" {
		if os.Getenv("PRUFYX_BASELINE_REQUIRED") != "" {
			t.Fatal("PRUFYX_BASELINE_MAIN not set but the comparison is required")
		}
		t.Skip("PRUFYX_BASELINE_MAIN not set")
	}
	if err := compareBaselineFiles(path, "testdata/readme-baseline.json"); err != nil {
		t.Fatal(err)
	}
}

func TestCompareBaselineFilesFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"decidedPairs":2,"crdPublishedProjects":1,"withdrawals":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.json")
	if err := compareBaselineFiles(good, good); err != nil {
		t.Fatalf("identical valid files: %v", err)
	}
	for name, c := range map[string][2]string{
		"missing base file": {missing, good},
		"deleted head file": {good, missing},
		"empty base file":   {empty, good},
		"empty head file":   {good, empty},
		"both missing":      {missing, missing},
	} {
		if err := compareBaselineFiles(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseBaselineRefuses(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"unknown field": `{"decidedPairs":1,"crdPublishedProjects":1,"withdrawals":[],"x":1}`,
		"no reason":     `{"decidedPairs":1,"crdPublishedProjects":1,"withdrawals":[{"project":"dapr","decidedPairs":1,"crdPublishedProjects":0}]}`,
		"negative":      `{"decidedPairs":-1,"crdPublishedProjects":1,"withdrawals":[]}`,
		"zero floor":    `{"decidedPairs":1,"crdPublishedProjects":1,"projectPairs":{"a":0},"withdrawals":[]}`,
		"duplicate":     `{"decidedPairs":1,"crdPublishedProjects":1,"withdrawals":[{"project":"a","decidedPairs":1,"reason":"r"},{"project":"a","decidedPairs":1,"reason":"r"}]}`,
		"empty":         ``,
	} {
		if _, err := ParseBaseline([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
