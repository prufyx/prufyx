// SPDX-License-Identifier: AGPL-3.0-only
package extractcli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/decision"
)

func TestRunDecisionV2MatchesTruthfulLegacyBridge(t *testing.T) {
	const id, fx, at = "k8s.served-api-removal", "../k8sservedapis/testdata/fixture", "2026-10-03T00:00:00Z"
	base := t.TempDir()
	legacy, v2, bridged := filepath.Join(base, "legacy"), filepath.Join(base, "v2"), filepath.Join(base, "bridge")
	for _, tt := range []struct{ dir, format string }{{legacy, "v1"}, {v2, "v2"}} {
		args := []string{"run", "--extractor", id, "--fixture", fx, "--out", tt.dir, "--derived-at", at}
		if tt.format == "v2" {
			args = append(args, "--output-format", "v2")
		}
		if code, out, err := run(args...); code != 0 {
			t.Fatalf("real run %s: %d %s %s", tt.format, code, out, err)
		}
	}
	if code, out, err := run("decisions", "--from", legacy, "--out", bridged); code != 0 {
		t.Fatalf("bridge %d %s %s", code, out, err)
	}
	if code, out, err := run("decisions", "--compare", v2, "--with", bridged); code != 0 {
		t.Fatalf("compare %d %s %s", code, out, err)
	}
	if code, out, err := run("decisions", "--verify", v2); code != 0 {
		t.Fatalf("verify %d %s %s", code, out, err)
	}
	p, e := decision.ReadPair(v2)
	if e != nil {
		t.Fatal(e)
	}
	originals, e := decision.Reconstruct(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range originals {
		old, e := os.ReadFile(filepath.Join(legacy, f.Path))
		if e != nil || !bytes.Equal(old, f.Data) {
			t.Fatalf("legacy original mismatch %s %v", f.Path, e)
		}
	}
	for _, args := range [][]string{{"verify", "--extractor", id, "--fixture", fx, "--out", v2}, {"apply", "--out", v2, "--pack", filepath.Join(base, "absent-pack")}, {"run", "--extractor", id, "--fixture", fx, "--out", filepath.Join(base, "bad"), "--output-format", "v3"}} {
		if code, _, _ := run(args...); code == 0 {
			t.Fatalf("unsupported consumer accepted %v", args)
		}
	}
	if _, e := os.Stat(filepath.Join(v2, "manifest.json")); !os.IsNotExist(e) {
		t.Fatal("v2 masquerades as legacy run")
	}
}
func TestDecisionsRejectsPartialOrMixedModes(t *testing.T) {
	for _, args := range [][]string{{"decisions"}, {"decisions", "--from", "a", "--verify", "b"}, {"decisions", "--compare", "a"}, {"decisions", "--verify", "a", "--out", "b"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestDecisionResultProtocol(t *testing.T) {
	const id, fx = "k8s.served-api-removal", "../k8sservedapis/testdata/fixture"
	base := t.TempDir()
	left, right := filepath.Join(base, "left"), filepath.Join(base, "right")
	for i, dir := range []string{left, right} {
		at := []string{"2026-10-03T00:00:00Z", "2026-10-04T00:00:00Z"}[i]
		if code, out, err := run("run", "--extractor", id, "--fixture", fx, "--out", dir, "--derived-at", at, "--output-format", "v2"); code != 0 {
			t.Fatalf("derive %d %s %s", code, out, err)
		}
	}
	for _, tt := range []struct {
		args   []string
		code   int
		result string
		right  bool
	}{
		{[]string{"decisions", "--verify", left}, 0, "VALID", false},
		{[]string{"decisions", "--compare", left, "--with", left}, 0, "EQUAL", true},
		{[]string{"decisions", "--compare", left, "--with", right}, 1, "DIFFERENT", true},
		{[]string{"decisions", "--verify", filepath.Join(base, "missing")}, 2, "INVALID", false},
	} {
		code, out, errs := run(tt.args...)
		if code != tt.code {
			t.Fatalf("result %v: %d %s %s", tt.args, code, out, errs)
		}
		var got decisionCheck
		if e := json.Unmarshal([]byte(out), &got); e != nil {
			t.Fatal(e)
		}
		if got.Schema != decisionCheckSchema || got.Result != tt.result {
			t.Fatalf("wrong result %+v", got)
		}
		if tt.code == 2 {
			if got.Left != nil || got.Right != nil {
				t.Fatal("invalid output carries trusted digests")
			}
			continue
		}
		p, e := decision.ReadPair(left)
		if e != nil {
			t.Fatal(e)
		}
		if got.Left == nil || *got.Left != *hashes(p) || (got.Right != nil) != tt.right {
			t.Fatalf("digest binding %+v", got)
		}
	}
}

func TestDecisionBridgeRejectsRealChartRun(t *testing.T) {
	const id, fixture = "helm.values.keda.keda", "../helmvalues/testdata/fixture"
	root := t.TempDir()
	legacy := filepath.Join(root, "chart-v1")
	if code, out, errs := run("run", "--extractor", id, "--fixture", fixture, "--out", legacy, "--derived-at", "2026-10-11T00:00:00Z"); code != 0 {
		t.Fatalf("real chart fixture failed before bridge: %d %s %s", code, out, errs)
	}
	bridged := filepath.Join(root, "bridge")
	code, out, errs := run("decisions", "--from", legacy, "--out", bridged)
	if code != 2 || !strings.Contains(errs, "chart producer") {
		t.Fatalf("unsupported actual chart producer accepted: %d %s %s", code, out, errs)
	}
	var result decisionCheck
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.Result != "INVALID" || result.Left != nil {
		t.Fatalf("chart refusal result: %s %v", out, err)
	}
	if _, err := os.Stat(bridged); !os.IsNotExist(err) {
		t.Fatal("refused chart bridge published output")
	}
	if code, _, _ := run("run", "--extractor", id, "--fixture", fixture, "--out", filepath.Join(root, "chart-v2"), "--derived-at", "2026-10-11T00:00:00Z", "--output-format", "v2"); code != 2 {
		t.Fatal("chart run-v2 no longer refuses")
	}
}
