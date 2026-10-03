// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixture = "../k8sfeaturegates/testdata/fixture"

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Main(args, nil, func() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunVerifyOracleOnFixture(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	code, out, errs := run("run", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture, "--out", dir, "--derived-at", "2026-10-02T00:00:00Z")
	if code != 0 || !strings.Contains(out, "3 pairs (3 derived, 0 withheld), 15 rules, 45 vectors") {
		t.Fatalf("run: %d %s %s", code, out, errs)
	}
	if code, out, errs := run("verify", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture, "--out", dir); code != 0 || !strings.Contains(out, "byte-identical") {
		t.Fatalf("verify: %d %s %s", code, out, errs)
	}
	if code, out, _ := run("oracle", "--extractor", "k8s.feature-gate-removal", "--out", dir, "--expected", "../k8sfeaturegates/testdata/oracle-fixture.json"); code != 0 {
		t.Fatalf("oracle: %d %s", code, out)
	}
	// Tampering is caught by verify.
	p := filepath.Join(dir, "candidates.json")
	data, _ := os.ReadFile(p)
	if err := os.WriteFile(p, bytes.Replace(data, []byte("StartupProbe"), []byte("StartupProbX"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run("verify", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture, "--out", dir); code != 1 || !strings.Contains(out, "DIFFERS candidates.json") {
		t.Fatalf("tampered verify: %d %s", code, out)
	}
	// A second run refuses a non-empty output directory.
	if code, _, _ := run("run", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture, "--out", dir); code != 2 {
		t.Fatalf("non-empty out: %d", code)
	}
}

func TestRejectsBadInvocations(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"nope"},
		{"run", "--extractor", "unknown", "--fixture", fixture, "--out", t.TempDir()},
		{"run", "--extractor", "k8s.feature-gate-removal", "--out", t.TempDir()},
		{"run", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture, "--mirror-state", "x", "--out", t.TempDir()},
		{"run", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture, "--out", t.TempDir(), "--derived-at", "2026-10-02T00:00:00+02:00"},
		{"verify", "--extractor", "k8s.feature-gate-removal", "--fixture", fixture},
	} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
	if code, out, _ := run("list"); code != 0 || !strings.Contains(out, "k8s.feature-gate-removal\tgithub.com/kubernetes/kubernetes") {
		t.Fatalf("list: %d %s", code, out)
	}
}

func TestServedAPIRunVerifyOracleOnFixture(t *testing.T) {
	const id, fx = "k8s.served-api-removal", "../k8sservedapis/testdata/fixture"
	dir := filepath.Join(t.TempDir(), "out")
	code, out, errs := run("run", "--extractor", id, "--fixture", fx, "--out", dir, "--derived-at", "2026-10-03T00:00:00Z")
	if code != 0 || !strings.Contains(out, "4 pairs (4 derived, 0 withheld), 5 rules, 15 vectors") {
		t.Fatalf("run: %d %s %s", code, out, errs)
	}
	if code, out, errs := run("verify", "--extractor", id, "--fixture", fx, "--out", dir); code != 0 || !strings.Contains(out, "byte-identical") {
		t.Fatalf("verify: %d %s %s", code, out, errs)
	}
	if code, out, _ := run("oracle", "--extractor", id, "--out", dir, "--expected", "../k8sservedapis/testdata/oracle-fixture.json"); code != 0 {
		t.Fatalf("oracle: %d %s", code, out)
	}
	p := filepath.Join(dir, "candidates.json")
	data, _ := os.ReadFile(p)
	if err := os.WriteFile(p, bytes.Replace(data, []byte("CronJob"), []byte("CronJoX"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run("verify", "--extractor", id, "--fixture", fx, "--out", dir); code != 1 || !strings.Contains(out, "DIFFERS candidates.json") {
		t.Fatalf("tampered verify: %d %s", code, out)
	}
	if code, out, _ := run("list"); code != 0 || !strings.Contains(out, id+"\tgithub.com/kubernetes/kubernetes") {
		t.Fatalf("list: %d %s", code, out)
	}
}
