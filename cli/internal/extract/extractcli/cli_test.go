// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"bytes"
	"encoding/json"
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
	if code != 0 || !strings.Contains(out, "4 pairs (4 derived, 0 withheld), 6 rules, 18 vectors") {
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

func TestCRDRunVerifyOracleOnFixture(t *testing.T) {
	for _, tc := range []struct{ id, fx, expected, summary string }{
		{"crd.version-removal.strimzi", "../crdversions/testdata/strimzi", "../crdversions/testdata/oracle-strimzi.json", "1 pairs (1 derived, 0 withheld), 10 rules, 30 vectors"},
		{"crd.version-removal.argo-cd", "../crdversions/testdata/fixture", "../crdversions/testdata/oracle-fixture.json", "2 pairs (2 derived, 0 withheld), 2 rules, 6 vectors"},
	} {
		dir := filepath.Join(t.TempDir(), "out")
		code, out, errs := run("run", "--extractor", tc.id, "--fixture", tc.fx, "--out", dir, "--derived-at", "2026-10-04T00:00:00Z")
		if code != 0 || !strings.Contains(out, tc.summary) {
			t.Fatalf("%s run: %d %s %s", tc.id, code, out, errs)
		}
		if code, out, errs := run("verify", "--extractor", tc.id, "--fixture", tc.fx, "--out", dir); code != 0 || !strings.Contains(out, "byte-identical") {
			t.Fatalf("%s verify: %d %s %s", tc.id, code, out, errs)
		}
		if code, out, _ := run("oracle", "--extractor", tc.id, "--out", dir, "--expected", tc.expected); code != 0 {
			t.Fatalf("%s oracle: %d %s", tc.id, code, out)
		}
		p := filepath.Join(dir, "candidates.json")
		data, _ := os.ReadFile(p)
		if err := os.WriteFile(p, bytes.Replace(data, []byte("/v1beta"), []byte("/v2beta"), 1), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, out, _ := run("verify", "--extractor", tc.id, "--fixture", tc.fx, "--out", dir); code != 1 || !strings.Contains(out, "DIFFERS candidates.json") {
			t.Fatalf("%s tampered verify: %d %s", tc.id, code, out)
		}
	}
	code, out, _ := run("list")
	for _, id := range []string{"crd.version-removal.argo-cd\tgithub.com/argoproj/argo-cd", "crd.version-removal.istio\tgithub.com/istio/istio", "crd.version-removal.strimzi\tgithub.com/strimzi/strimzi-kafka-operator"} {
		if code != 0 || !strings.Contains(out, id) {
			t.Fatalf("list: %d %s", code, out)
		}
	}
}

func TestRunLeaseDays(t *testing.T) {
	const id, fx = "k8s.served-api-removal", "../k8sservedapis/testdata/fixture"
	validUntil := func(dir string) string {
		raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			ValidUntil string `json:"validUntil"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m.ValidUntil
	}
	for _, tc := range []struct {
		days string
		want string
	}{{"", "2027-01-01T00:00:00Z"}, {"76", "2026-12-18T00:00:00Z"}, {"1", "2026-10-04T00:00:00Z"}, {"365", "2027-10-03T00:00:00Z"}} {
		dir := filepath.Join(t.TempDir(), "out")
		args := []string{"run", "--extractor", id, "--fixture", fx, "--out", dir, "--derived-at", "2026-10-03T00:00:00Z"}
		if tc.days != "" {
			args = append(args, "--lease-days", tc.days)
		}
		if code, out, errs := run(args...); code != 0 {
			t.Fatalf("%v: %d %s %s", args, code, out, errs)
		}
		if got := validUntil(dir); got != tc.want {
			t.Fatalf("lease %q: validUntil %s, want %s", tc.days, got, tc.want)
		}
		if code, out, errs := run("verify", "--extractor", id, "--fixture", fx, "--out", dir); code != 0 {
			t.Fatalf("verify lease %q: %d %s %s", tc.days, code, out, errs)
		}
	}
	for _, bad := range []string{"0", "-1", "366", "x"} {
		if code, _, _ := run("run", "--extractor", id, "--fixture", fx, "--out", t.TempDir()+"/o", "--derived-at", "2026-10-03T00:00:00Z", "--lease-days", bad); code != 2 {
			t.Fatalf("--lease-days %s: exit %d, want 2", bad, code)
		}
	}
}
