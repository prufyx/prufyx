// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// strictRoute is one check route with a command line that ends in each exit
// status the route can give from a local fixture.
type strictRoute struct {
	name string
	// cases maps a label to the command line and its status without
	// --strict-exit.
	cases []strictCase
}
type strictCase struct {
	label string
	args  []string
	want  int
}

func strictRoutes(t *testing.T) []strictRoute {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	dir := privateDir(t)

	certPass := filepath.Join(dir, "pass.pem")
	writePrivate(t, certPass, makeCertificate(t, "spiffe://example.test/workload", false))
	certFail := filepath.Join(dir, "fail.pem")
	writePrivate(t, certFail, makeCertificate(t, "https://example.test/x", false))

	evPass := filepath.Join(dir, "ev-pass.json")
	writePrivate(t, evPass, []byte(`{"specversion":"1.0","id":"a","source":"b","type":"example.fixed"}`))
	evFail := filepath.Join(dir, "ev-fail.json")
	writePrivate(t, evFail, []byte(`{"specversion":"1.0","id":"a","source":"b"}`))

	tikvPass := filepath.Join(dir, "tikv-pass.toml")
	writePrivate(t, tikvPass, []byte("[backup]\ngcp-v2-enable = true\n"))
	tikvFail := filepath.Join(dir, "tikv-fail.toml")
	writePrivate(t, tikvFail, []byte("[backup]\ngcp-v2-enable = false\n"))

	cm := filepath.Join(dir, "cm-pass.json")
	writePrivate(t, cm, []byte(`{"prometheus":{"servicemonitor":{"enabled":true}}}`))
	cmBlocked := filepath.Join(dir, "cm-blocked.json")
	writePrivate(t, cmBlocked, []byte(`{"prometheus":{"servicemonitor":{"path":"x"}}}`))

	projPass := writePrivateProjectFixture(t, "[unified_alerting]\nenabled=true\n")
	projBlocked := writePrivateProjectFixture(t, "[alerting]\nenabled=true\n")
	proj := func(path string) []string {
		return []string{"check", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-12T00:00:00Z", "--format", "json"}
	}

	helm := writeCNCFFile(t, "helm.json", []byte(syntheticHelmInput), 0o600)

	root := t.TempDir()
	thanos := map[string]any{
		"schema": "prufyx.io/operator-declared-constraint-input/v1alpha1", "authority": "OPERATOR_DECLARED_MINIMIZED",
		"current":  map[string]any{"components": []any{map[string]any{"component": "pkg:github/thanos-io/thanos", "version": "0.41.0", "facts": []any{}}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": "pkg:github/thanos-io/thanos", "version": "0.42.0", "facts": []any{map[string]any{"id": "component.thanos.removed_subcommand_flags_present", "state": "declared", "boolValue": false}}}}},
	}
	raw, _ := json.Marshal(thanos)
	if err := os.WriteFile(filepath.Join(root, "input.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, _ := json.Marshal(map[string]any{"schema": "prufyx.io/batch-check-plan/v1alpha1", "authority": "OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS", "knowledge": map[string]any{"mode": "embedded_only"}, "items": []any{map[string]any{"id": "thanos-pass", "kind": "cncf", "project": "thanos", "from": "0.41.0", "to": "0.42.0", "inputPath": "input.json"}}})
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(planPath, plan, 0o600); err != nil {
		t.Fatal(err)
	}
	batch := []string{"check", "batch", "--plan", planPath, "--root", root, "--now", "2026-09-12T22:00:00Z", "--format", "json"}
	tikv := func(p string) []string {
		return []string{"check", "tikv-gcp-v2-wif-backup", "--config", p, "--target-version", tikvArgsTarget, "--operation", tikvArgsOperation, "--now", now, "--format", "json"}
	}

	return []strictRoute{
		{"batch", []strictCase{{"pass", batch, ExitOK}, {"usage", []string{"check", "batch"}, ExitUsage}}},
		{"cncf", []strictCase{{"pass", append(cncfArgs(helm), "--format", "json"), ExitOK}, {"usage", []string{"check", "cncf"}, ExitUsage}}},
		{"project", []strictCase{{"pass", proj(projPass), ExitOK}, {"blocked", proj(projBlocked), ExitBlocked}, {"usage", []string{"check", "project"}, ExitUsage}}},
		{"cert-manager-values", []strictCase{
			{"pass", []string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", cm}, ExitOK},
			{"blocked", []string{"check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", cmBlocked}, ExitBlocked},
			{"usage", []string{"check", "cert-manager-values"}, ExitUsage}}},
		{"prometheus-mode", []strictCase{{"demo-unknown", []string{"check", "prometheus-mode", "--demo"}, ExitUnknown}, {"usage", []string{"check", "prometheus-mode"}, ExitUsage}}},
		{"spiffe-x509-svid", []strictCase{
			{"pass", []string{"check", "spiffe-x509-svid", "--certificate", certPass, "--now", now}, ExitOK},
			{"blocked", []string{"check", "spiffe-x509-svid", "--certificate", certFail, "--now", now}, ExitBlocked},
			{"usage", []string{"check", "spiffe-x509-svid"}, ExitUsage}}},
		{"cloudevents-structured-json", []strictCase{
			{"pass", []string{"check", "cloudevents-structured-json", "--event", evPass, "--now", now}, ExitOK},
			{"blocked", []string{"check", "cloudevents-structured-json", "--event", evFail, "--now", now}, ExitBlocked},
			{"usage", []string{"check", "cloudevents-structured-json"}, ExitUsage}}},
		{"tikv-gcp-v2-wif-backup", []strictCase{
			{"pass", tikv(tikvPass), ExitOK},
			{"blocked", tikv(tikvFail), ExitBlocked},
			{"usage", []string{"check", "tikv-gcp-v2-wif-backup"}, ExitUsage}}},
	}
}

// TestStrictExitEveryCheckRoute runs every check route both ways: without the
// flag the status, stdout and stderr are the existing ones; with it only the
// scoped PASS (0) changes, to ExitScopedPass, and stdout stays byte-identical.
func TestStrictExitEveryCheckRoute(t *testing.T) {
	for _, route := range strictRoutes(t) {
		for _, c := range route.cases {
			t.Run(route.name+"/"+c.label, func(t *testing.T) {
				code, out, errout := runCNCFCLI(t, c.args...)
				if code != c.want {
					t.Fatalf("default code=%d want %d stdout=%q stderr=%q", code, c.want, out, errout)
				}
				strictArgs := append(append([]string{c.args[0]}, "--strict-exit"), c.args[1:]...)
				for _, a := range [][]string{strictArgs, append(append([]string{}, c.args...), "--strict-exit")} {
					scode, sout, serr := runCNCFCLI(t, a...)
					want := c.want
					if want == ExitOK {
						want = ExitScopedPass
					}
					if scode != want {
						t.Fatalf("strict code=%d want %d stdout=%q stderr=%q", scode, want, sout, serr)
					}
					if sout != out {
						t.Fatalf("strict stdout differs:\n%q\n%q", sout, out)
					}
					if c.want == ExitOK && !strings.Contains(serr, "not a complete PASS") {
						t.Fatalf("strict scoped PASS prints no note: %q", serr)
					}
					if c.want != ExitOK && serr != errout {
						t.Fatalf("strict stderr differs for exit %d: %q vs %q", c.want, serr, errout)
					}
				}
				// An explicit false is the default.
				fcode, fout, _ := runCNCFCLI(t, append(append([]string{}, c.args...), "--strict-exit=false")...)
				if fcode != c.want || fout != out {
					t.Fatalf("--strict-exit=false changed the result: code=%d", fcode)
				}
			})
		}
	}
}

func TestStrictExitLeavesHelpAndOtherCommandsAlone(t *testing.T) {
	for _, args := range [][]string{{"check", "--help"}, {"check", "cncf", "--help"}, {"check", "batch", "--help"}} {
		code, _, _ := runCNCFCLI(t, append(args, "--strict-exit")...)
		if code != ExitOK {
			t.Fatalf("%v: help exit %d, want 0", args, code)
		}
	}
	// Outside check the flag is not accepted.
	if code, _, _ := runCNCFCLI(t, "version", "--strict-exit"); code == ExitScopedPass {
		t.Fatal("version must not take --strict-exit")
	}
	if code, _, _ := runCNCFCLI(t, "scan", "--strict-exit"); code != ExitUsage {
		t.Fatalf("scan --strict-exit exit %d, want 2", code)
	}
}
