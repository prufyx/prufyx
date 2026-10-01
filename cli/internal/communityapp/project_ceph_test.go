// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"
)

func TestCephSelectedOSDProjectCLI(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		complete   bool
		want       int
	}{
		{"filestore-blocked", `{"id":7,"osd_objectstore":"filestore","hostname":"private-node"}`, true, ExitBlocked},
		{"bluestore-pass", `{"id":7,"osd_objectstore":"bluestore"}`, true, ExitOK},
		{"unsupported-unknown", `{"id":7,"osd_objectstore":"memstore"}`, true, ExitUnknown},
		{"incomplete-unknown", `{"id":7,"osd_objectstore":"filestore"}`, false, ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writePrivateProjectFixture(t, tc.body)
			args := []string{"check", "project", "--project", "ceph", "--selected-osd-metadata", path, "--selected-osd-id", "7", "--from", "17.2.7", "--to", "18.2.0", "--now", "2026-09-11T21:00:00Z", "--format", "json"}
			if tc.complete {
				args = append(args, "--selected-osd-metadata-complete")
			}
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), args, &stdout, &stderr, "test")
			if exit != tc.want {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", exit, tc.want, stdout.String(), stderr.String())
			}
			for _, private := range []string{path, "private-node", `"id":7`, `"osd_objectstore"`} {
				if strings.Contains(stdout.String()+stderr.String(), private) {
					t.Fatalf("private selected metadata leaked: %q", private)
				}
			}
		})
	}
}

func TestCephLatestSelectedOSDAllExactOrigins(t *testing.T) {
	for _, from := range []string{"19.2.6", "18.2.8", "17.2.9", "16.2.15", "15.2.17"} {
		for _, tc := range []struct {
			name, store, status string
			complete            bool
			want                int
		}{
			{"filestore-blocked", "filestore", "BLOCKED", true, ExitBlocked},
			{"bluestore-pass", "bluestore", "PASS", true, ExitOK},
			{"unknown-backend", "memstore", "UNKNOWN", true, ExitUnknown},
			{"incomplete-unknown", "filestore", "UNKNOWN", false, ExitUnknown},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				body := `{"id":7,"osd_objectstore":"` + tc.store + `","hostname":"private-node"}`
				path := writePrivateProjectFixture(t, body)
				args := []string{"check", "project", "--project", "ceph", "--selected-osd-metadata", path, "--selected-osd-id", "7", "--from", from, "--to", "20.2.4", "--now", "2026-09-12T09:20:00Z", "--format", "json"}
				if tc.complete {
					args = append(args, "--selected-osd-metadata-complete")
				}
				var stdout, stderr bytes.Buffer
				exit := Run(t.Context(), args, &stdout, &stderr, "test")
				if exit != tc.want || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"assessment":"UNKNOWN"`) {
					t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
				}
				if tc.status != "UNKNOWN" && !strings.Contains(stdout.String(), `"status":"`+tc.status+`"`) {
					t.Fatalf("missing status %s: %s", tc.status, stdout.String())
				}
				for _, private := range []string{path, "private-node", `"id":7`, `"osd_objectstore"`} {
					if strings.Contains(stdout.String()+stderr.String(), private) {
						t.Fatalf("private selected metadata leaked: %q", private)
					}
				}
			})
		}
	}
	for _, tc := range []struct{ from, to string }{{"19.2.5", "20.2.4"}, {"19.2.6", "20.2.3"}} {
		path := writePrivateProjectFixture(t, `{"id":7,"osd_objectstore":"filestore"}`)
		args := []string{"check", "project", "--project", "ceph", "--selected-osd-metadata", path, "--selected-osd-id", "7", "--from", tc.from, "--to", tc.to, "--selected-osd-metadata-complete", "--now", "2026-09-12T09:20:00Z", "--format", "json"}
		var stdout, stderr bytes.Buffer
		if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUnknown || stderr.Len() != 0 || !strings.Contains(stdout.String(), "no reviewed rule matches") || strings.Contains(stdout.String()+stderr.String(), path) {
			t.Fatalf("pair=%s/%s exit=%d stdout=%q stderr=%q", tc.from, tc.to, exit, stdout.String(), stderr.String())
		}
	}
}

func TestCephSelectedOSDProjectAdmissionAndHumanScope(t *testing.T) {
	path := writePrivateProjectFixture(t, `{"id":7,"osd_objectstore":"filestore"}`)
	base := []string{"check", "project", "--project", "ceph", "--selected-osd-metadata", path, "--selected-osd-id", "7", "--from", "17.2.7", "--to", "18.2.0", "--selected-osd-metadata-complete", "--now", "2026-09-11T21:00:00Z"}
	var stdout, stderr bytes.Buffer
	if exit := Run(t.Context(), base, &stdout, &stderr, "test"); exit != ExitBlocked || !strings.Contains(stdout.String(), "caller-selected current OSD metadata") || !strings.Contains(stdout.String(), "src/os/ObjectStore.cc") || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatalf("exit/output=%d %q %q", exit, stdout.String(), stderr.String())
	}
	for _, extra := range [][]string{
		{"--effective-config", path},
		{"--workload", path},
		{"--knowledge-db", "store"},
		{"--profile", "cncf"},
		{"--replay-report", "receipt"},
	} {
		stdout.Reset()
		stderr.Reset()
		if exit := Run(t.Context(), append(append([]string{}, base...), extra...), &stdout, &stderr, "test"); exit != ExitUsage || strings.Contains(stdout.String()+stderr.String(), path) {
			t.Fatalf("extra=%v exit=%d output=%q", extra, exit, stdout.String()+stderr.String())
		}
	}
	stdout.Reset()
	stderr.Reset()
	badPair := append([]string{}, base...)
	for index := range badPair {
		if badPair[index] == "17.2.7" {
			badPair[index] = "17.2.8"
		}
	}
	if exit := Run(t.Context(), badPair, &stdout, &stderr, "test"); exit != ExitUnknown || !strings.Contains(stdout.String(), "no reviewed rule matches") {
		t.Fatalf("wrong pair exit/output=%d %q", exit, stdout.String())
	}
}

func TestProjectExplicitEmptyDigestPinsAreRejected(t *testing.T) {
	config := writePrivateProjectFixture(t, "[alerting]\nenabled=false\n")
	workload := writePrivateProjectFixture(t, `{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v3.6.0","args":["server"]}]}}}}`)
	osd := writePrivateProjectFixture(t, `{"id":7,"osd_objectstore":"bluestore"}`)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"effective-config-prepare-empty", []string{"prepare", "project", "--project", "grafana", "--effective-config", config, "--effective-config-digest=", "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved"}},
		{"effective-config-check-space", []string{"check", "project", "--project", "grafana", "--effective-config", config, "--effective-config-digest= ", "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-09-11T21:00:00Z"}},
		{"workload-prepare-space", []string{"prepare", "project", "--project", "argo-workflows", "--workload", workload, "--workload-digest= ", "--from", "3.5.0", "--to", "3.6.0", "--workload-complete"}},
		{"workload-check-empty", []string{"check", "project", "--project", "argo-workflows", "--workload", workload, "--workload-digest=", "--from", "3.5.0", "--to", "3.6.0", "--workload-complete", "--now", "2026-09-11T21:00:00Z"}},
		{"osd-prepare-empty", []string{"prepare", "project", "--project", "ceph", "--selected-osd-metadata", osd, "--selected-osd-metadata-digest=", "--selected-osd-id", "7", "--from", "17.2.7", "--to", "18.2.0", "--selected-osd-metadata-complete"}},
		{"osd-check-space", []string{"check", "project", "--project", "ceph", "--selected-osd-metadata", osd, "--selected-osd-metadata-digest= ", "--selected-osd-id", "7", "--from", "17.2.7", "--to", "18.2.0", "--selected-osd-metadata-complete", "--now", "2026-09-11T21:00:00Z"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if exit := Run(t.Context(), tc.args, &stdout, &stderr, "test"); exit != ExitUsage {
				t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
			}
			for _, path := range []string{config, workload, osd} {
				if strings.Contains(stdout.String()+stderr.String(), path) {
					t.Fatalf("private path leaked: %q", path)
				}
			}
		})
	}
}
