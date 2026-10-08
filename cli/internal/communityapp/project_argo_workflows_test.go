// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgoWorkflowsProjectCLIEndToEndAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, args string
		want       int
	}{
		{"blocked", `"server","--basehref","/private-route"`, ExitBlocked},
		{"fixed", `"server","--base-href","/private-route"`, ExitOK},
		{"default", `"server"`, ExitOK},
		{"unrelated-inline", `"server","--auth-mode=server","--secure=false"`, ExitOK},
		{"unknown", `"server","--auth-mode","client"`, ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"private-workflow"},"spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v3.6.0","command":["argo"],"args":[` + tc.args + `],"env":[]}]}}}}`
			path := writePrivateProjectFixture(t, body)
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"check", "project", "--project", "argo-workflows", "--workload", path, "--from", "3.5.0", "--to", "3.6.0", "--workload-complete", "--now", "2026-09-11T21:00:00Z"}, &stdout, &stderr, "test")
			if exit != tc.want || stderr.Len() != 0 {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", exit, tc.want, stdout.String(), stderr.String())
			}
			for _, private := range []string{path, "private-workflow", "private-route"} {
				if strings.Contains(stdout.String(), private) || strings.Contains(stderr.String(), private) {
					t.Fatalf("private workload data leaked: %q", private)
				}
			}
			if tc.want != ExitUnknown && !strings.Contains(stdout.String(), "docs/upgrading.md") {
				t.Fatal("human result omitted pinned source")
			}
		})
	}
}

func TestArgoWorkflowsProjectCLIModeAndPinAdmission(t *testing.T) {
	t.Parallel()
	body := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v3.6.0","command":["argo"],"args":["server"],"env":[]}]}}}}`)
	path := filepath.Join(t.TempDir(), "workload.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"check", "project", "--project", "argo-workflows", "--workload", path, "--from", "3.5.0", "--to", "3.6.0", "--workload-complete", "--now", "2026-09-11T21:00:00Z"}
	for _, extra := range [][]string{
		{"--effective-config", path},
		{"--effective-config-complete"},
		{"--precedence-resolved"},
		{"--knowledge-db", "private-store"},
		{"--profile", "private-profile"},
		{"--replay", "private-replay"},
		{"--raw-input-digest", "sha256:" + strings.Repeat("1", 64)},
		{"--knowledge-pack-digest", "sha256:" + strings.Repeat("2", 64)},
	} {
		var stdout, stderr bytes.Buffer
		if exit := Run(t.Context(), append(append([]string{}, base...), extra...), &stdout, &stderr, "test"); exit != ExitUsage || strings.Contains(stdout.String()+stderr.String(), path) || strings.Contains(stdout.String()+stderr.String(), "private-") {
			t.Fatalf("extra=%v exit/output=%d %q", extra, exit, stdout.String()+stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	withPin := append(append([]string{}, base...), "--workload-digest", digestCommunityBytes(body), "--format", "json")
	if exit := Run(t.Context(), withPin, &stdout, &stderr, "test"); exit != ExitOK || !strings.Contains(stdout.String(), `"project":"argo-workflows"`) || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatalf("pinned exit/output=%d %q %q", exit, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	badPin := append(append([]string{}, base...), "--workload-digest", "sha256:"+strings.Repeat("0", 64))
	if exit := Run(t.Context(), badPin, &stdout, &stderr, "test"); exit != ExitIntegrity || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatalf("bad pin exit/output=%d %q", exit, stdout.String()+stderr.String())
	}
	for _, command := range [][]string{
		base,
		{"prepare", "project", "--project", "argo-workflows", "--workload", path, "--from", "3.5.0", "--to", "3.6.0", "--workload-complete"},
	} {
		for _, value := range []string{"", " "} {
			stdout.Reset()
			stderr.Reset()
			args := append(append([]string{}, command...), "--workload-digest="+value)
			if exit := Run(t.Context(), args, &stdout, &stderr, "test"); exit != ExitUsage || strings.Contains(stdout.String()+stderr.String(), path) {
				t.Fatalf("empty workload pin args=%v exit=%d output=%q", args, exit, stdout.String()+stderr.String())
			}
		}
	}
}

func TestArgoWorkflowsLatestProjectCLIFiveOrigins(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"3.4.18", "3.5.15", "3.6.19", "3.7.18", "4.0.11"} {
		for _, tc := range []struct {
			arg  string
			want int
		}{
			{`--basehref=/private-route`, ExitBlocked},
			{`--base-href=/private-route`, ExitOK},
		} {
			body := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"private-workflow"},"spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v4.1.3","command":["argo"],"args":["server","` + tc.arg + `"],"env":[]}]}}}}`
			path := writePrivateProjectFixture(t, body)
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"check", "project", "--project", "argo-workflows", "--workload", path, "--from", from, "--to", "4.1.3", "--workload-complete", "--now", "2026-09-12T11:30:00Z"}, &stdout, &stderr, "test")
			if exit != tc.want || stderr.Len() != 0 || strings.Contains(stdout.String(), "private") {
				t.Fatalf("from=%s arg=%s exit=%d stdout=%q stderr=%q", from, tc.arg, exit, stdout.String(), stderr.String())
			}
		}
	}
}

func TestArgoWorkflowsPrepareInput(t *testing.T) {
	t.Parallel()
	path := writePrivateProjectFixture(t, `{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v3.6.0","command":["argo"],"args":["server"],"env":[]}]}}}}`)
	var stdout, stderr bytes.Buffer
	exit := Run(t.Context(), []string{"prepare", "project", "--project", "argo-workflows", "--workload", path, "--from", "3.5.0", "--to", "3.6.0", "--workload-complete", "--format", "input"}, &stdout, &stderr, "test")
	if exit != ExitOK || stderr.Len() != 0 || !strings.Contains(stdout.String(), projectArgoWorkflowsComponentForTest) || strings.Contains(stdout.String(), path) {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}

func TestArgoWorkflowsPublicExamples(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want int
	}{
		{"broken.json", ExitBlocked},
		{"fixed.json", ExitOK},
		{"unknown.json", ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "projects", "argo-workflows", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			path := writePrivateProjectFixture(t, string(raw))
			var stdout, stderr bytes.Buffer
			exit := Run(t.Context(), []string{"check", "project", "--project", "argo-workflows", "--workload", path, "--from", "3.5.0", "--to", "3.6.0", "--workload-complete", "--now", "2026-09-11T21:00:00Z"}, &stdout, &stderr, "test")
			if exit != tc.want || stderr.Len() != 0 {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", exit, tc.want, stdout.String(), stderr.String())
			}
			if tc.name != "unknown.json" && !strings.Contains(stdout.String(), "omitted command resolved from the reviewed exact-image ENTRYPOINT source") {
				t.Fatalf("source-derived command was not disclosed: %q", stdout.String())
			}
		})
	}
}

func TestArgoWorkflowsLatestPublicExamples(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		want int
	}{
		{"latest-broken.json", ExitBlocked},
		{"latest-fixed.json", ExitOK},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "projects", "argo-workflows", tc.name))
		if err != nil {
			t.Fatal(err)
		}
		path := writePrivateProjectFixture(t, string(raw))
		var stdout, stderr bytes.Buffer
		exit := Run(t.Context(), []string{"check", "project", "--project", "argo-workflows", "--workload", path, "--from", "4.0.11", "--to", "4.1.3", "--workload-complete", "--now", "2026-09-12T11:30:00Z"}, &stdout, &stderr, "test")
		if exit != tc.want || stderr.Len() != 0 || strings.Contains(stdout.String(), path) {
			t.Fatalf("name=%s exit=%d stdout=%q stderr=%q", tc.name, exit, stdout.String(), stderr.String())
		}
	}
}

const projectArgoWorkflowsComponentForTest = "pkg:github/argoproj/argo-workflows"
