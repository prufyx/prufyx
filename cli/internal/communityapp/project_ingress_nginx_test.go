// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

const ingressNginxRuleID = "ingress-nginx.configuration-snippet-rejected-at-default-risk-level.1-10-0-to-1-15-0"

// Canary strings must never appear in any output, error or canonical input.
var ingressNginxCanaries = []string{"CANARY_CM_VALUE", "CANARY_SNIPPET_BODY", "CANARY_BINARY", "CANARY_SECRET", "PRIVATE_NAME", "CANARY_LABEL", "CANARY_SPEC"}

func ingressNginxConfigMap(allow, level string) string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: PRIVATE_NAME\ndata:\n  other-key: CANARY_CM_VALUE\n")
	if allow != "" {
		b.WriteString("  allow-snippet-annotations: " + allow + "\n")
	}
	if level != "" {
		b.WriteString("  annotations-risk-level: " + level + "\n")
	}
	b.WriteString("binaryData:\n  blob: CANARY_BINARY\n")
	return b.String()
}

func ingressNginxIngress(annotations string) string {
	return "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: PRIVATE_NAME\n  labels:\n    nginx.ingress.kubernetes.io/configuration-snippet: CANARY_LABEL\n  annotations:\n" + annotations + "spec:\n  ingressClassName: nginx\n  note: CANARY_SPEC\n"
}

const ingressNginxSnippetAnnotation = "    nginx.ingress.kubernetes.io/configuration-snippet: |\n      CANARY_SNIPPET_BODY\n"

// ingressNginxFlags are the declarations a caller makes; a case clears one to test it.
type ingressNginxFlags struct{ configMapComplete, setComplete, scope bool }

func ingressNginxAllFlags() ingressNginxFlags { return ingressNginxFlags{true, true, true} }

func runIngressNginx(t *testing.T, command, cm, ing string, flags ingressNginxFlags, from, to string, extra ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	cmPath, ingPath := filepath.Join(dir, "configmap.yaml"), filepath.Join(dir, "ingresses.yaml")
	for path, raw := range map[string]string{cmPath: cm, ingPath: ing} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{command, "project", "--project", "ingress-nginx", "--ingress-nginx-configmap", cmPath, "--ingress-nginx-ingresses", ingPath, "--from", from, "--to", to}
	if command == "check" {
		args = append(args, "--now", "2026-11-18T13:00:00Z", "--format", "json")
	}
	if flags.configMapComplete {
		args = append(args, "--configmap-complete")
	}
	if flags.setComplete {
		args = append(args, "--ingress-set-complete")
	}
	if flags.scope {
		args = append(args, "--ingress-scope-declared")
	}
	args = append(args, extra...)
	var out, stderr bytes.Buffer
	exit := Run(t.Context(), args, &out, &stderr, "test")
	return exit, out.String(), stderr.String()
}

func assertNoIngressNginxCanary(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, canary := range ingressNginxCanaries {
			if strings.Contains(output, canary) {
				t.Fatalf("output echoes %s: %s", canary, output)
			}
		}
	}
}

func TestIngressNginxSnippetRuleEndToEnd(t *testing.T) {
	snippet, plain := ingressNginxIngress(ingressNginxSnippetAnnotation), ingressNginxIngress("    example.com/other: x\n")
	all := ingressNginxAllFlags()
	noCM, noSet, noScope := all, all, all
	noCM.configMapComplete, noSet.setComplete, noScope.scope = false, false, false
	for _, tc := range []struct {
		name, cm, ing string
		flags         ingressNginxFlags
		from, to      string
		wantExit      int
		wantStatus    string // empty: no claim expected
	}{
		// Positive: the cluster-tested break, at every level below Critical.
		{"blocked-high", ingressNginxConfigMap(`"true"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-medium", ingressNginxConfigMap(`"true"`, `"Medium"`), snippet, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-low", ingressNginxConfigMap(`"true"`, `"Low"`), snippet, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-default-level-complete-configmap", ingressNginxConfigMap(`"true"`, ``), snippet, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-set-incomplete-presence-decisive", ingressNginxConfigMap(`"true"`, `"High"`), snippet, noSet, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-json-input", ingressNginxConfigMap(`"true"`, `"High"`), `{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"PRIVATE_NAME","annotations":{"nginx.ingress.kubernetes.io/configuration-snippet":"CANARY_SNIPPET_BODY"}}}`, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-leading-empty-documents", ingressNginxConfigMap(`"true"`, `"High"`), "---\n# Source: x\n---\n" + snippet, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-second-ingress-has-it", ingressNginxConfigMap(`"true"`, `"High"`), plain + "---\n" + snippet, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		{"blocked-unreadable-sibling-presence-decisive", ingressNginxConfigMap(`"true"`, `"High"`), ingressNginxIngress("    - not-a-map\n") + "---\n" + snippet, all, "1.10.0", "1.15.0", ExitBlocked, "BLOCKED"},
		// PASS only with every declaration.
		{"pass-no-snippet-all-declared", ingressNginxConfigMap(`"true"`, `"High"`), plain, all, "1.10.0", "1.15.0", ExitOK, "PASS"},
		{"pass-snippet-like-keys-not-counted", ingressNginxConfigMap(`"true"`, `"High"`), ingressNginxIngress("    nginx.ingress.kubernetes.io/server-snippet: x\n    nginx.ingress.kubernetes.io/configuration-snippet-x: x\n    example.com/nginx.ingress.kubernetes.io/configuration-snippet: x\n    Nginx.Ingress.Kubernetes.Io/Configuration-Snippet: x\n"), all, "1.10.0", "1.15.0", ExitOK, "PASS"},
		{"pass-annotations-null", ingressNginxConfigMap(`"true"`, `"High"`), "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: x\n  annotations:\n", all, "1.10.0", "1.15.0", ExitOK, "PASS"},
		{"unknown-no-snippet-set-incomplete", ingressNginxConfigMap(`"true"`, `"High"`), plain, noSet, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		// I3: without the scope declaration neither BLOCKED nor PASS.
		{"unknown-snippet-scope-undeclared", ingressNginxConfigMap(`"true"`, `"High"`), snippet, noScope, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-plain-scope-undeclared", ingressNginxConfigMap(`"true"`, `"High"`), plain, noScope, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		// Rule not applicable.
		{"unknown-critical-level", ingressNginxConfigMap(`"true"`, `"Critical"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-false", ingressNginxConfigMap(`"false"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-absent-complete-is-false", ingressNginxConfigMap(``, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		// Absent keys need the complete declaration.
		{"unknown-allow-absent-incomplete", ingressNginxConfigMap(``, `"High"`), snippet, noCM, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-level-absent-incomplete", ingressNginxConfigMap(`"true"`, ``), snippet, noCM, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		// Exact tokens only.
		{"unknown-allow-TRUE", ingressNginxConfigMap(`"TRUE"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-True", ingressNginxConfigMap(`"True"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-leading-space", ingressNginxConfigMap(`" true"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-trailing-newline", ingressNginxConfigMap(`"true\n"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-one", ingressNginxConfigMap(`"1"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-empty", ingressNginxConfigMap(`""`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-unquoted-bool", ingressNginxConfigMap(`true`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-allow-templated", ingressNginxConfigMap(`"{{ .Values.x }}"`, `"High"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-level-lowercase", ingressNginxConfigMap(`"true"`, `"high"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-level-uppercase", ingressNginxConfigMap(`"true"`, `"HIGH"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-level-trailing-space", ingressNginxConfigMap(`"true"`, `"High "`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-level-other-token", ingressNginxConfigMap(`"true"`, `"Severe"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-level-empty", ingressNginxConfigMap(`"true"`, `""`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		// I4: input shapes.
		{"unknown-duplicate-allow-key", strings.Replace(ingressNginxConfigMap(`"false"`, `"High"`), "  allow-snippet-annotations: \"false\"\n", "  allow-snippet-annotations: \"false\"\n  allow-snippet-annotations: \"true\"\n", 1), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-duplicate-level-key", strings.Replace(ingressNginxConfigMap(`"true"`, `"Critical"`), "  annotations-risk-level: \"Critical\"\n", "  annotations-risk-level: \"Critical\"\n  annotations-risk-level: \"High\"\n", 1), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-configmap-is-secret", strings.Replace(ingressNginxConfigMap(`"true"`, `"High"`), "kind: ConfigMap", "kind: Secret", 1), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-configmap-wrong-apiversion", strings.Replace(ingressNginxConfigMap(`"true"`, `"High"`), "apiVersion: v1", "apiVersion: v2", 1), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-configmap-two-documents", ingressNginxConfigMap(`"true"`, `"High"`) + "---\n" + ingressNginxConfigMap(`"false"`, `"Critical"`), snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-configmap-binarydata-holds-key", ingressNginxConfigMap(``, `"High"`) + "  allow-snippet-annotations: Q0FOQVJZ\n", snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-configmap-not-yaml", "{{ not yaml", snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-file-has-secret", ingressNginxConfigMap(`"true"`, `"High"`), snippet + "---\napiVersion: v1\nkind: Secret\ndata:\n  password: CANARY_SECRET\n", all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-file-secret-first-invalid-body", ingressNginxConfigMap(`"true"`, `"High"`), "apiVersion: v1\nkind: Secret\ndata: [CANARY_SECRET\n---\n" + snippet, all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-list", ingressNginxConfigMap(`"true"`, `"High"`), "apiVersion: networking.k8s.io/v1\nkind: IngressList\nitems: []\n", all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-old-apiversion", ingressNginxConfigMap(`"true"`, `"High"`), strings.Replace(snippet, "networking.k8s.io/v1", "extensions/v1beta1", 1), all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-kind-lowercase", ingressNginxConfigMap(`"true"`, `"High"`), strings.Replace(snippet, "kind: Ingress", "kind: ingress", 1), all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-duplicate-snippet-key", ingressNginxConfigMap(`"true"`, `"High"`), ingressNginxIngress(ingressNginxSnippetAnnotation + ingressNginxSnippetAnnotation), all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-annotations-wrong-type", ingressNginxConfigMap(`"true"`, `"High"`), ingressNginxIngress("    - not-a-map\n"), all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-annotations-alias", ingressNginxConfigMap(`"true"`, `"High"`), "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: x\n  annotations: &a\n    k: v\n", all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-annotations-merge-key", ingressNginxConfigMap(`"true"`, `"High"`), ingressNginxIngress("    <<: {k: v}\n"), all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-no-metadata", ingressNginxConfigMap(`"true"`, `"High"`), "apiVersion: networking.k8s.io/v1\nkind: Ingress\n", all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		{"unknown-ingress-file-only-empty-documents", ingressNginxConfigMap(`"true"`, `"High"`), "---\n---\n# nothing\n", all, "1.10.0", "1.15.0", ExitUnknown, "UNKNOWN"},
		// Exact pair only.
		{"no-claim-wrong-target", ingressNginxConfigMap(`"true"`, `"High"`), snippet, all, "1.10.0", "1.14.0", ExitUnknown, ""},
		{"no-claim-wrong-origin-patch", ingressNginxConfigMap(`"true"`, `"High"`), snippet, all, "1.10.1", "1.15.0", ExitUnknown, ""},
		{"no-claim-reverse", ingressNginxConfigMap(`"true"`, `"High"`), snippet, all, "1.15.0", "1.10.0", ExitUnknown, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, out, stderr := runIngressNginx(t, "check", tc.cm, tc.ing, tc.flags, tc.from, tc.to)
			assertNoIngressNginxCanary(t, out, stderr)
			if exit != tc.wantExit {
				t.Fatalf("exit=%d want=%d stdout=%s stderr=%s", exit, tc.wantExit, out, stderr)
			}
			var report projectcheck.Report
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("report: %v\n%s", err, out)
			}
			if tc.wantStatus == "" {
				if len(report.Check.Claims) != 0 {
					t.Fatalf("unreviewed pair produced a claim: %s", out)
				}
				return
			}
			if len(report.Check.Claims) != 1 || report.Check.Claims[0].RuleID != ingressNginxRuleID || report.Check.Claims[0].Status != tc.wantStatus {
				t.Fatalf("claims=%+v want %s", report.Check.Claims, tc.wantStatus)
			}
		})
	}
}

func TestIngressNginxPrepareNeverRetainsInputValues(t *testing.T) {
	for _, tc := range []struct{ name, cm, ing string }{
		{"decided", ingressNginxConfigMap(`"true"`, `"High"`), ingressNginxIngress(ingressNginxSnippetAnnotation)},
		{"secret-document", ingressNginxConfigMap(`"true"`, `"High"`), "apiVersion: v1\nkind: Secret\nstringData:\n  password: CANARY_SECRET\n"},
		{"broken", "kind: ConfigMap\n  CANARY_CM_VALUE: [", "{CANARY_SNIPPET_BODY"},
	} {
		for _, format := range []string{"input", "json", "human"} {
			t.Run(tc.name+"-"+format, func(t *testing.T) {
				exit, out, stderr := runIngressNginx(t, "prepare", tc.cm, tc.ing, ingressNginxAllFlags(), "1.10.0", "1.15.0", "--format", format)
				if exit != ExitOK && exit != ExitUnknown {
					t.Fatalf("exit=%d stderr=%s", exit, stderr)
				}
				assertNoIngressNginxCanary(t, out, stderr)
				if format == "input" && !strings.Contains(out, "component.ingress_nginx.configuration_snippet_annotation_present") {
					t.Fatalf("input lacks the fact: %s", out)
				}
			})
		}
	}
}

func TestIngressNginxDigestPinsAndFlagExclusivity(t *testing.T) {
	cm, ing := ingressNginxConfigMap(`"true"`, `"High"`), ingressNginxIngress(ingressNginxSnippetAnnotation)
	wrong := "sha256:" + strings.Repeat("0", 64)
	if exit, out, stderr := runIngressNginx(t, "check", cm, ing, ingressNginxAllFlags(), "1.10.0", "1.15.0", "--ingress-nginx-configmap-digest", wrong); exit != ExitIntegrity {
		t.Fatalf("configmap pin: exit=%d out=%s stderr=%s", exit, out, stderr)
	}
	if exit, out, stderr := runIngressNginx(t, "check", cm, ing, ingressNginxAllFlags(), "1.10.0", "1.15.0", "--ingress-nginx-ingresses-digest", wrong); exit != ExitIntegrity {
		t.Fatalf("ingress pin: exit=%d out=%s stderr=%s", exit, out, stderr)
	}
	if exit, _, _ := runIngressNginx(t, "check", cm, ing, ingressNginxAllFlags(), "1.10.0", "1.15.0", "--ingress-nginx-ingresses-digest", "not-a-digest"); exit != ExitUsage {
		t.Fatalf("malformed pin: exit=%d", exit)
	}
	// Flags of another route are refused, not ignored.
	for _, extra := range [][]string{{"--effective-config", "x"}, {"--workload", "x"}, {"--mariadb-resource", "x"}, {"--resource-complete"}, {"--knowledge-db", "x"}, {"--precedence-resolved"}, {"--upstream-distribution"}} {
		if exit, _, _ := runIngressNginx(t, "check", cm, ing, ingressNginxAllFlags(), "1.10.0", "1.15.0", extra...); exit != ExitUsage {
			t.Fatalf("%v accepted: exit=%d", extra, exit)
		}
	}
	// The ingress flags belong to the ingress-nginx project only.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("x: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, extra := range [][]string{{"--ingress-nginx-configmap", path}, {"--ingress-nginx-ingresses", path}, {"--configmap-complete"}, {"--ingress-set-complete"}, {"--ingress-scope-declared"}, {"--ingress-nginx-configmap-digest", wrong}} {
		args := append([]string{"check", "project", "--project", "grafana", "--effective-config", path, "--from", "10.4.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", "2026-11-18T13:00:00Z"}, extra...)
		var out, stderr bytes.Buffer
		if exit := Run(t.Context(), args, &out, &stderr, "test"); exit != ExitUsage {
			t.Fatalf("%v accepted for another project: exit=%d", extra, exit)
		}
	}
	// Both files are required.
	var out, stderr bytes.Buffer
	args := []string{"check", "project", "--project", "ingress-nginx", "--ingress-nginx-configmap", path, "--from", "1.10.0", "--to", "1.15.0", "--now", "2026-11-18T13:00:00Z"}
	if exit := Run(t.Context(), args, &out, &stderr, "test"); exit != ExitUsage {
		t.Fatalf("missing ingresses file accepted: exit=%d", exit)
	}
}
