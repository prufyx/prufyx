// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

func argoCDLatestNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "argo-cd", "--repository-secret", path,
		"--from", from, "--to", to,
		"--repository-distribution", "official_upstream", "--repository-settings-resolved", "true", "--repository-uses-plain-http", "true",
		"--now", "2026-09-19T00:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed
// PrepareArgoCDLatestRepository adapter; this exercises it end to end for
// the 3.4.8 -> 3.5.2 pair without a separate prepare step. It authors no new
// compatibility claim: the preparer already existed and evaluated all five
// reviewed origins before this route was wired.
func TestArgoCDLatestNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	blocked := writeCNCFFile(t, "argocd-repository-blocked.json", []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"false","insecure":"false"}}`), 0o600)
	code, stdout, stderr := runCNCFCLI(t, argoCDLatestNativeArgs(blocked, "3.4.8", "3.5.2")...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, blocked) || strings.Contains(stdout, "private-repository") {
		t.Fatalf("blocked code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	clean := writeCNCFFile(t, "argocd-repository-clear.json", []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"true","insecure":"false"}}`), 0o600)
	code, stdout, stderr = runCNCFCLI(t, argoCDLatestNativeArgs(clean, "3.4.8", "3.5.2")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("clear code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 3.5.2 latest-target origins are routed through the same
// native path.
func TestArgoCDLatestNativeCheck_AllOriginsAreRouted(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"3.0.23", "3.1.16", "3.2.12", "3.3.14", "3.4.8"} {
		t.Run(from, func(t *testing.T) {
			blocked := writeCNCFFile(t, "argocd-repository-latest-blocked.json", []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"false","insecure":"false"}}`), 0o600)
			code, stdout, stderr := runCNCFCLI(t, argoCDLatestNativeArgs(blocked, from, "3.5.2")...)
			if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) {
				t.Fatalf("from=%s blocked code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
		})
	}
}

func TestArgoCDLatestNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "argocd-repository.json", []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"true","insecure":"false"}}`), 0o600)
	code, stdout, stderr := runCNCFCLI(t, argoCDLatestNativeArgs(path, "3.4.8", "3.5.3")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestArgoCDLatestNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "argocd-repository.json", []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"false","insecure":"false"}}`), 0o600)
	args := append(argoCDLatestNativeArgs(path, "3.4.8", "3.5.2"), "--repository-secret-digest", cncfDigest([]byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"other","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"true","insecure":"false"}}`)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestArgoCDLatestPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"private-repository","labels":{"argocd.argoproj.io/secret-type":"repository"}},"stringData":{"type":"helm","enableOCI":"true","url":"charts.example.invalid/team","insecureOCIForceHttp":"false","insecure":"false"}}`)
	path := writeCNCFFile(t, "argocd-repository.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "argo-cd", "--input", path, "--from", "3.4.8", "--to", "3.5.2", "--distribution", "official_upstream", "--repository-settings-resolved", "true", "--repository-uses-plain-http", "true", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.argo_cd.plain_http_oci_repository_unusable") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "argocd-repository-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "argo-cd", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, argoCDLatestNativeArgs(path, "3.4.8", "3.5.2")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
