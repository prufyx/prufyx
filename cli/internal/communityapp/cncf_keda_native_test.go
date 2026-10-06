// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const kedaExternalNoCertFileInput = `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"scaleTargetRef":{"name":"private-workload"},"triggers":[{"type":"external","metadata":{"scalerAddress":"private-scaler.svc:9090"}}]}}`
const kedaExternalWithCertFileInput = `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"scaleTargetRef":{"name":"private-workload"},"triggers":[{"type":"external","metadata":{"scalerAddress":"private-scaler.svc:9090","tlsCertFile":"/etc/private-certs/tls.crt"}}]}}`

func kedaNativeArgs(path string, declaration ...string) []string {
	args := []string{
		"check", "cncf", "--project", "keda", "--keda-scaled-object", path,
		"--keda-scaled-object-complete",
		"--from", "2.16.0", "--to", "2.17.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
	if len(declaration) == 1 {
		args = append(args, "--keda-legacy-tls-transport-required", declaration[0])
	}
	return args
}

func TestKEDANativeScaledObjectCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw, reason string
		declaration       []string
		want              int
	}{
		{"declared reliance blocks", kedaExternalWithCertFileInput, "REVIEWED_SOURCE_CONSTRAINT", []string{"true"}, ExitBlocked},
		{"no cert file passes", kedaExternalNoCertFileInput, "REVIEWED_SOURCE_CONSTRAINT", nil, ExitOK},
		{"forwarded metadata declared not required passes", kedaExternalWithCertFileInput, "REVIEWED_SOURCE_CONSTRAINT", []string{"false"}, ExitOK},
		{"cert file present without declaration stays unknown", kedaExternalWithCertFileInput, "RULE_FACT_UNAVAILABLE", nil, ExitUnknown},
		{"conflicting declaration stays unknown", kedaExternalNoCertFileInput, "RULE_FACT_UNAVAILABLE", []string{"true"}, ExitUnknown},
		{"no external scaler stays unknown", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"triggers":[{"type":"cpu","metadata":{"value":"60"}}]}}`, "RULE_APPLICABILITY_NOT_MATCHED", nil, ExitUnknown},
		{"scaled job surface stays unknown", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledJob","metadata":{"name":"private-scaler"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"a"}}]}}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", nil, ExitUnknown},
		{"unreviewed served version stays unknown", `{"apiVersion":"keda.sh/v1beta1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"a"}}]}}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", nil, ExitUnknown},
		{"unresolved rendering stays unknown", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"{{ .Values.addr }}"}}]}}`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", nil, ExitUnknown},
		{"unparseable shape stays unknown", `[` + kedaExternalNoCertFileInput + `]`, "RULE_APPLICABILITY_FACT_UNAVAILABLE", nil, ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "keda.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, kedaNativeArgs(path, test.declaration...)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestKEDANativeScaledObjectCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "keda.json", []byte(kedaExternalNoCertFileInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, kedaNativeArgs(path)...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// A tlsCertFile metadata field is explicitly not sufficient for the reviewed
// condition fact, so this route must never turn its presence into a BLOCKED
// claim on its own.
func TestKEDANativeScaledObjectCheck_PresenceAloneNeverBlocks(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "keda.json", []byte(kedaExternalWithCertFileInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, kedaNativeArgs(path)...)
	if code != ExitUnknown || stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, `"status":"BLOCKED"`) || strings.Contains(stdout, `"status":"PASS"`) {
		t.Fatalf("presence alone resolved the condition: %q", stdout)
	}
}

func TestKEDANativeScaledObjectCheck_UndeclaredSelectionScopeStaysUnknown(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "keda.json", []byte(kedaExternalNoCertFileInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "keda", "--keda-scaled-object", path, "--from", "2.16.0", "--to", "2.17.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_APPLICABILITY") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stdout, `"status":"PASS"`) {
		t.Fatalf("an undeclared selection scope produced a PASS: %q", stdout)
	}
}

func TestKEDANativeScaledObjectCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "keda.json", []byte(kedaExternalWithCertFileInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "keda", "--keda-scaled-object", path, "--keda-scaled-object-complete", "--keda-legacy-tls-transport-required", "true", "--from", "2.16.0", "--to", "2.18.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "keda", "--keda-scaled-object", path, "--keda-scaled-object-complete", "--keda-legacy-tls-transport-required", "yes", "--from", "2.16.0", "--to", "2.17.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("bad declaration token code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--keda-scaled-object", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "keda", "--keda-scaled-object", path, "--native-resource", path, "--keda-scaled-object-complete", "--from", "2.16.0", "--to", "2.17.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKEDANativeScaledObjectCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "keda.json", []byte(kedaExternalWithCertFileInput), 0o600)
	args := append(kedaNativeArgs(path, "true"), "--keda-scaled-object-digest", cncfDigest([]byte(kedaExternalNoCertFileInput)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKEDAPrepareScaledObjectFeedsCheck(t *testing.T) {
	t.Parallel()
	raw := []byte(kedaExternalWithCertFileInput)
	path := writeCNCFFile(t, "keda.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "keda", "--keda-scaled-object", path, "--keda-scaled-object-digest", cncfDigest(raw), "--keda-scaled-object-complete", "--keda-legacy-tls-transport-required", "true", "--from", "2.16.0", "--to", "2.17.0", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.keda.legacy_tls_cert_file_required_for_transport") || strings.Contains(canonical, "private-") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "keda-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "keda", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}
