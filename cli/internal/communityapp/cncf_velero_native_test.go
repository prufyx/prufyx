// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const veleroBackupCRDDocument = `{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"backups.velero.io"},"spec":{"group":"velero.io","scope":"Namespaced"}}`
const veleroServerDeploymentDocument = `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"private-server","namespace":"private-ns"},"spec":{"replicas":1}}`
const veleroServiceAccountDocument = `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"private-sa","namespace":"private-ns"}}`

func veleroPlanDocument(items ...string) string {
	return `{"apiVersion":"v1","kind":"List","items":[` + strings.Join(items, ",") + `]}`
}

func veleroNativeArgs(path, from string) []string {
	return []string{
		"check", "cncf", "--project", "velero", "--upgrade-plan", path,
		"--velero-server-deployment", "private-server", "--velero-plan-order-declared",
		"--from", from, "--to", "1.18.0", "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

func TestVeleroNativeCRDOrderCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"crds after server blocks", veleroPlanDocument(veleroServerDeploymentDocument, veleroBackupCRDDocument), "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"crds before server passes", veleroPlanDocument(veleroBackupCRDDocument, veleroServerDeploymentDocument), "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"unrelated kinds keep the order", veleroPlanDocument(veleroServiceAccountDocument, veleroBackupCRDDocument, veleroServerDeploymentDocument), "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"absent crd documents stay unknown", veleroPlanDocument(veleroServiceAccountDocument, veleroServerDeploymentDocument), "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unresolved server selection stays unknown", veleroPlanDocument(veleroBackupCRDDocument, veleroServiceAccountDocument), "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unresolved rendering stays unknown", veleroPlanDocument(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"{{ .Release.Name }}"}}`), "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"pagination stays unknown", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[` + veleroBackupCRDDocument + `,` + veleroServerDeploymentDocument + `]}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "velero.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, veleroNativeArgs(path, "1.17.0")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestVeleroNativeCRDOrderCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "velero.json", []byte(veleroPlanDocument(veleroBackupCRDDocument, veleroServerDeploymentDocument)), 0o600)
	code, stdout, stderr := runCNCFCLI(t, veleroNativeArgs(path, "1.17.0")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// The reviewed 1.16.2 -> 1.18.0 intermediate-version gate is not bypassable by
// any native input: even the plan that scores a scoped PASS at 1.17.0 -> 1.18.0
// stays BLOCKED on the direct pair.
func TestVeleroNativeIntermediateVersionGateIsNotBypassable(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "velero.json", []byte(veleroPlanDocument(veleroBackupCRDDocument, veleroServerDeploymentDocument)), 0o600)
	code, stdout, stderr := runCNCFCLI(t, veleroNativeArgs(path, "1.16.2")...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"status":"BLOCKED"`) || !strings.Contains(stdout, "velero.intermediate-1-17.1-18") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, `"status":"PASS"`) {
		t.Fatalf("intermediate pair leaked a PASS: %q", stdout)
	}
}

func TestVeleroNativeCRDOrderCheck_UndeclaredPlanOrderOrServerStaysUnknown(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "velero.json", []byte(veleroPlanDocument(veleroBackupCRDDocument, veleroServerDeploymentDocument)), 0o600)
	for _, test := range []struct {
		name   string
		mutate func([]string) []string
	}{
		{"plan order not declared", func(args []string) []string {
			for index, value := range args {
				if value == "--velero-plan-order-declared" {
					return append(args[:index:index], args[index+1:]...)
				}
			}
			return args
		}},
		{"server not selected", func(args []string) []string {
			for index, value := range args {
				if value == "--velero-server-deployment" {
					return append(args[:index:index], args[index+2:]...)
				}
			}
			return args
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, test.mutate(veleroNativeArgs(path, "1.17.0"))...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_FACT_UNAVAILABLE") || strings.Contains(stdout, `"status":"PASS"`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestVeleroNativeCRDOrderCheck_RejectsWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	selected := writeCNCFFile(t, "velero.json", []byte(veleroPlanDocument(veleroBackupCRDDocument, veleroServerDeploymentDocument)), 0o600)
	args := veleroNativeArgs(selected, "1.17.0")
	for index := range args {
		if args[index] == "1.18.0" {
			args[index] = "1.18.1"
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--upgrade-plan", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "velero", "--upgrade-plan", selected, "--native-resource", selected, "--velero-server-deployment", "private-server", "--velero-plan-order-declared", "--from", "1.17.0", "--to", "1.18.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestVeleroNativeCRDOrderCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	raw := []byte(veleroPlanDocument(veleroBackupCRDDocument, veleroServerDeploymentDocument))
	path := writeCNCFFile(t, "velero.json", raw, 0o600)
	args := append(veleroNativeArgs(path, "1.17.0"), "--upgrade-plan-digest", cncfDigest([]byte(veleroPlanDocument(veleroServerDeploymentDocument, veleroBackupCRDDocument))))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "PASS") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestVeleroPrepareUpgradePlanFeedsCheck(t *testing.T) {
	t.Parallel()
	raw := []byte(veleroPlanDocument(veleroServerDeploymentDocument, veleroBackupCRDDocument))
	path := writeCNCFFile(t, "velero.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "velero", "--upgrade-plan", path, "--upgrade-plan-digest", cncfDigest(raw), "--from", "1.17.0", "--to", "1.18.0", "--velero-server-deployment", "private-server", "--velero-plan-order-declared", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.velero.crd_update_before_server") || strings.Contains(canonical, "private-") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "velero-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "velero", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitBlocked || stderr != "" || !strings.Contains(report, `"status":"BLOCKED"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
}
