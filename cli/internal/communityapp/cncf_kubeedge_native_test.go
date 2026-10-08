// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func keadmInitArgvFile(t *testing.T, name string, tokens ...string) string {
	t.Helper()
	raw, err := json.Marshal(tokens)
	if err != nil {
		t.Fatal(err)
	}
	return writeCNCFFile(t, name, raw, 0o600)
}

func kubeEdgeNativeArgs(path, from, to, distribution, argvComplete string) []string {
	args := []string{
		"check", "cncf", "--project", "kubeedge", "--keadm-init-argv", path,
		"--from", from, "--to", to,
	}
	if distribution != "" {
		args = append(args, "--kubeedge-distribution", distribution)
	}
	if argvComplete != "" {
		args = append(args, "--keadm-argv-complete", argvComplete)
	}
	return append(args, "--now", "2026-09-19T00:00:00Z", "--format", "json")
}

// The native one-step route derives the reviewed init version-selector form
// from one caller-declared effective keadm init argv. It authors no new
// compatibility claim: the reviewed rule's own fact description states the
// whole grammar, and the pinned v1.18 install path, v1.18 --profile flag help,
// v1.19 install path and v1.19 release note establish each accepted form.
func TestKubeEdgeInitArgvNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		tokens []string
		status string
		want   int
	}{
		{"legacy profile version selector blocks", []string{"keadm", "init", "--advertise-address=10.0.0.9", "--profile", "version=v1.19.0"}, "BLOCKED", ExitBlocked},
		{"attached legacy profile version selector blocks", []string{"keadm", "init", "--profile=version=v1.19.0"}, "BLOCKED", ExitBlocked},
		{"explicit target version flag with absent profile passes", []string{"keadm", "init", "--kubeedge-version=v1.19.0", "--kube-config=/private/kube/config"}, "PASS", ExitOK},
		{"external profile values file stays unknown", []string{"keadm", "init", "--profile", "/private/version.yaml"}, "UNKNOWN", ExitUnknown},
		{"both selectors stay unknown", []string{"keadm", "init", "--profile", "version=v1.19.0", "--kubeedge-version=v1.19.0"}, "UNKNOWN", ExitUnknown},
		{"neither selector stays unknown", []string{"keadm", "init", "--advertise-address=10.0.0.9"}, "UNKNOWN", ExitUnknown},
		{"another keadm subcommand stays unknown", []string{"keadm", "join", "--profile", "version=v1.19.0"}, "UNKNOWN", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := keadmInitArgvFile(t, "keadm-init-argv.json", test.tokens...)
			code, stdout, stderr := runCNCFCLI(t, kubeEdgeNativeArgs(path, "1.18.0", "1.19.0", "official_upstream", "true")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, secret := range []string{"10.0.0.9", "/private/kube/config", "/private/version.yaml"} {
				if strings.Contains(stdout, secret) {
					t.Fatalf("private argv fragment %q echoed: %q", secret, stdout)
				}
			}
		})
	}
}

// The scoped PASS requires both caller declarations; neither is inferred.
func TestKubeEdgeInitArgvNativeCheck_GuardsAreNeverInferred(t *testing.T) {
	t.Parallel()
	path := keadmInitArgvFile(t, "keadm-init-argv.json", "keadm", "init", "--kubeedge-version=v1.19.0")
	for _, test := range []struct {
		name                       string
		distribution, argvComplete string
		status                     string
		want                       int
	}{
		{"custom build stays unknown", "custom_build", "true", "UNKNOWN", ExitUnknown},
		{"incomplete argv stays unknown", "official_upstream", "false", "UNKNOWN", ExitUnknown},
		{"complete official argv passes", "official_upstream", "true", "PASS", ExitOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, kubeEdgeNativeArgs(path, "1.18.0", "1.19.0", test.distribution, test.argvComplete)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestKubeEdgeInitArgvNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	path := keadmInitArgvFile(t, "keadm-init-argv-clean.json", "keadm", "init", "--kubeedge-version=v1.19.0")
	code, stdout, stderr := runCNCFCLI(t, kubeEdgeNativeArgs(path, "1.18.0", "1.19.0", "official_upstream", "true")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

func TestKubeEdgeInitArgvNativeCheck_RejectsWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	path := keadmInitArgvFile(t, "keadm-init-argv.json", "keadm", "init", "--profile", "version=v1.19.0")
	code, stdout, stderr := runCNCFCLI(t, kubeEdgeNativeArgs(path, "1.18.1", "1.19.0", "official_upstream", "true")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--keadm-init-argv", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubeedge", "--keadm-init-argv", path, "--from", "1.18.0", "--to", "1.19.0", "--kubeedge-distribution", "unreviewed", "--keadm-argv-complete", "true", "--now", "2026-09-19T00:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("bad distribution code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKubeEdgeInitArgvNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	path := keadmInitArgvFile(t, "keadm-init-argv.json", "keadm", "init", "--profile", "version=v1.19.0")
	other, err := json.Marshal([]string{"keadm", "init", "--kubeedge-version=v1.19.0"})
	if err != nil {
		t.Fatal(err)
	}
	args := append(kubeEdgeNativeArgs(path, "1.18.0", "1.19.0", "official_upstream", "true"), "--keadm-init-argv-digest", cncfDigest(other))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// The native route and the hand-authored canonical declaration reach the same
// scoped outcome for the same reviewed rule.
func TestKubeEdgeInitArgvNativeCheckMatchesCanonicalDeclaration(t *testing.T) {
	t.Parallel()
	path := keadmInitArgvFile(t, "keadm-init-argv.json", "keadm", "init", "--profile", "version=v1.19.0")
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, kubeEdgeNativeArgs(path, "1.18.0", "1.19.0", "official_upstream", "true")...)
	if nativeCode != ExitBlocked || nativeErr != "" || !strings.Contains(nativeReport, `"ruleId":"kubeedge.keadm-init-profile-version-selector.1-18-to-1-19"`) || !strings.Contains(nativeReport, `"status":"BLOCKED"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
	declared := kubeEdgeExampleDeclaration(t, "declared", "legacy_profile_version", true, "official_upstream", "keadm_init", "1.18.0")
	declaredCode, declaredReport, declaredErr := runKubeEdgeDeclaration(t, declared)
	if declaredCode != nativeCode || declaredErr != "" || !strings.Contains(declaredReport, `"status":"BLOCKED"`) {
		t.Fatalf("declared code=%d stdout=%q stderr=%q", declaredCode, declaredReport, declaredErr)
	}
}
