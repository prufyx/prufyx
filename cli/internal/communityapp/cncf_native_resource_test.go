// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCNCFNativeResourceExamplesUseDirectRawFiles(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "examples", "cncf", "native-resources")
	read := func(parts ...string) string {
		t.Helper()
		path := filepath.Join(append([]string{root}, parts...)...)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return writeCNCFFile(t, filepath.Base(path), raw, 0o600)
	}
	for _, test := range []struct {
		project, from, to, directory string
		now                          string
		want                         int
	}{
		{"metallb", "0.12.1", "0.13.2", "metallb", "2026-09-11T18:00:00Z", ExitBlocked},
		{"contour", "1.19.0", "1.20.0", "contour", "2026-09-11T18:00:00Z", ExitBlocked},
		{"kubevirt", "1.8.4", "1.9.0", "kubevirt", "2026-09-11T18:00:00Z", ExitBlocked},
		{"thanos", "0.41.0", "0.42.0", "thanos", "2026-09-11T18:00:00Z", ExitBlocked},
		{"cortex", "1.17.2", "1.21.1", "cortex", "2026-09-11T23:00:00Z", ExitBlocked},
	} {
		t.Run(test.project, func(t *testing.T) {
			for name, want := range map[string]int{"broken.json": test.want, "fixed.json": ExitOK, "unknown.json": ExitUnknown} {
				path := read(test.directory, name)
				code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", test.project, "--native-resource", path, "--from", test.from, "--to", test.to, "--now", test.now, "--format", "json")
				if code != want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
					t.Fatalf("%s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
				}
			}
		})
	}
	for name, want := range map[string]int{"broken": ExitBlocked, "fixed": ExitOK, "unknown": ExitUnknown} {
		current := read("cloudnativepg", "current-"+name+".json")
		proposed := read("cloudnativepg", "proposed-"+name+".json")
		code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cloudnativepg", "--current-resource", current, "--resource", proposed, "--from", "1.29.0", "--to", "1.30.0", "--now", "2026-09-11T18:00:00Z", "--format", "json")
		if code != want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
			t.Fatalf("cloudnativepg %s code=%d stdout=%q stderr=%q", name, code, stdout, stderr)
		}
	}
}

func TestCNCFNativeResourceChecksPrepareAndEvaluateInMemory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, project, from, to string
		current, proposed       []byte
		wantCode                int
		args                    func(currentPath, proposedPath string) []string
	}{
		{
			name: "metallb legacy configmap", project: "metallb", from: "0.12.1", to: "0.13.2",
			wantCode: ExitBlocked,
			proposed: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"metallb-system"},"data":{"config":"address-pools: []"}}`),
			args: func(_, proposed string) []string {
				return []string{"check", "cncf", "--project", "metallb", "--native-resource", proposed, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z", "--format", "json"}
			},
		},
		{
			name: "contour reviewed target group", project: "contour", from: "1.19.0", to: "1.20.0",
			wantCode: ExitOK,
			proposed: []byte(`{"apiVersion":"gateway.networking.k8s.io/v1alpha2","kind":"HTTPRoute","metadata":{"name":"route","namespace":"edge"},"spec":{}}`),
			args: func(_, proposed string) []string {
				return []string{"check", "cncf", "--project", "contour", "--native-resource", proposed, "--from", "1.19.0", "--to", "1.20.0", "--now", "2026-09-11T18:00:00Z", "--format", "json"}
			},
		},
		{
			name: "cloudnativepg changed reference", project: "cloudnativepg", from: "1.29.0", to: "1.30.0",
			wantCode: ExitBlocked,
			current:  []byte(`{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"name":"app","namespace":"db","uid":"opaque"},"spec":{"cluster":{"name":"old"}},"status":{"opaque":true}}`),
			proposed: []byte(`{"apiVersion":"postgresql.cnpg.io/v1","kind":"Database","metadata":{"name":"app","namespace":"db"},"spec":{"cluster":{"name":"new"}}}`),
			args: func(current, proposed string) []string {
				return []string{"check", "cncf", "--project", "cloudnativepg", "--current-resource", current, "--resource", proposed, "--from", "1.29.0", "--to", "1.30.0", "--now", "2026-09-11T18:00:00Z", "--format", "json"}
			},
		},
		{
			name: "kubevirt missing binding", project: "kubevirt", from: "1.8.4", to: "1.9.0",
			wantCode: ExitBlocked,
			proposed: []byte(`{"apiVersion":"kubevirt.io/v1","kind":"VirtualMachineInstance","metadata":{"name":"vm","namespace":"compute"},"spec":{"domain":{"devices":{"interfaces":[{"name":"default"}]}}}}`),
			args: func(_, proposed string) []string {
				return []string{"check", "cncf", "--project", "kubevirt", "--native-resource", proposed, "--from", "1.8.4", "--to", "1.9.0", "--now", "2026-09-11T18:00:00Z", "--format", "json"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			currentPath, proposedPath := "", writeCNCFFile(t, "resource.json", test.proposed, 0o600)
			if test.current != nil {
				currentPath = writeCNCFFile(t, "current.json", test.current, 0o600)
			}
			code, stdout, stderr := runCNCFCLI(t, test.args(currentPath, proposedPath)...)
			if code != test.wantCode || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, `"networkUsed":false`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, private := range []string{"metallb-system", "address-pools", `"uid"`, `"old"`, `"new"`} {
				if strings.Contains(stdout, private) {
					t.Fatalf("private native resource content escaped: %q", private)
				}
			}
		})
	}
}

func TestCNCFNativeResourceChecksRejectCrossModeAndBadPinsBeforeEvaluation(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"metallb-system"},"data":{"config":"address-pools: []"}}`)
	path := writeCNCFFile(t, "resource.json", raw, 0o600)
	for _, args := range [][]string{
		{"check", "cncf", "--project", "metallb", "--native-resource", path, "--input", path, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z"},
		{"check", "cncf", "--project", "metallb", "--native-resource", path, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z", "--native-resource-digest", "sha256:" + strings.Repeat("0", 64)},
		{"check", "cncf", "--project", "helm", "--native-resource", path, "--now", "2026-09-11T18:00:00Z"},
		{"check", "cncf", "--project", "metallb", "--native-resource", path, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z", "--knowledge-db", ""},
		{"check", "cncf", "--project", "cloudnativepg", "--native-resource", "", "--current-resource", path, "--resource", path, "--from", "1.29.0", "--to", "1.30.0", "--now", "2026-09-11T18:00:00Z"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage && code != ExitIntegrity || stdout != "" || strings.Contains(stderr, path) || strings.Contains(stderr, "metallb-system") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestCNCFNativeResourceHumanOutputIncludesScopedVerdictAndEvidence(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"metallb-system"},"data":{"config":"address-pools: []"}}`)
	path := writeCNCFFile(t, "resource.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "metallb", "--native-resource", path, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z")
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, "BLOCKED") || !strings.Contains(stdout, "next action:") || !strings.Contains(stdout, "pinned source:") || strings.Contains(stdout, "metallb-system") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCNCFNativeResourceWrongPairAndMissingFileRemainSafeUnknownOrInputError(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"metallb.io/v1beta1","kind":"IPAddressPool","metadata":{"name":"pool","namespace":"metallb-system"},"spec":{"addresses":["192.0.2.10-192.0.2.20"]}}`)
	path := writeCNCFFile(t, "resource.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "metallb", "--native-resource", path, "--from", "0.12.1", "--to", "0.13.3", "--now", "2026-09-11T18:00:00Z", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, "RULE_TRANSITION_NOT_REVIEWED") {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	missing := filepath.Join(t.TempDir(), "missing-resource.json")
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "metallb", "--native-resource", missing, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, missing) {
		t.Fatalf("missing file code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCNCFNativeResourceExternalKnowledgeHasNoEmbeddedFallbackAndReplayPinsRawInput(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"metallb-system"},"data":{"config":"address-pools: []"}}`)
	resource := writeCNCFFile(t, "metallb.json", raw, 0o600)
	embedded := []string{"check", "cncf", "--project", "metallb", "--native-resource", resource, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z", "--format", "json"}
	code, stdout, stderr := runCNCFCLI(t, embedded...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, `"knowledgeOrigin":"embedded"`) {
		t.Fatalf("embedded code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	external := []string{"check", "cncf", "--project", "metallb", "--native-resource", resource, "--native-resource-digest", cncfDigest(raw), "--from", "0.12.1", "--to", "0.13.2", "--knowledge-db", fixture.store, "--knowledge-revision", "1", "--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest, "--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json"}
	code, original, stderr := runCNCFCLI(t, external...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || strings.Contains(original, "metallb-system") {
		t.Fatalf("external no-fallback code=%d stdout=%q stderr=%q", code, original, stderr)
	}
	report := writeCNCFFile(t, "native-report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	replay := append(append([]string(nil), external...), "--replay-report", report)
	code, stdout, stderr = runCNCFCLI(t, replay...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"mode":"historical"`) || !strings.Contains(stdout, `"status":"MATCH"`) {
		t.Fatalf("replay code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	missingRawPin := append([]string{}, external[:6]...)
	missingRawPin = append(missingRawPin, external[8:]...)
	missingRawPin = append(missingRawPin, "--replay-report", report)
	code, stdout, stderr = runCNCFCLI(t, missingRawPin...)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "external native CNCF replay requires every raw resource digest") {
		t.Fatalf("missing raw replay pin code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCNCFModeAdmissionRejectsEveryForeignSelector(t *testing.T) {
	t.Parallel()
	nativeAllowed := []string{"native-resource", "native-resource-digest", "current-resource", "current-resource-digest", "resource", "resource-digest"}
	for _, name := range []string{"input", "config-map", "python-source", "nats-config", "nats-config-digest", "image-manifest", "image-manifest-digest", "cni-configuration", "cni-configuration-digest", "operation", "effective-config", "effective-config-digest", "effective-config-complete", "diagd-argv", "diagd-argv-digest"} {
		if !cncfUnexpectedModeFlag([]string{"--native-resource=resource.json", "--" + name + "=other"}, nativeAllowed...) {
			t.Fatalf("native route accepted foreign %q", name)
		}
	}
	if cncfUnexpectedModeFlag([]string{"--native-resource", "image-manifest"}, nativeAllowed...) {
		t.Fatal("native route treated a positional path as a foreign selector")
	}
	if cncfUnexpectedModeFlag([]string{"--cni-configuration", "input.json", "--operation", "effective-config"}, "cni-configuration", "cni-configuration-digest", "operation") {
		t.Fatal("CNI route treated an operation value as a foreign selector")
	}
}

func TestCNCFDirectEmissaryAndOpenFGARoutes(t *testing.T) {
	t.Parallel()
	emissaryBroken := writeCNCFFile(t, "emissary-broken.json", []byte(`["diagd","--metrics-endpoint","https://example.invalid/metrics"]`), 0o600)
	emissaryFixed := writeCNCFFile(t, "emissary-fixed.json", []byte(`["diagd","--port","-1"]`), 0o600)
	openFGABroken := writeCNCFFile(t, "openfga-broken.json", []byte(`{"authn":{"method":"oidc","oidc":{"audience":"aud"}}}`), 0o600)
	openFGAFixed := writeCNCFFile(t, "openfga-fixed.json", []byte(`{"authn":{"method":"oidc","oidc":{"issuer":"issuer","audience":"aud"}}}`), 0o600)
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"emissary broken", []string{"check", "cncf", "--project", "emissary-ingress", "--diagd-argv", emissaryBroken, "--from", "3.10.0", "--to", "4.0.1", "--now", "2026-09-11T18:00:00Z", "--format", "json"}, ExitBlocked},
		{"emissary fixed", []string{"check", "cncf", "--project", "emissary-ingress", "--diagd-argv", emissaryFixed, "--from", "3.10.0", "--to", "4.0.1", "--now", "2026-09-11T18:00:00Z", "--format", "json"}, ExitOK},
		{"openfga broken", []string{"check", "cncf", "--project", "openfga", "--effective-config", openFGABroken, "--effective-config-complete", "--from", "1.17.1", "--to", "1.18.0", "--now", "2026-09-11T18:00:00Z", "--format", "json"}, ExitBlocked},
		{"openfga fixed", []string{"check", "cncf", "--project", "openfga", "--effective-config", openFGAFixed, "--effective-config-complete", "--from", "1.17.1", "--to", "1.18.0", "--now", "2026-09-11T18:00:00Z", "--format", "json"}, ExitOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCNCFCLI(t, test.args...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
	for _, args := range [][]string{
		{"check", "cncf", "--project", "openfga", "--effective-config", openFGAFixed, "--from", "1.17.1", "--to", "1.18.0", "--now", "2026-09-11T18:00:00Z", "--format", "json"},
		{"check", "cncf", "--project", "openfga", "--effective-config", openFGAFixed, "--effective-config-complete=false", "--from", "1.17.1", "--to", "1.18.0", "--now", "2026-09-11T18:00:00Z", "--format", "json"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
			t.Fatalf("incomplete effective config code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "openfga", "--effective-config", openFGAFixed, "--from", "1.17.1", "--to", "1.18.0", "--now", "2026-09-11T18:00:00Z", "--format", "human")
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "precedence was not declared complete") || strings.Contains(stdout, "caller declares file, environment, and flag precedence complete") {
		t.Fatalf("incomplete OpenFGA human output code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--help")
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "--diagd-argv") || !strings.Contains(stdout, "--effective-config-complete") {
		t.Fatalf("direct format help code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

// TestCNCFNativeResourceGroupOrWorldReadableInputGetsAnActionableHint proves a
// newcomer's very first mistake (a --native-resource file left at the
// default umask, e.g. 0644) fails with the same reason code and exit code as
// before, but with a plain-English explanation and a concrete fix appended,
// instead of a bare, unexplained reason code. A correctly-permissioned
// (0600) file with identical content still succeeds, so the permission
// control itself is exactly as strict as before this change.
func TestCNCFNativeResourceGroupOrWorldReadableInputGetsAnActionableHint(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=n"]}`)
	args := func(path string) []string {
		return []string{
			"check", "cncf", "--project", "etcd", "--native-resource", path,
			"--from", "3.5.17", "--to", "3.6.0", "--now", "2026-09-24T00:00:00Z", "--format", "json",
		}
	}

	t.Run("0644 fails with the same reason code, exit code, and an added hint", func(t *testing.T) {
		path := writeCNCFFile(t, "etcd-group-readable.json", raw, 0o644)
		code, stdout, stderr := runCNCFCLI(t, args(path)...)
		if code != ExitUsage {
			t.Fatalf("code=%d, want ExitUsage(%d); stdout=%q stderr=%q", code, ExitUsage, stdout, stderr)
		}
		if stdout != "" {
			t.Fatalf("stdout must stay empty on a rejected input, got %q", stdout)
		}
		if !strings.Contains(stderr, "NATIVE_CNCF_RESOURCE_INPUT_INVALID") {
			t.Fatalf("stable reason code must be preserved: stderr=%q", stderr)
		}
		if !strings.Contains(stderr, "chmod 600") {
			t.Fatalf("hint must tell the user how to fix it (chmod 600): stderr=%q", stderr)
		}
		if !strings.Contains(stderr, "group") && !strings.Contains(stderr, "others") {
			t.Fatalf("hint must explain what happened (group/other readable): stderr=%q", stderr)
		}
		if strings.Contains(stderr, path) {
			t.Fatalf("hint must not print the full sensitive path: stderr=%q", stderr)
		}
	})

	t.Run("0600 with identical content still succeeds", func(t *testing.T) {
		path := writeCNCFFile(t, "etcd-private.json", raw, 0o600)
		code, stdout, stderr := runCNCFCLI(t, args(path)...)
		if code != ExitUnknown || stderr != "" {
			t.Fatalf("code=%d, want ExitUnknown(%d); stdout=%q stderr=%q", code, ExitUnknown, stdout, stderr)
		}
		if !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
			t.Fatalf("expected an UNKNOWN assessment: stdout=%q", stdout)
		}
	})
}

func TestCNCFHumanAndJSONOutputShowEvidenceBasisWithoutChangingExit(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"config","namespace":"metallb-system"},"data":{"config":"address-pools: []"}}`)
	path := writeCNCFFile(t, "resource.json", raw, 0o600)
	args := []string{"check", "cncf", "--project", "metallb", "--native-resource", path, "--from", "0.12.1", "--to", "0.13.2", "--now", "2026-09-11T18:00:00Z"}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitBlocked || stderr != "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	line := "evidence basis: reviewed by maintainer\n"
	if strings.Count(stdout, line) != 1 || strings.Index(stdout, line) > strings.Index(stdout, "pinned source:") {
		t.Fatalf("expected one basis line before the pinned sources: %q", stdout)
	}
	jsonCode, jsonOut, jsonErr := runCNCFCLI(t, append(args, "--format", "json")...)
	if jsonCode != code || jsonErr != "" {
		t.Fatalf("json exit %d differs from human exit %d (%q)", jsonCode, code, jsonErr)
	}
	// Published rules declare no basis, so their reports keep their exact
	// shape; an absent basis means the rule was reviewed by a maintainer.
	if strings.Contains(jsonOut, "evidenceBasis") || strings.Contains(jsonOut, "evidenceExtractor") {
		t.Fatalf("a reviewed rule's JSON must not carry a basis: %q", jsonOut)
	}
}
