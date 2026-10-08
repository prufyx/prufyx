// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDistributionManifestPreparationFeedsScopedRule(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, status      string
		prepareCode, checkCode int
	}{
		{"schema1 blocked", `{"schemaVersion":1,"name":"private/example","tag":"latest","architecture":"amd64","fsLayers":[{"blobSum":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"history":[{"v1Compatibility":"{\"private\":\"canary\"}"}],"signatures":[{"signature":"private-signature"}]}`, "BLOCKED", ExitOK, ExitBlocked},
		{"schema2 pass", `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":2,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":3,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"annotations":{"private":"canary"}}`, "PASS", ExitOK, ExitOK},
		{"manifest list unknown", `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[]}`, "UNKNOWN", ExitUnknown, ExitUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(test.raw)
			path := writeCNCFFile(t, "manifest.json", raw, 0o600)
			code, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "distribution", "--input", path, "--from", "2.8.3", "--to", "3.0.0", "--input-digest", cncfDigest(raw), "--format", "input")
			if code != test.prepareCode || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, "private") || strings.Contains(input, "latest") {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "distribution", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-11T16:30:00Z", "--format", "json")
			if code != test.checkCode || stderr != "" || !strings.Contains(report, `"status":"`+test.status+`"`) || strings.Contains(report, "private") {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
		})
	}
}

func TestNativeFormatDirectCheckSelectedEmptyStoreHasNoEmbeddedFallback(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"schemaVersion":1,"name":"private/example","tag":"latest","architecture":"amd64","fsLayers":[],"history":[]}`)
	path := writeCNCFFile(t, "manifest.json", raw, 0o600)
	store := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCNCFCLI(t, "check", "cncf", "--project", "distribution", "--image-manifest", path, "--from", "2.8.3", "--to", "3.0.0", "--knowledge-db", store, "--format", "human")
	if code != ExitUnknown || stdout != "" || !strings.Contains(stderr, "no verified CNCF revision selected") || strings.Contains(stderr, path) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestNativeFormatSelectedCurrentAndHistoricalReplayBindRawAndKnowledgePins(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	raw := []byte(`{"schemaVersion":1,"name":"private/example","tag":"latest","architecture":"amd64","fsLayers":[],"history":[],"private-canary":"secret"}`)
	path := writeCNCFFile(t, "manifest.json", raw, 0o600)
	base := []string{"check", "cncf", "--project", "distribution", "--image-manifest", path, "--from", "2.8.3", "--to", "3.0.0", "--knowledge-db", fixture.store, "--format", "json"}
	code, original, stderr := runCNCFCLI(t, base...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(original, `"knowledgeOrigin":"external_declared"`) || strings.Contains(original, "private") {
		t.Fatalf("selected current code=%d stderr=%q stdout=%s", code, stderr, original)
	}
	reportPath := writeCNCFFile(t, "report.json", []byte(original), 0o600)
	importExternalCLIRevision2(t, &fixture)
	replay := append(append([]string{}, base...),
		"--image-manifest-digest", cncfDigest(raw),
		"--replay-report", reportPath,
		"--knowledge-revision", "1",
		"--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest,
		"--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest,
	)
	code, output, stderr := runCNCFCLI(t, replay...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, `"status":"MATCH"`) || !strings.Contains(output, `"mode":"historical"`) || strings.Contains(output, "private") {
		t.Fatalf("historical replay code=%d stderr=%q stdout=%s", code, stderr, output)
	}
	for _, option := range []string{"--image-manifest-digest", "--knowledge-revision", "--knowledge-bundle-digest", "--knowledge-trust-receipt-digest"} {
		code, output, stderr = runCNCFCLI(t, omitCLIOption(replay, option)...)
		if code != ExitUsage || output != "" || stderr == "" || strings.Contains(stderr, path) {
			t.Fatalf("missing %s code=%d stdout=%q stderr=%q", option, code, output, stderr)
		}
	}
	assertStoreDoesNotContain(t, fixture.store, []string{"private", path, "private-canary", "secret"})
}

func TestCNISpecPreparationRequiresShapeEditAndIntent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, raw, operation, status string
		prepareCode, checkCode       int
	}{
		{"old label remains outside target", `{"cniVersion":"0.4.0","name":"private-net","type":"bridge","bridge":"private-bridge"}`, "configuration-spec-migration", "UNKNOWN", ExitOK, ExitUnknown},
		{"version-only edit blocked", `{"cniVersion":"1.0.0","name":"private-net","type":"bridge","bridge":"private-bridge"}`, "configuration-spec-migration", "BLOCKED", ExitOK, ExitBlocked},
		{"list form pass", `{"cniVersion":"1.0.0","name":"private-net","plugins":[{"type":"bridge","bridge":"private-bridge"}]}`, "configuration-spec-migration", "PASS", ExitOK, ExitOK},
		{"intent omitted unknown", `{"cniVersion":"1.0.0","name":"private-net","plugins":[{"type":"bridge"}]}`, "", "UNKNOWN", ExitUnknown, ExitUnknown},
		{"mixed form unknown", `{"cniVersion":"1.0.0","name":"private-net","type":"bridge","plugins":[{"type":"portmap"}]}`, "configuration-spec-migration", "UNKNOWN", ExitUnknown, ExitUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(test.raw)
			path := writeCNCFFile(t, "cni.json", raw, 0o600)
			args := []string{"prepare", "cncf", "--project", "container-network-interface-cni", "--input", path, "--from", "0.4.0", "--to", "1.0.0", "--input-digest", cncfDigest(raw), "--format", "input"}
			if test.operation != "" {
				args = append(args, "--operation", test.operation)
			}
			code, input, stderr := runCNCFCLI(t, args...)
			if code != test.prepareCode || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, "private-net") || strings.Contains(input, "private-bridge") {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "container-network-interface-cni", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-11T16:30:00Z", "--format", "json")
			if code != test.checkCode || stderr != "" || !strings.Contains(report, `"status":"`+test.status+`"`) || strings.Contains(report, "private") {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
		})
	}
}

func TestNativeFormatPreparationRejectsCrossModeFlagsWithoutOpeningInput(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"prepare", "cncf", "--project", "distribution", "--input", "/private/not-opened", "--from", "2.8.3", "--to", "3.0.0", "--operation", "configuration-spec-migration"},
		{"prepare", "cncf", "--project", "container-network-interface-cni", "--input", "/private/not-opened", "--from", "0.4.0", "--to", "1.0.0", "--distribution", "official_upstream"},
	} {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, "/private/not-opened") {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestNativeFormatDirectCheckUsesPrivateSourceWithoutCanonicalHandOff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, project, flag, raw, operation, status string
		wantCode                                    int
	}{
		{"distribution schema1 blocked", "distribution", "--image-manifest", `{"schemaVersion":1,"name":"private/example","tag":"latest","architecture":"amd64","fsLayers":[{"blobSum":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"history":[{"v1Compatibility":"{\"private-canary\":true}"}]}`, "", "BLOCKED", ExitBlocked},
		{"distribution schema2 pass", "distribution", "--image-manifest", `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":2,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":3,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`, "", "PASS", ExitOK},
		{"distribution unsupported unknown", "distribution", "--image-manifest", `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[],"private-canary":"secret"}`, "", "UNKNOWN", ExitUnknown},
		{"cni version-only blocked", "container-network-interface-cni", "--cni-configuration", `{"cniVersion":"1.0.0","name":"private-net","type":"bridge","bridge":"private-canary"}`, "configuration-spec-migration", "BLOCKED", ExitBlocked},
		{"cni list pass", "container-network-interface-cni", "--cni-configuration", `{"cniVersion":"1.0.0","name":"private-net","plugins":[{"type":"bridge","bridge":"private-canary"}]}`, "configuration-spec-migration", "PASS", ExitOK},
		{"cni mixed unknown", "container-network-interface-cni", "--cni-configuration", `{"cniVersion":"1.0.0","name":"private-net","type":"bridge","plugins":[{"type":"portmap","private-canary":"secret"}]}`, "configuration-spec-migration", "UNKNOWN", ExitUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(test.raw)
			path := writeCNCFFile(t, "native.json", raw, 0o600)
			from, to := "2.8.3", "3.0.0"
			pinFlag := "--image-manifest-digest"
			if test.project == "container-network-interface-cni" {
				from, to = "0.4.0", "1.0.0"
				pinFlag = "--cni-configuration-digest"
			}
			args := []string{"check", "cncf", "--project", test.project, test.flag, path, pinFlag, cncfDigest(raw), "--from", from, "--to", to, "--now", "2026-09-11T16:30:00Z", "--format", "json"}
			if test.operation != "" {
				args = append(args, "--operation", test.operation)
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != test.wantCode || stderr != "" || !strings.Contains(stdout, `"status":"`+test.status+`"`) {
				t.Fatalf("code=%d stderr=%q stdout=%s", code, stderr, stdout)
			}
			if strings.Contains(stdout, "private") || strings.Contains(stdout, path) || strings.Contains(stderr, path) {
				t.Fatalf("native private input leaked: stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestNativeFormatDirectCheckFuturePairExtractsFactsButRuleRemainsUnknown(t *testing.T) {
	t.Parallel()
	tests := []struct {
		project, flag, raw, from, to, operation string
	}{
		{"distribution", "--image-manifest", `{"schemaVersion":1,"name":"private/example","tag":"latest","architecture":"amd64","fsLayers":[],"history":[]}`, "3.0.0", "4.0.0", ""},
		{"container-network-interface-cni", "--cni-configuration", `{"cniVersion":"1.0.0","name":"private-net","plugins":[{"type":"bridge"}]}`, "1.0.0", "2.0.0", "configuration-spec-migration"},
	}
	for _, test := range tests {
		t.Run(test.project, func(t *testing.T) {
			path := writeCNCFFile(t, "native.json", []byte(test.raw), 0o600)
			args := []string{"check", "cncf", "--project", test.project, test.flag, path, "--from", test.from, "--to", test.to, "--now", "2026-09-11T16:30:00Z", "--format", "json"}
			if test.operation != "" {
				args = append(args, "--operation", test.operation)
			}
			code, stdout, stderr := runCNCFCLI(t, args...)
			if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, `"reasonCode":"RULE_TRANSITION_NOT_REVIEWED"`) || strings.Contains(stdout, "private") {
				t.Fatalf("code=%d stderr=%q stdout=%s", code, stderr, stdout)
			}
		})
	}
}

func TestNativeFormatDirectCheckRejectsCrossModeBeforeOpeningInput(t *testing.T) {
	t.Parallel()
	tests := [][]string{
		{"check", "cncf", "--project", "distribution", "--image-manifest", "/private/not-opened", "--cni-configuration", "/private/also-not-opened", "--from", "2.8.3", "--to", "3.0.0", "--now", "2026-09-11T16:30:00Z"},
		{"check", "cncf", "--project", "knative", "--image-manifest", "/private/not-opened", "--from", "2.8.3", "--to", "3.0.0", "--now", "2026-09-11T16:30:00Z"},
		{"check", "cncf", "--project", "container-network-interface-cni", "--cni-configuration", "/private/not-opened", "--input", "/private/prepared-not-opened", "--from", "0.4.0", "--to", "1.0.0", "--now", "2026-09-11T16:30:00Z"},
	}
	for _, args := range tests {
		code, stdout, stderr := runCNCFCLI(t, args...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, "/private/") {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}
