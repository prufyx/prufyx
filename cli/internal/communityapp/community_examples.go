// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// communityExample runs a public synthetic walkthrough inside the Community
// binary. It never contacts a cluster or network and removes its private input
// directory before returning. The examples exercise only declared input and
// scoped rule results; they do not claim runtime or whole-upgrade safety.
func (r runtime) communityExample(args []string) int {
	if hasHelp(args) || len(args) != 1 {
		fmt.Fprintln(r.stdout, "Usage: prufyx community-preview example <cncf-coredns-latest|cncf-envoy-latest|cncf-etcd|cncf-kyverno-latest|cncf-nats-latest|cncf-opa-latest|cncf-opentelemetry|cncf-rook-latest|knowledge-cert-manager|knowledge-cncf|project-ceph-latest>")
		return ExitOK
	}
	var result communityExampleResult
	var err error
	switch args[0] {
	case "cncf-coredns-latest":
		result, err = r.runCoreDNSLatestExample()
	case "cncf-envoy-latest":
		result, err = r.runEnvoyLatestExample()
	case "cncf-etcd":
		result, err = r.runEtcdExample()
	case "cncf-kyverno-latest":
		result, err = r.runKyvernoLatestExample()
	case "cncf-nats-latest":
		result, err = r.runNATSLatestExample()
	case "cncf-opa-latest":
		result, err = r.runOPALatestExample()
	case "cncf-opentelemetry":
		result, err = r.runOpenTelemetryExample()
	case "cncf-rook-latest":
		result, err = r.runRookLatestExample()
	case "knowledge-cert-manager":
		result, err = r.runKnowledgeCertManagerExample()
	case "knowledge-cncf":
		result, err = r.runKnowledgeCNCFExample()
	case "project-ceph-latest":
		result, err = r.runCephLatestExample()
	default:
		return r.usage("unknown Community example; use prufyx community-preview example --help")
	}
	if err != nil {
		return r.fail("synthetic Community example failed", ExitIntegrity)
	}
	return r.writeEnvelope(envelope{
		SchemaVersion: legacyEnvelopeAPIVersion,
		Command:       "community-preview example " + args[0],
		Result: envelopeResult{
			Status:   "OK",
			Decision: "SYNTHETIC_RESULT",
			Scope:    "local declared input only",
			Reason:   "synthetic_example_completed",
			Messages: []string{"No network, process, cluster, or runtime behavior was observed."},
		},
		Data: result,
	}, ExitOK)
}

type communityExampleResult struct {
	Example         string `json:"example"`
	BlockedExit     int    `json:"blockedExit"`
	CleanExit       int    `json:"cleanExit,omitempty"`
	UnknownExit     int    `json:"unknownExit"`
	Aggregate       string `json:"aggregate"`
	NetworkUsed     bool   `json:"networkUsed"`
	ClusterUsed     bool   `json:"clusterUsed"`
	PrivateRetained bool   `json:"privateInputsRetained"`
	RuntimeObserved bool   `json:"runtimeObserved"`
	ProcessExecuted bool   `json:"processExecuted"`
	ScopedClaimOnly bool   `json:"scopedClaimOnly"`
}

func (r runtime) runKnowledgeCertManagerExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-knowledge-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private knowledge example directory: %w", err)
	}
	defer os.RemoveAll(work)
	packages, store := filepath.Join(work, "packages"), filepath.Join(work, "store")
	if err := os.Mkdir(packages, 0o700); err != nil {
		return communityExampleResult{}, fmt.Errorf("create package directory: %w", err)
	}
	artifacts, err := knowledgefixture.Generate(time.Now().UTC())
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("generate synthetic knowledge: %w", err)
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{
		{knowledgefixture.RootName, artifacts.Root}, {knowledgefixture.Revision1Name, artifacts.Revision1}, {knowledgefixture.Revision2Name, artifacts.Revision2}, {knowledgefixture.ManifestName, artifacts.Manifest},
	} {
		if err := os.WriteFile(filepath.Join(packages, file.name), file.raw, 0o600); err != nil {
			return communityExampleResult{}, fmt.Errorf("write synthetic knowledge: %w", err)
		}
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil || len(manifest.Revisions) < 2 || manifest.PrivateKeysPersisted {
		return communityExampleResult{}, fmt.Errorf("decode synthetic knowledge manifest")
	}
	values := []byte(`{"syntheticCanary":"PRIVATE-SYNTHETIC-CANARY","prometheus":{"servicemonitor":{"path":"PRIVATE-SYNTHETIC-CANARY"}}}`)
	valuesPath := filepath.Join(work, "values.json")
	if err := os.WriteFile(valuesPath, values, 0o600); err != nil {
		return communityExampleResult{}, fmt.Errorf("write private values: %w", err)
	}
	importOne, receiptOne, err := r.importSyntheticKnowledge(packages, store, manifest, 0, true, "cert-manager")
	if err != nil || importOne != ExitOK {
		return communityExampleResult{}, fmt.Errorf("import synthetic revision one: %w", err)
	}
	reportOnePath := filepath.Join(work, "report-one.json")
	codeOne, reportOne, err := r.checkSyntheticCertManager(valuesPath, store, manifest.Revisions[0], receiptOne, "")
	if err != nil || codeOne != ExitUnknown || !strings.Contains(reportOne, `"UNKNOWN"`) || strings.Contains(reportOne, "PRIVATE-SYNTHETIC-CANARY") {
		return communityExampleResult{}, fmt.Errorf("revision one did not remain redacted UNKNOWN")
	}
	if err := os.WriteFile(reportOnePath, []byte(reportOne), 0o600); err != nil {
		return communityExampleResult{}, fmt.Errorf("write revision one report: %w", err)
	}
	importTwo, receiptTwo, err := r.importSyntheticKnowledge(packages, store, manifest, 1, false, "cert-manager")
	if err != nil || importTwo != ExitOK {
		return communityExampleResult{}, fmt.Errorf("import synthetic revision two: %w", err)
	}
	codeTwo, reportTwo, err := r.checkSyntheticCertManager(valuesPath, store, manifest.Revisions[1], receiptTwo, "")
	if err != nil || codeTwo != ExitBlocked || !strings.Contains(reportTwo, `"BLOCKED"`) || strings.Contains(reportTwo, "PRIVATE-SYNTHETIC-CANARY") {
		return communityExampleResult{}, fmt.Errorf("revision two did not remain redacted BLOCKED")
	}
	codeReplay, replay, err := r.checkSyntheticCertManager(valuesPath, store, manifest.Revisions[0], receiptOne, reportOnePath)
	if err != nil || codeReplay != ExitUnknown || !strings.Contains(replay, `"MATCH"`) || strings.Contains(replay, "PRIVATE-SYNTHETIC-CANARY") {
		return communityExampleResult{}, fmt.Errorf("historical replay did not match")
	}
	return communityExampleResult{Example: "knowledge-cert-manager", BlockedExit: codeTwo, UnknownExit: codeOne, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) importSyntheticKnowledge(packages, store string, manifest knowledgefixture.Manifest, index int, bootstrap bool, profile string) (int, string, error) {
	revision := manifest.Revisions[index]
	args := []string{"import", filepath.Join(packages, revision.PackagePath), "--db-root", store, "--profile", profile, "--expected-revision", revision.Revision, "--expected-bundle-digest", revision.BundleDigest, "--format", "json"}
	if bootstrap {
		args = append(args, "--bootstrap-root", filepath.Join(packages, knowledgefixture.RootName), "--bootstrap-root-digest", manifest.BootstrapRoot.Digest)
	}
	var stdout bytes.Buffer
	child := r
	child.stdout = &stdout
	code := child.database(context.Background(), args)
	var receipt struct {
		TrustReceiptDigest string `json:"trustReceiptDigest"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.TrustReceiptDigest == "" {
		return code, "", fmt.Errorf("decode synthetic import receipt")
	}
	return code, receipt.TrustReceiptDigest, nil
}

func (r runtime) checkSyntheticCertManager(values, store string, revision knowledgefixture.Revision, receipt, replay string) (int, string, error) {
	args := []string{"--from", "1.20.3", "--to", "1.21.1", "--values", values, "--knowledge-db", store, "--knowledge-revision", revision.Revision, "--knowledge-bundle-digest", revision.BundleDigest, "--knowledge-trust-receipt-digest", receipt, "--format", "json"}
	if replay != "" {
		args = append(args, "--values-digest", communityDigest(mustReadExample(values)), "--replay-receipt", replay)
	}
	var stdout bytes.Buffer
	child := r
	child.stdout = &stdout
	code := child.certManager(args)
	if !json.Valid(stdout.Bytes()) {
		return code, "", fmt.Errorf("decode synthetic cert-manager result")
	}
	return code, stdout.String(), nil
}

func mustReadExample(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return raw
}

func (r runtime) runKnowledgeCNCFExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-cncf-knowledge-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private CNCF knowledge example directory: %w", err)
	}
	defer os.RemoveAll(work)
	packages, store := filepath.Join(work, "packages"), filepath.Join(work, "store")
	if err := os.Mkdir(packages, 0o700); err != nil {
		return communityExampleResult{}, fmt.Errorf("create package directory: %w", err)
	}
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC())
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("generate synthetic CNCF knowledge: %w", err)
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{
		{knowledgefixture.RootName, artifacts.Root}, {knowledgefixture.Revision1Name, artifacts.Revision1}, {knowledgefixture.Revision2Name, artifacts.Revision2}, {knowledgefixture.ManifestName, artifacts.Manifest},
	} {
		if err := os.WriteFile(filepath.Join(packages, file.name), file.raw, 0o600); err != nil {
			return communityExampleResult{}, fmt.Errorf("write synthetic CNCF knowledge: %w", err)
		}
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil || len(manifest.Revisions) < 2 || manifest.PrivateKeysPersisted {
		return communityExampleResult{}, fmt.Errorf("decode synthetic CNCF knowledge manifest")
	}
	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.distribution","state":"declared","enumValue":"official_upstream"},{"id":"component.kyverno.execution_surface","state":"declared","enumValue":"reports_controller"},{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":true}]}]}}`)
	inputPath := filepath.Join(work, "input.json")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		return communityExampleResult{}, fmt.Errorf("write private CNCF input: %w", err)
	}
	codeImportOne, receiptOne, err := r.importSyntheticKnowledge(packages, store, manifest, 0, true, "cncf")
	if err != nil || codeImportOne != ExitOK {
		return communityExampleResult{}, fmt.Errorf("import synthetic CNCF revision one: %w", err)
	}
	codeOne, reportOne, err := r.checkSyntheticCNCF(inputPath, store, manifest.Revisions[0], receiptOne, "")
	if err != nil || codeOne != ExitUnknown || !strings.Contains(reportOne, `"UNKNOWN"`) || strings.Contains(reportOne, "kyverno") && strings.Contains(reportOne, "PRIVATE") {
		return communityExampleResult{}, fmt.Errorf("CNCF revision one did not remain UNKNOWN")
	}
	reportOnePath := filepath.Join(work, "report-one.json")
	if err := os.WriteFile(reportOnePath, []byte(reportOne), 0o600); err != nil {
		return communityExampleResult{}, fmt.Errorf("write CNCF report one: %w", err)
	}
	codeImportTwo, receiptTwo, err := r.importSyntheticKnowledge(packages, store, manifest, 1, false, "cncf")
	if err != nil || codeImportTwo != ExitOK {
		return communityExampleResult{}, fmt.Errorf("import synthetic CNCF revision two: %w", err)
	}
	codeTwo, reportTwo, err := r.checkSyntheticCNCF(inputPath, store, manifest.Revisions[1], receiptTwo, "")
	if err != nil || codeTwo != ExitBlocked || !strings.Contains(reportTwo, `"BLOCKED"`) {
		return communityExampleResult{}, fmt.Errorf("CNCF revision two did not become BLOCKED")
	}
	codeReplay, replay, err := r.checkSyntheticCNCF(inputPath, store, manifest.Revisions[0], receiptOne, reportOnePath)
	if err != nil || codeReplay != ExitUnknown || !strings.Contains(replay, `"MATCH"`) {
		return communityExampleResult{}, fmt.Errorf("CNCF historical replay did not match")
	}
	return communityExampleResult{Example: "knowledge-cncf", BlockedExit: codeTwo, UnknownExit: codeOne, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) checkSyntheticCNCF(input, store string, revision knowledgefixture.Revision, receipt, replay string) (int, string, error) {
	args := []string{"--project", "kyverno", "--input", input, "--knowledge-db", store, "--knowledge-revision", revision.Revision, "--knowledge-bundle-digest", revision.BundleDigest, "--knowledge-trust-receipt-digest", receipt, "--format", "json"}
	if replay != "" {
		args = append(args, "--input-digest", communityDigest(mustReadExample(input)), "--replay-report", replay)
	}
	var stdout bytes.Buffer
	child := r
	child.stdout = &stdout
	code := child.cncf(args)
	if !json.Valid(stdout.Bytes()) {
		return code, "", fmt.Errorf("decode synthetic CNCF result")
	}
	return code, stdout.String(), nil
}

func (r runtime) runEtcdExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-etcd-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private example directory: %w", err)
	}
	defer os.RemoveAll(work)
	blocked := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=synthetic-private-node","--enable-v2=false"]}`)
	unknown := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--initial-cluster","--enable-v2=true"]}`)
	blockedCode, blockedReport, err := r.prepareThenCheck(work, "etcd", "3.5.17", "3.6.0", blocked)
	if err != nil || blockedCode != ExitBlocked || !communityClaim(blockedReport, "BLOCKED") {
		return communityExampleResult{}, fmt.Errorf("etcd removed-v2 witness did not produce scoped BLOCKED")
	}
	unknownCode, unknownReport, err := r.prepareThenCheck(work, "etcd", "3.5.17", "3.6.0", unknown)
	if err != nil || unknownCode != ExitUnknown || !communityClaim(unknownReport, "UNKNOWN") {
		return communityExampleResult{}, fmt.Errorf("etcd incomplete argv did not produce scoped UNKNOWN")
	}
	latestBlocked := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=synthetic-private-node","--experimental-compact-hash-check-enabled=true"]}`)
	latestClean := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=synthetic-private-node","--feature-gates=CompactHashCheck=true"]}`)
	latestUnknown := []byte(`{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--config-file=/synthetic/private/etcd.yaml"]}`)
	latestBlockedCode, latestBlockedReport, err := r.prepareThenCheck(work, "etcd", "3.6.14", "3.7.1", latestBlocked)
	if err != nil || latestBlockedCode != ExitBlocked || !communityClaim(latestBlockedReport, "BLOCKED") {
		return communityExampleResult{}, fmt.Errorf("etcd 3.7 removed experimental flag did not produce scoped BLOCKED")
	}
	latestCleanCode, latestCleanReport, err := r.prepareThenCheck(work, "etcd", "3.6.14", "3.7.1", latestClean)
	if err != nil || latestCleanCode != ExitOK || !communityClaim(latestCleanReport, "PASS") {
		return communityExampleResult{}, fmt.Errorf("etcd documented feature gate replacement did not produce scoped PASS")
	}
	latestUnknownCode, latestUnknownReport, err := r.prepareThenCheck(work, "etcd", "3.6.14", "3.7.1", latestUnknown)
	if err != nil || latestUnknownCode != ExitUnknown || !communityClaim(latestUnknownReport, "UNKNOWN") {
		return communityExampleResult{}, fmt.Errorf("etcd indirect configuration did not remain UNKNOWN")
	}
	return communityExampleResult{Example: "cncf-etcd", BlockedExit: latestBlockedCode, CleanExit: latestCleanCode, UnknownExit: latestUnknownCode, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) runRookLatestExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-rook-latest-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private Rook example directory: %w", err)
	}
	defer os.RemoveAll(work)
	input := func(from, kubernetes string) []byte {
		dependency := ""
		if kubernetes != "" {
			dependency = fmt.Sprintf(`{"component":"pkg:github/kubernetes/kubernetes","version":%q,"facts":[]},`, kubernetes)
		}
		return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/rook/rook","version":%q,"facts":[]}]},"proposed":{"components":[%s{"component":"pkg:github/rook/rook","version":"1.20.7","facts":[]}]}}`, from, dependency))
	}
	// Rook documents only adjacent supported minor upgrade paths. Every
	// non-adjacent origin therefore carries a reviewed BLOCKED
	// direct-minor-skip claim whatever Kubernetes version is declared, so the
	// Kubernetes-minimum matrix is only demonstrated from the adjacent origin.
	for _, from := range []string{"1.15.9", "1.16.9", "1.17.9", "1.18.11"} {
		// Each non-adjacent origin reports the forbidden direct skip alongside
		// the separate Kubernetes-minimum claim for the same exact pair.
		for _, pair := range []struct{ kubernetes, minimum string }{
			{"1.30.9", "BLOCKED"},
			{"1.31.0", "PASS"},
			{"", "UNKNOWN"},
		} {
			skipCode, skipReport, skipErr := r.checkPrepared(work, "rook", input(from, pair.kubernetes))
			if skipErr != nil || skipCode != ExitBlocked || !communityClaims(skipReport, "BLOCKED", pair.minimum) {
				return communityExampleResult{}, fmt.Errorf("Rook %s direct minor skip to 1.20.7 did not produce scoped BLOCKED", from)
			}
		}
	}
	blockedCode, blockedReport, err := r.checkPrepared(work, "rook", input("1.19.11", "1.30.9"))
	if err != nil || blockedCode != ExitBlocked || !communityClaim(blockedReport, "BLOCKED") {
		return communityExampleResult{}, fmt.Errorf("Rook 1.19.11 below-minimum Kubernetes declaration did not produce scoped BLOCKED")
	}
	cleanCode, cleanReport, err := r.checkPrepared(work, "rook", input("1.19.11", "1.31.0"))
	if err != nil || cleanCode != ExitOK || !communityClaim(cleanReport, "PASS") {
		return communityExampleResult{}, fmt.Errorf("Rook 1.19.11 minimum Kubernetes declaration did not produce scoped PASS")
	}
	unknownCode, unknownReport, err := r.checkPrepared(work, "rook", input("1.19.11", ""))
	if err != nil || unknownCode != ExitUnknown || !communityClaim(unknownReport, "UNKNOWN") {
		return communityExampleResult{}, fmt.Errorf("Rook 1.19.11 missing Kubernetes declaration did not remain UNKNOWN")
	}
	return communityExampleResult{Example: "cncf-rook-latest", BlockedExit: blockedCode, CleanExit: cleanCode, UnknownExit: unknownCode, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) runOpenTelemetryExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-opentelemetry-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private example directory: %w", err)
	}
	defer os.RemoveAll(work)
	blocked := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/open-telemetry/opentelemetry-collector","version":"0.110.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/open-telemetry/opentelemetry-collector","version":"0.111.0","facts":[{"id":"component.opentelemetry.config_complete","state":"declared","boolValue":true},{"id":"component.opentelemetry.config_precedence_resolved","state":"declared","boolValue":true},{"id":"component.opentelemetry.distribution","state":"declared","enumValue":"official"},{"id":"component.opentelemetry.internal_metrics_localhost_remote_conflict","state":"declared","boolValue":false},{"id":"component.opentelemetry.internal_metrics_override_absent","state":"declared","boolValue":true},{"id":"component.opentelemetry.internal_metrics_remote_scrape_required","state":"declared","boolValue":false},{"id":"component.opentelemetry.logging_exporter_present","state":"declared","boolValue":true},{"id":"component.opentelemetry.telemetry_use_localhost_default_metrics_address_effective","state":"declared","boolValue":false}]}]}}`)
	clean := []byte(strings.Replace(string(blocked), `"id":"component.opentelemetry.logging_exporter_present","state":"declared","boolValue":true`, `"id":"component.opentelemetry.logging_exporter_present","state":"declared","boolValue":false`, 1))
	unknown := []byte(strings.Replace(string(blocked), `,{"id":"component.opentelemetry.logging_exporter_present","state":"declared","boolValue":true}`, "", 1))
	blockedCode, blockedReport, err := r.checkPrepared(work, "opentelemetry", blocked)
	if err != nil || blockedCode != ExitBlocked || !communityClaims(blockedReport, "BLOCKED", "PASS") {
		return communityExampleResult{}, fmt.Errorf("OpenTelemetry logging exporter witness did not produce scoped BLOCKED")
	}
	cleanCode, cleanReport, err := r.checkPrepared(work, "opentelemetry", clean)
	if err != nil || cleanCode != ExitOK || !communityClaims(cleanReport, "PASS", "PASS") {
		return communityExampleResult{}, fmt.Errorf("OpenTelemetry corrected witness did not produce scoped PASS")
	}
	unknownCode, unknownReport, err := r.checkPrepared(work, "opentelemetry", unknown)
	if err != nil || unknownCode != ExitUnknown || !communityClaims(unknownReport, "UNKNOWN", "PASS") {
		return communityExampleResult{}, fmt.Errorf("OpenTelemetry missing fact did not produce scoped UNKNOWN")
	}
	return communityExampleResult{Example: "cncf-opentelemetry", BlockedExit: blockedCode, CleanExit: cleanCode, UnknownExit: unknownCode, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) runOPALatestExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-opa-latest-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private OPA example directory: %w", err)
	}
	defer os.RemoveAll(work)
	for _, from := range []string{"1.15.2", "1.16.2", "1.17.1", "1.18.2", "1.19.1"} {
		base := fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/open-policy-agent/opa","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/open-policy-agent/opa","version":"1.20.2","facts":[{"id":"component.opa.modules_use_rego_v1_import","state":"declared","boolValue":false},{"id":"component.opa.producer_v0_compatible","state":"declared","boolValue":false},{"id":"component.opa.v0_consumers_remain","state":"declared","boolValue":true}]}]}}`, from)
		blocked := []byte(base)
		clean := []byte(strings.Replace(base, `"id":"component.opa.producer_v0_compatible","state":"declared","boolValue":false`, `"id":"component.opa.producer_v0_compatible","state":"declared","boolValue":true`, 1))
		unknown := []byte(strings.Replace(base, `"id":"component.opa.producer_v0_compatible","state":"declared","boolValue":false`, `"id":"component.opa.producer_v0_compatible","state":"missing"`, 1))
		blockedCode, blockedReport, err := r.checkPrepared(work, "opa", blocked)
		if err != nil || blockedCode != ExitBlocked || !communityClaim(blockedReport, "BLOCKED") {
			return communityExampleResult{}, fmt.Errorf("OPA %s target-only witness did not produce scoped BLOCKED", from)
		}
		cleanCode, cleanReport, err := r.checkPrepared(work, "opa", clean)
		if err != nil || cleanCode != ExitOK || !communityClaim(cleanReport, "PASS") {
			return communityExampleResult{}, fmt.Errorf("OPA %s corrected witness did not produce scoped PASS", from)
		}
		unknownCode, unknownReport, err := r.checkPrepared(work, "opa", unknown)
		if err != nil || unknownCode != ExitUnknown || !communityClaim(unknownReport, "UNKNOWN") {
			return communityExampleResult{}, fmt.Errorf("OPA %s missing producer declaration did not produce scoped UNKNOWN", from)
		}
	}
	return communityExampleResult{Example: "cncf-opa-latest", BlockedExit: ExitBlocked, CleanExit: ExitOK, UnknownExit: ExitUnknown, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) runKyvernoLatestExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-kyverno-latest-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private Kyverno example directory: %w", err)
	}
	defer os.RemoveAll(work)
	blocked := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"synthetic-private"},"spec":{"template":{"spec":{"containers":[{"name":"selected","image":"private.example/opaque","command":["reports-controller"],"args":["--reportsChunkSize=16"]}]}}}}`)
	clean := []byte(strings.Replace(string(blocked), `,"args":["--reportsChunkSize=16"]`, "", 1))
	for _, from := range []string{"1.14.5", "1.15.3", "1.16.4", "1.17.2", "1.18.2"} {
		blockedCode, blockedReport, err := r.prepareKyvernoThenCheck(work, from, "1.19.1", "official_upstream", blocked)
		if err != nil || blockedCode != ExitBlocked || !communityClaim(blockedReport, "BLOCKED") {
			return communityExampleResult{}, fmt.Errorf("Kyverno %s target-only witness did not produce scoped BLOCKED", from)
		}
		cleanCode, cleanReport, err := r.prepareKyvernoThenCheck(work, from, "1.19.1", "official_upstream", clean)
		if err != nil || cleanCode != ExitOK || !communityClaim(cleanReport, "PASS") {
			return communityExampleResult{}, fmt.Errorf("Kyverno %s corrected witness did not produce scoped PASS", from)
		}
		unknownCode, unknownReport, err := r.prepareKyvernoThenCheck(work, from, "1.19.1", "custom_build", clean)
		if err != nil || unknownCode != ExitUnknown || !communityClaim(unknownReport, "UNKNOWN") {
			return communityExampleResult{}, fmt.Errorf("Kyverno %s custom distribution did not produce scoped UNKNOWN", from)
		}
	}
	return communityExampleResult{Example: "cncf-kyverno-latest", BlockedExit: ExitBlocked, CleanExit: ExitOK, UnknownExit: ExitUnknown, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) prepareKyvernoThenCheck(work, from, to, distribution string, raw []byte) (int, map[string]any, error) {
	input := filepath.Join(work, "kyverno-workload.json")
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		return 0, nil, fmt.Errorf("write private Kyverno input: %w", err)
	}
	var prepared bytes.Buffer
	child := r
	child.stdout = &prepared
	code := child.prepareCNCF([]string{"--project", "kyverno", "--input", input, "--container", "selected", "--from", from, "--to", to, "--distribution", distribution, "--input-digest", communityDigest(raw), "--format", "input"})
	if (code != ExitOK && code != ExitUnknown) || !json.Valid(prepared.Bytes()) {
		return code, nil, fmt.Errorf("prepare Kyverno returned %d", code)
	}
	return r.checkPrepared(work, "kyverno", prepared.Bytes())
}

func (r runtime) prepareThenCheck(work, project, from, to string, raw []byte) (int, map[string]any, error) {
	input := filepath.Join(work, project+"-input.json")
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		return 0, nil, fmt.Errorf("write private %s input: %w", project, err)
	}
	var prepared bytes.Buffer
	child := r
	child.stdout = &prepared
	code := child.prepareCNCF([]string{"--project", project, "--input", input, "--from", from, "--to", to, "--input-digest", communityDigest(raw), "--format", "input"})

	if (code != ExitOK && code != ExitUnknown) || !json.Valid(prepared.Bytes()) {
		return code, nil, fmt.Errorf("prepare %s returned %d", project, code)
	}
	return r.checkPrepared(work, project, prepared.Bytes())
}

func (r runtime) checkPrepared(work, project string, raw []byte) (int, map[string]any, error) {
	input := filepath.Join(work, project+"-prepared.json")
	if err := os.WriteFile(input, raw, 0o600); err != nil {
		return 0, nil, fmt.Errorf("write private %s prepared input: %w", project, err)
	}
	var stdout bytes.Buffer
	child := r
	child.stdout = &stdout
	evaluationTime := "2026-09-10T00:00:00Z"
	if project == "opentelemetry" {
		evaluationTime = "2026-09-13T10:00:00Z"
	} else if project == "etcd" {
		evaluationTime = "2026-09-12T07:38:00Z"
	} else if project == "rook" {
		evaluationTime = "2026-09-12T08:32:00Z"
	}
	if project == "opa" || project == "kyverno" {
		evaluationTime = "2026-09-12T09:34:00Z"
	}
	code := child.cncf([]string{"--project", project, "--input", input, "--input-digest", communityDigest(raw), "--now", evaluationTime, "--format", "json"})
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return code, nil, fmt.Errorf("decode %s report: %w", project, err)
	}
	return code, report, nil
}

func communityClaim(report map[string]any, want string) bool {
	return communityClaims(report, want)
}

func communityClaims(report map[string]any, wants ...string) bool {
	check, _ := report["check"].(map[string]any)
	claims, _ := check["claims"].([]any)
	if len(claims) != len(wants) {
		return false
	}
	remaining := make(map[string]int, len(wants))
	for _, want := range wants {
		remaining[want]++
	}
	for _, value := range claims {
		claim, _ := value.(map[string]any)
		status, _ := claim["status"].(string)
		if remaining[status] == 0 {
			return false
		}
		remaining[status]--
	}
	return report["assessment"] == "UNKNOWN" && report["networkUsed"] == false && report["runtimeReproduced"] == float64(0)
}

func communityDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
