// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (r runtime) runEnvoyLatestExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-envoy-latest-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private Envoy example directory: %w", err)
	}
	defer os.RemoveAll(work)
	input := func(from, major string) []byte {
		fact := ""
		if major != "" {
			fact = fmt.Sprintf(`{"id":"component.envoy.xds_api_major","state":"declared","enumValue":%q}`, major)
		}
		return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/envoyproxy/envoy","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/envoyproxy/envoy","version":"1.39.1","facts":[%s]}]}}`, from, fact))
	}
	var blockedCode, cleanCode, unknownCode int
	var report map[string]any
	for _, from := range []string{"1.38.4", "1.37.6", "1.36.10", "1.35.13", "1.34.14"} {
		blockedCode, report, err = r.checkLatestGenericExample(work, "envoy", input(from, "v2"))
		if err != nil || blockedCode != ExitBlocked || !communityClaim(report, "BLOCKED") {
			return communityExampleResult{}, fmt.Errorf("Envoy %s xDS v2 declaration did not produce scoped BLOCKED", from)
		}
		cleanCode, report, err = r.checkLatestGenericExample(work, "envoy", input(from, "v3"))
		if err != nil || cleanCode != ExitOK || !communityClaim(report, "PASS") {
			return communityExampleResult{}, fmt.Errorf("Envoy %s xDS v3 declaration did not produce scoped PASS", from)
		}
		unknownCode, report, err = r.checkLatestGenericExample(work, "envoy", input(from, ""))
		if err != nil || unknownCode != ExitUnknown || !communityClaim(report, "UNKNOWN") {
			return communityExampleResult{}, fmt.Errorf("Envoy %s missing xDS declaration did not remain UNKNOWN", from)
		}
	}
	return communityExampleResult{Example: "cncf-envoy-latest", BlockedExit: blockedCode, CleanExit: cleanCode, UnknownExit: unknownCode, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) runCoreDNSLatestExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-coredns-latest-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private CoreDNS example directory: %w", err)
	}
	defer os.RemoveAll(work)
	input := func(from, distribution, directive string) []byte {
		facts := fmt.Sprintf(`{"id":"component.coredns.distribution","state":"declared","enumValue":%q}`, distribution)
		if directive != "" {
			facts += fmt.Sprintf(`,{"id":"component.coredns.federation_directive_present","state":"declared","boolValue":%s}`, directive)
		}
		return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/coredns/coredns","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/coredns/coredns","version":"1.14.7","facts":[%s]}]}}`, from, facts))
	}
	var blockedCode, cleanCode, unknownCode int
	var report map[string]any
	for _, from := range []string{"1.13.2", "1.12.4", "1.11.4", "1.10.1", "1.9.4"} {
		blockedCode, report, err = r.checkLatestGenericExample(work, "coredns", input(from, "official", "true"))
		if err != nil || blockedCode != ExitBlocked || !communityClaim(report, "BLOCKED") {
			return communityExampleResult{}, fmt.Errorf("CoreDNS %s official federation declaration did not produce scoped BLOCKED", from)
		}
		cleanCode, report, err = r.checkLatestGenericExample(work, "coredns", input(from, "official", "false"))
		if err != nil || cleanCode != ExitOK || !communityClaim(report, "PASS") {
			return communityExampleResult{}, fmt.Errorf("CoreDNS %s official federation absence did not produce scoped PASS", from)
		}
		unknownCode, report, err = r.checkLatestGenericExample(work, "coredns", input(from, "official", ""))
		if err != nil || unknownCode != ExitUnknown || !communityClaim(report, "UNKNOWN") {
			return communityExampleResult{}, fmt.Errorf("CoreDNS %s missing directive declaration did not remain UNKNOWN", from)
		}
		unknownCode, report, err = r.checkLatestGenericExample(work, "coredns", input(from, "custom", "true"))
		if err != nil || unknownCode != ExitUnknown || !communityClaim(report, "UNKNOWN") {
			return communityExampleResult{}, fmt.Errorf("CoreDNS %s custom distribution did not remain UNKNOWN", from)
		}
	}
	return communityExampleResult{Example: "cncf-coredns-latest", BlockedExit: blockedCode, CleanExit: cleanCode, UnknownExit: unknownCode, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) checkLatestGenericExample(work, project string, raw []byte) (int, map[string]any, error) {
	path := filepath.Join(work, project+"-input.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return 0, nil, fmt.Errorf("write private %s input: %w", project, err)
	}
	var stdout bytes.Buffer
	child := r
	child.stdout = &stdout
	code := child.cncf([]string{"--project", project, "--input", path, "--input-digest", communityDigest(raw), "--now", "2026-09-12T09:01:00Z", "--format", "json"})
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return code, nil, fmt.Errorf("decode %s report: %w", project, err)
	}
	return code, report, nil
}
