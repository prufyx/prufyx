// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"strings"
	"testing"
)

func TestEnvoyLatestGenericInputAllExactOrigins(t *testing.T) {
	t.Parallel()
	input := func(from, to, major string) []byte {
		fact := ""
		if major != "" {
			fact = fmt.Sprintf(`{"id":"component.envoy.xds_api_major","state":"declared","enumValue":%q}`, major)
		}
		return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/envoyproxy/envoy","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/envoyproxy/envoy","version":%q,"facts":[%s]}]}}`, from, to, fact))
	}
	for _, from := range []string{"1.38.4", "1.37.6", "1.36.10", "1.35.13", "1.34.14"} {
		for _, tc := range []struct {
			name, major, status string
			ambiguous           bool
			want                int
		}{{"v2-blocked", "v2", "BLOCKED", false, ExitBlocked}, {"v3-pass", "v3", "PASS", false, ExitOK}, {"missing-unknown", "", "UNKNOWN", false, ExitUnknown}, {"ambiguous-unknown", "v2", "UNKNOWN", true, ExitUnknown}} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				raw := input(from, "1.39.1", tc.major)
				if tc.ambiguous {
					raw = []byte(strings.Replace(string(raw), `"state":"declared","enumValue":"v2"`, `"state":"conflict"`, 1))
				}
				path := writeCNCFFile(t, "envoy-latest.json", raw, 0o600)
				code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "envoy", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T09:01:00Z", "--format", "json")
				if code != tc.want || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
					t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
				}
				if tc.status != "UNKNOWN" && !strings.Contains(output, `"status":"`+tc.status+`"`) {
					t.Fatalf("missing %s claim: %s", tc.status, output)
				}
			})
		}
	}
	// Controls moved outside the reviewed Envoy range (1.38-1.39): an origin
	// below it and a target past it.
	for _, pair := range [][2]string{{"1.37.5", "1.39.1"}, {"1.38.4", "1.40.0"}} {
		raw := input(pair[0], pair[1], "v2")
		path := writeCNCFFile(t, "envoy-wrong-pair.json", raw, 0o600)
		code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "envoy", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T09:01:00Z", "--format", "json")
		if code != ExitUnknown || stderr != "" || !strings.Contains(output, "RULE_TRANSITION_NOT_REVIEWED") {
			t.Fatalf("pair=%v code=%d stderr=%q output=%s", pair, code, stderr, output)
		}
	}
	// The two pairs the wrong-pair control used before the 1.38 to 1.39
	// line-wide range: both are inside it, so they are decided range matches.
	for _, pair := range [][2]string{{"1.38.3", "1.39.1"}, {"1.38.4", "1.39.0"}} {
		for _, c := range []struct {
			major, status string
			want          int
		}{{"v2", "BLOCKED", ExitBlocked}, {"v3", "PASS", ExitOK}} {
			raw := input(pair[0], pair[1], c.major)
			path := writeCNCFFile(t, "envoy-range.json", raw, 0o600)
			code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "envoy", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T09:01:00Z", "--format", "json")
			if code != c.want || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
				t.Fatalf("pair=%v code=%d stderr=%q output=%s", pair, code, stderr, output)
			}
			assertRangeClaim(t, output, "envoy.xds-v2-unsupported-at-1-39-1-from-1-38-4", c.status)
		}
	}
}

func TestCoreDNSLatestGenericInputAllExactOrigins(t *testing.T) {
	t.Parallel()
	input := func(from, to, distribution, directive string) []byte {
		facts := ""
		if distribution != "" {
			facts = fmt.Sprintf(`{"id":"component.coredns.distribution","state":"declared","enumValue":%q}`, distribution)
		}
		if directive != "" {
			if facts != "" {
				facts += ","
			}
			facts += fmt.Sprintf(`{"id":"component.coredns.federation_directive_present","state":"declared","boolValue":%s}`, directive)
		}
		return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/coredns/coredns","version":%q,"facts":[]}]},"proposed":{"components":[{"component":"pkg:github/coredns/coredns","version":%q,"facts":[%s]}]}}`, from, to, facts))
	}
	for _, from := range []string{"1.13.2", "1.12.4", "1.11.4", "1.10.1", "1.9.4"} {
		for _, tc := range []struct {
			name, distribution, directive, status string
			ambiguous                             bool
			want                                  int
		}{{"official-federation-blocked", "official", "true", "BLOCKED", false, ExitBlocked}, {"official-absent-pass", "official", "false", "PASS", false, ExitOK}, {"missing-directive-unknown", "official", "", "UNKNOWN", false, ExitUnknown}, {"custom-build-unknown", "custom", "true", "UNKNOWN", false, ExitUnknown}, {"ambiguous-unknown", "official", "true", "UNKNOWN", true, ExitUnknown}} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				raw := input(from, "1.14.7", tc.distribution, tc.directive)
				if tc.ambiguous {
					raw = []byte(strings.Replace(string(raw), `"id":"component.coredns.federation_directive_present","state":"declared","boolValue":true`, `"id":"component.coredns.federation_directive_present","state":"conflict"`, 1))
				}
				path := writeCNCFFile(t, "coredns-latest.json", raw, 0o600)
				code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "coredns", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T09:01:00Z", "--format", "json")
				if code != tc.want || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
					t.Fatalf("code=%d stderr=%q output=%s", code, stderr, output)
				}
				if tc.status != "UNKNOWN" && !strings.Contains(output, `"status":"`+tc.status+`"`) {
					t.Fatalf("missing %s claim: %s", tc.status, output)
				}
			})
		}
	}
	// Controls moved outside the reviewed CoreDNS range (1.13-1.14): an origin
	// below it and a target past it.
	for _, pair := range [][2]string{{"1.12.3", "1.14.7"}, {"1.13.2", "1.15.0"}} {
		raw := input(pair[0], pair[1], "official", "true")
		path := writeCNCFFile(t, "coredns-wrong-pair.json", raw, 0o600)
		code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "coredns", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T09:01:00Z", "--format", "json")
		if code != ExitUnknown || stderr != "" || !strings.Contains(output, "RULE_TRANSITION_NOT_REVIEWED") {
			t.Fatalf("pair=%v code=%d stderr=%q output=%s", pair, code, stderr, output)
		}
	}
	// The two pairs the wrong-pair control used before the 1.13 to 1.14
	// line-wide range: both are inside it, so they are decided range matches.
	for _, pair := range [][2]string{{"1.13.1", "1.14.7"}, {"1.13.2", "1.14.6"}} {
		for _, c := range []struct {
			directive, status string
			want              int
		}{{"true", "BLOCKED", ExitBlocked}, {"false", "PASS", ExitOK}} {
			raw := input(pair[0], pair[1], "official", c.directive)
			path := writeCNCFFile(t, "coredns-range.json", raw, 0o600)
			code, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "coredns", "--input", path, "--input-digest", cncfDigest(raw), "--now", "2026-09-12T09:01:00Z", "--format", "json")
			if code != c.want || stderr != "" || !strings.Contains(output, `"assessment":"UNKNOWN"`) {
				t.Fatalf("pair=%v code=%d stderr=%q output=%s", pair, code, stderr, output)
			}
			assertRangeClaim(t, output, "coredns.official-federation-absent-at-1-14-7-from-1-13-2", c.status)
		}
	}
}
