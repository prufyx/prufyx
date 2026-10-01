// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"
)

const jaegerNativeAuthority = "OPERATOR_DECLARED_DIRECT_OFFICIAL_JAEGER_V2_ARGUMENTS_ONLY"

func jaegerNativeDeclaration(configArg string) []byte {
	if configArg == "" {
		return []byte(`{"authority":"` + jaegerNativeAuthority + `","argv":[]}`)
	}
	return []byte(`{"authority":"` + jaegerNativeAuthority + `","argv":["--config=` + configArg + `"]}`)
}

func jaegerNativeArgs(path, from, to string, nonMemory, official string) []string {
	args := []string{
		"check", "cncf", "--project", "jaeger", "--jaeger-argv", path,
		"--from", from, "--to", to, "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
	if nonMemory != "" {
		args = append(args, "--non-memory-storage-required", nonMemory)
	}
	if official != "" {
		args = append(args, "--official-jaeger-distribution", official)
	}
	return args
}

// The native one-step route reuses the already-reviewed PrepareJaeger
// adapter; this exercises it end to end for the 1.76.0 -> 2.20.0 pair without
// a separate prepare step. The reviewed rule only forbids the predicate when
// non-memory storage and official distribution are both explicitly declared
// true and the config is definitely absent; declared presence yields a
// genuine positive-witness PASS, never a negative-presence one.
func TestJaegerNativeCheck_BoundedOutcomesAndPrivacy(t *testing.T) {
	const canary = "private-jaeger-native-canary-9c31"
	for _, test := range []struct {
		name, configArg, nonMemory, official, reason string
		want                                         int
	}{
		{"explicit config passes", "/etc/jaeger/" + canary + ".yaml", "true", "true", "REVIEWED_SOURCE_CONSTRAINT", ExitOK},
		{"absent config stays unknown, never a negative-presence pass", "", "true", "true", "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"declarations omitted stays unknown", "/etc/jaeger/" + canary + ".yaml", "", "", "RULE_APPLICABILITY_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := jaegerNativeDeclaration(test.configArg)
			path := writeCNCFFile(t, "jaeger.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, jaegerNativeArgs(path, "1.76.0", "2.20.0", test.nonMemory, test.official)...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, canary) || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN.
func TestJaegerNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	raw := jaegerNativeDeclaration("/etc/jaeger/config.yaml")
	path := writeCNCFFile(t, "jaeger.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, jaegerNativeArgs(path, "1.76.0", "2.20.0", "true", "true")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 2.20.0 target-only origins are routed through the same
// native path.
func TestJaegerNativeCheck_AllTargetOriginsAreRouted(t *testing.T) {
	for _, tc := range []struct{ from, ruleID string }{
		{"2.15.1", "jaeger.explicit-config-required-for-non-memory.target.2-15-to-2-20"},
		{"2.16.0", "jaeger.explicit-config-required-for-non-memory.target.2-16-to-2-20"},
		{"2.17.0", "jaeger.explicit-config-required-for-non-memory.target.2-17-to-2-20"},
		{"2.18.0", "jaeger.explicit-config-required-for-non-memory.target.2-18-to-2-20"},
		{"2.19.0", "jaeger.explicit-config-required-for-non-memory.target.2-19-to-2-20"},
	} {
		t.Run(tc.from, func(t *testing.T) {
			raw := jaegerNativeDeclaration("/etc/jaeger/config.yaml")
			path := writeCNCFFile(t, "jaeger-latest.json", raw, 0o600)
			code, stdout, stderr := runCNCFCLI(t, jaegerNativeArgs(path, tc.from, "2.20.0", "true", "true")...)
			if code != ExitOK || stderr != "" || !strings.Contains(stdout, tc.ruleID) || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s code=%d stdout=%q stderr=%q", tc.from, code, stdout, stderr)
			}
		})
	}
}

func TestJaegerNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	raw := jaegerNativeDeclaration("/etc/jaeger/config.yaml")
	path := writeCNCFFile(t, "jaeger.json", raw, 0o600)
	code, stdout, stderr := runCNCFCLI(t, jaegerNativeArgs(path, "1.76.0", "2.20.1", "true", "true")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, jaegerNativeArgs(path, "1.76.0", "2.20.0", "maybe", "true")...)
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, path) {
		t.Fatalf("bad tri-state code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "falco", "--jaeger-argv", "PRIVATE-NOT-READ.json", "--from", "0.40.0", "--to", "0.41.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" || strings.Contains(stderr, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "jaeger", "--jaeger-argv", path, "--native-resource", path, "--from", "1.76.0", "--to", "2.20.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitUsage || stdout != "" {
		t.Fatalf("cross-mode selector code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestJaegerNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	raw := jaegerNativeDeclaration("/etc/jaeger/config.yaml")
	path := writeCNCFFile(t, "jaeger.json", raw, 0o600)
	otherRaw := jaegerNativeDeclaration("/etc/jaeger/other.yaml")
	args := append(jaegerNativeArgs(path, "1.76.0", "2.20.0", "true", "true"), "--jaeger-argv-digest", cncfDigest(otherRaw))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "PASS") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestJaegerPrepareFeedsNativeCheckEquivalently(t *testing.T) {
	raw := jaegerNativeDeclaration("/etc/jaeger/config.yaml")
	path := writeCNCFFile(t, "jaeger.json", raw, 0o600)
	code, canonical, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "jaeger", "--input", path, "--from", "1.76.0", "--to", "2.20.0", "--non-memory-storage-required", "true", "--official-jaeger-distribution", "true", "--format", "input")
	if code != ExitOK || stderr != "" || !strings.Contains(canonical, "component.jaeger.explicit_config_provided") {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, canonical, stderr)
	}
	prepared := writeCNCFFile(t, "jaeger-canonical.json", []byte(canonical), 0o600)
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "jaeger", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitOK || stderr != "" || !strings.Contains(report, `"status":"PASS"`) {
		t.Fatalf("check code=%d stdout=%q stderr=%q", code, report, stderr)
	}
	nativeCode, nativeReport, nativeErr := runCNCFCLI(t, jaegerNativeArgs(path, "1.76.0", "2.20.0", "true", "true")...)
	if nativeCode != code || nativeErr != "" || !strings.Contains(nativeReport, `"status":"PASS"`) {
		t.Fatalf("native code=%d stdout=%q stderr=%q", nativeCode, nativeReport, nativeErr)
	}
}
