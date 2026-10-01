// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const kumaCleanArgv = `["kumactl","install","transparent-proxy","--exclude-outbound-ports-for-uids","tcp:3000:1000"]`
const kumaRemovedArgv = `["kumactl","install","transparent-proxy","--exclude-outbound-tcp-ports-for-uids","3000:1000"]`

func TestPrepareKumaInstallTransparentProxyArgv_BoundedRemovedSpellings(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		state             State
	}{
		{"clean argv with consolidated flag", kumaCleanArgv, string(ReasonKumaRemovedFlagsAbsent), StatePrepared},
		{"bare subcommand", `["kumactl","install","transparent-proxy"]`, string(ReasonKumaRemovedFlagsAbsent), StatePrepared},
		{"absolute path executable", `["/usr/local/bin/kumactl","install","transparent-proxy"]`, string(ReasonKumaRemovedFlagsAbsent), StatePrepared},
		{"removed tcp spelling", kumaRemovedArgv, string(ReasonKumaRemovedFlagsPresent), StatePrepared},
		{"removed udp spelling", `["kumactl","install","transparent-proxy","--exclude-outbound-udp-ports-for-uids","53:1000"]`, string(ReasonKumaRemovedFlagsPresent), StatePrepared},
		{"removed spelling attached value", `["kumactl","install","transparent-proxy","--exclude-outbound-tcp-ports-for-uids=3000:1000"]`, string(ReasonKumaRemovedFlagsPresent), StatePrepared},
		// A removed spelling supplied as another option's value is still a
		// literal occurrence in the declared argv, which is exactly what the
		// reviewed fact predicate names. It must never be silently skipped.
		{"removed spelling in value position", `["kumactl","install","transparent-proxy","--kuma-cp-ip","--exclude-outbound-udp-ports-for-uids"]`, string(ReasonKumaRemovedFlagsPresent), StatePrepared},
		// The consolidated target-supported form is not the removed spelling and
		// is never treated as equivalent to it in either direction.
		{"consolidated flag alone is not removed", `["kumactl","install","transparent-proxy","--exclude-outbound-ports-for-uids","udp:53:1000"]`, string(ReasonKumaRemovedFlagsAbsent), StatePrepared},
		{"unrelated long option", `["kumactl","install","transparent-proxy","--redirect-dns"]`, string(ReasonKumaRemovedFlagsAbsent), StatePrepared},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKumaInstallTransparentProxyArgv([]byte(test.raw), KumaFrom, KumaTo, KumaDistributionOfficial)
			if err != nil || prepared.Reason != Reason(test.reason) || prepared.State != test.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "transparent-proxy") {
				t.Fatalf("canonical input retained supplied tokens: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

// A clustered or value-attached short token can hide a spelling from a literal
// comparison, and an option delimiter leaves the remaining tokens' treatment
// unestablished. Both must stay UNKNOWN, never a PASS.
func TestPrepareKumaInstallTransparentProxyArgv_AmbiguousTokensStayUnknown(t *testing.T) {
	for _, raw := range []string{
		`["kumactl","install","transparent-proxy","-vv"]`,
		`["kumactl","install","transparent-proxy","--"]`,
		`["kumactl","install","transparent-proxy","-"]`,
		`["kumactl","install","transparent-proxy","--","--exclude-outbound-tcp-ports-for-uids"]`,
	} {
		prepared, err := PrepareKumaInstallTransparentProxyArgv([]byte(raw), KumaFrom, KumaTo, KumaDistributionOfficial)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKumaArgvUnresolved {
			t.Fatalf("raw=%s prepared=%+v err=%v", raw, prepared, err)
		}
		if strings.Contains(string(prepared.CanonicalInputJSON), `"state":"declared","boolValue"`) {
			t.Fatalf("raw=%s declared a presence predicate: %s", raw, prepared.CanonicalInputJSON)
		}
	}
}

func TestPrepareKumaInstallTransparentProxyArgv_OtherCommandSurfacesStayUnknown(t *testing.T) {
	for _, raw := range []string{
		`["kumactl","install","control-plane"]`,
		`["kumactl","install"]`,
		`["kumactl","get","dataplanes"]`,
		`["kuma-dp","run"]`,
		`["sh","-c","kumactl install transparent-proxy"]`,
		// Cobra tolerates global options before the subcommand, but the reviewed
		// evidence scopes the rule to the direct command path only.
		`["kumactl","--config-file","/etc/kumactl.yaml","install","transparent-proxy"]`,
	} {
		prepared, err := PrepareKumaInstallTransparentProxyArgv([]byte(raw), KumaFrom, KumaTo, KumaDistributionOfficial)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKumaSurfaceOther {
			t.Fatalf("raw=%s prepared=%+v err=%v", raw, prepared, err)
		}
		if !strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"`+KumaSurfaceOther+`"`) {
			t.Fatalf("raw=%s surface not declared other: %s", raw, prepared.CanonicalInputJSON)
		}
	}
}

func TestPrepareKumaInstallTransparentProxyArgv_GuardsPrecedeArgvClassification(t *testing.T) {
	tests := []struct {
		name, from, to, distribution, reason string
	}{
		{"unreviewed origin", "2.7.0", KumaTo, KumaDistributionOfficial, string(ReasonKumaPairUnsupported)},
		{"unreviewed target", KumaFrom, "2.10.0", KumaDistributionOfficial, string(ReasonKumaPairUnsupported)},
		{"missing distribution", KumaFrom, KumaTo, "", string(ReasonKumaGuardUnresolved)},
		{"unknown distribution token", KumaFrom, KumaTo, "vendor_build", string(ReasonKumaGuardUnresolved)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKumaInstallTransparentProxyArgv([]byte(kumaRemovedArgv), test.from, test.to, test.distribution)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

// A custom build is a declared fact, not a guard failure: the adapter still
// derives the argv fact and lets the rule's own applicability keep the claim
// UNKNOWN. This must never become a PASS route for unreviewed builds.
func TestPrepareKumaInstallTransparentProxyArgv_CustomBuildStaysDeclaredNotOfficial(t *testing.T) {
	prepared, err := PrepareKumaInstallTransparentProxyArgv([]byte(kumaCleanArgv), KumaFrom, KumaTo, KumaDistributionCustom)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonKumaRemovedFlagsAbsent {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if !strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"`+KumaDistributionCustom+`"`) {
		t.Fatalf("custom build not declared: %s", prepared.CanonicalInputJSON)
	}
}

func TestPrepareKumaInstallTransparentProxyArgv_UnresolvedShapesStayUnknown(t *testing.T) {
	tests := []struct {
		name, raw, reason string
	}{
		{"template marker", `["kumactl","install","transparent-proxy","{{ .Values.extraArgs }}"]`, string(ReasonKumaTemplated)},
		{"shell substitution", `["kumactl","install","transparent-proxy","${EXTRA_ARGS}"]`, string(ReasonKumaTemplated)},
		{"object root", `{"command":["kumactl","install","transparent-proxy"]}`, string(ReasonKumaInputUnsupported)},
		{"scalar root", `"kumactl"`, string(ReasonKumaInputUnsupported)},
		{"empty array", `[]`, string(ReasonKumaInputUnsupported)},
		{"non-string item", `["kumactl","install","transparent-proxy",7]`, string(ReasonKumaInputUnsupported)},
		{"empty token", `["kumactl","install","transparent-proxy",""]`, string(ReasonKumaInputUnsupported)},
		{"nested array", `["kumactl","install",["transparent-proxy"]]`, string(ReasonKumaInputUnsupported)},
		{"truncated json", `["kumactl","install",`, string(ReasonKumaInputUnsupported)},
		{"duplicate keys object", `{"a":1,"a":2}`, string(ReasonKumaInputUnsupported)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKumaInstallTransparentProxyArgv([]byte(test.raw), KumaFrom, KumaTo, KumaDistributionOfficial)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

func TestPrepareKumaInstallTransparentProxyArgv_RejectsRawBoundsAndVersionSyntax(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0xff},
		make([]byte, maxInputBytes+1),
	} {
		if _, err := PrepareKumaInstallTransparentProxyArgv(raw, KumaFrom, KumaTo, KumaDistributionOfficial); err == nil {
			t.Fatalf("accepted raw input of %d bytes", len(raw))
		}
	}
	for _, from := range []string{"", "2.8", "v2.8.0", KumaTo} {
		if _, err := PrepareKumaInstallTransparentProxyArgv([]byte(kumaCleanArgv), from, KumaTo, KumaDistributionOfficial); err == nil {
			t.Fatalf("accepted from version %q", from)
		}
	}
}

func TestPrepareKumaInstallTransparentProxyArgv_DigestsAndOmissionsAreStable(t *testing.T) {
	first, err := PrepareKumaInstallTransparentProxyArgv([]byte(kumaRemovedArgv), KumaFrom, KumaTo, KumaDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareKumaInstallTransparentProxyArgv([]byte(kumaRemovedArgv), KumaFrom, KumaTo, KumaDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceDigest != second.SourceDigest || first.InputDigest != second.InputDigest {
		t.Fatalf("unstable digests %+v %+v", first, second)
	}
	if first.SourceDigest != digestBytes([]byte(kumaRemovedArgv)) || first.InputDigest != digestBytes(first.CanonicalInputJSON) {
		t.Fatalf("digest bindings %+v", first)
	}
	if len(first.Omissions) != 4 || first.Omissions[3] != OmissionNoWholeUpgrade || first.Omissions[2] != OmissionNoLiveObservation {
		t.Fatalf("omissions = %v", first.Omissions)
	}
}

// The shared argv scan is the only place Falco and Kuma overlap. Its safety
// property is the one that must hold for both: a removed spelling is never
// skipped because another option might have consumed it as a value.
func TestScanRemovedArgvSpellings_SharedSafetyProperty(t *testing.T) {
	removed := map[string]bool{"-A": true, "--snaplen": true}
	tests := []struct {
		name             string
		tokens           []string
		present, resolve bool
	}{
		{"absent", []string{"-c", "path"}, false, true},
		{"exact short", []string{"-A"}, true, true},
		{"exact long", []string{"--snaplen"}, true, true},
		{"long with attached value", []string{"--snaplen=256"}, true, true},
		{"after an unknown long option", []string{"--unknown", "-A"}, true, true},
		{"longer long option is distinct", []string{"--snaplength"}, false, true},
		{"clustered short is unresolved", []string{"-Ab"}, false, false},
		{"attached short value is unresolved", []string{"-S256"}, false, false},
		{"delimiter is unresolved", []string{"--"}, false, false},
		{"bare dash is unresolved", []string{"-"}, false, false},
		{"positionals are not options", []string{"value", "another"}, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			present, resolved := scanRemovedArgvSpellings(test.tokens, removed)
			if present != test.present || resolved != test.resolve {
				t.Fatalf("present=%v resolved=%v", present, resolved)
			}
		})
	}
}

func TestArgvExecutableMatches_BoundedSpellings(t *testing.T) {
	for _, token := range []string{"kumactl", "/usr/bin/kumactl", "./kumactl", "../bin/kumactl"} {
		if !argvExecutableMatches(token, "kumactl") {
			t.Fatalf("rejected %q", token)
		}
	}
	for _, token := range []string{"", "kumactl-extra", "mykumactl", "usr/bin/kumactl", "kumactl arg", "/usr/bin/kuma-dp"} {
		if argvExecutableMatches(token, "kumactl") {
			t.Fatalf("accepted %q", token)
		}
	}
}
