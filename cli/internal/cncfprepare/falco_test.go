// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const falcoCleanArgv = `["falco","-c","/etc/private-falco.yaml","--unbuffered"]`
const falcoRemovedArgv = `["falco","-c","/etc/private-falco.yaml","--snaplen","256"]`

func TestPrepareFalcoArgv_BoundedRemovedSpellings(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		state             State
	}{
		{"clean argv", falcoCleanArgv, string(ReasonFalcoRemovedFlagsAbsent), StatePrepared},
		{"bare executable", `["falco"]`, string(ReasonFalcoRemovedFlagsAbsent), StatePrepared},
		{"absolute path executable", `["/usr/bin/falco","-c","/etc/private-falco.yaml"]`, string(ReasonFalcoRemovedFlagsAbsent), StatePrepared},
		{"relative path executable", `["./falco","-c","/etc/private-falco.yaml"]`, string(ReasonFalcoRemovedFlagsAbsent), StatePrepared},
		{"removed long spelling", falcoRemovedArgv, string(ReasonFalcoRemovedFlagsPresent), StatePrepared},
		{"removed long spelling attached value", `["falco","--snaplen=256"]`, string(ReasonFalcoRemovedFlagsPresent), StatePrepared},
		{"removed print-base64", `["falco","--print-base64"]`, string(ReasonFalcoRemovedFlagsPresent), StatePrepared},
		{"removed short -A", `["falco","-A"]`, string(ReasonFalcoRemovedFlagsPresent), StatePrepared},
		{"removed short -b", `["falco","-b"]`, string(ReasonFalcoRemovedFlagsPresent), StatePrepared},
		{"removed short -S", `["falco","-S","256"]`, string(ReasonFalcoRemovedFlagsPresent), StatePrepared},
		// A removed spelling supplied as another option's value is still a
		// literal occurrence in the declared argv, which is exactly what the
		// reviewed fact predicate names. It must never be silently skipped.
		{"removed spelling in value position", `["falco","--rule-name","-A"]`, string(ReasonFalcoRemovedFlagsPresent), StatePrepared},
		{"unknown long option is not a removed spelling", `["falco","--snaplength","256"]`, string(ReasonFalcoRemovedFlagsAbsent), StatePrepared},
		{"positional after options", `["falco","-c","/etc/private-falco.yaml","private-positional"]`, string(ReasonFalcoRemovedFlagsAbsent), StatePrepared},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareFalcoArgv([]byte(test.raw), FalcoFrom, FalcoTo041, FalcoDistributionOfficial)
			if err != nil || prepared.Reason != Reason(test.reason) || prepared.State != test.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "private-") {
				t.Fatalf("canonical input retained private tokens: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

// A clustered or value-attached short token can hide a removed short spelling
// from a literal comparison, and an option delimiter leaves the remaining
// tokens' treatment unestablished. Both must stay UNKNOWN, never a PASS.
func TestPrepareFalcoArgv_AmbiguousShortTokensStayUnknown(t *testing.T) {
	for _, raw := range []string{
		`["falco","-Ab"]`,
		`["falco","-S256"]`,
		`["falco","-cv"]`,
		`["falco","--"]`,
		`["falco","-"]`,
		`["falco","--","-A"]`,
	} {
		prepared, err := PrepareFalcoArgv([]byte(raw), FalcoFrom, FalcoTo041, FalcoDistributionOfficial)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonFalcoArgvUnresolved {
			t.Fatalf("raw=%s prepared=%+v err=%v", raw, prepared, err)
		}
		if strings.Contains(string(prepared.CanonicalInputJSON), `"state":"declared","boolValue"`) {
			t.Fatalf("raw=%s declared a presence predicate: %s", raw, prepared.CanonicalInputJSON)
		}
	}
}

func TestPrepareFalcoArgv_OtherCommandSurfacesStayUnknown(t *testing.T) {
	for _, raw := range []string{
		`["falcoctl","install"]`,
		`["sh","-c","falco -A"]`,
		`["/bin/sh","falco"]`,
		`["falco-driver-loader"]`,
		`["falco extra","-c","x"]`,
		`["usr/bin/falco"]`,
	} {
		prepared, err := PrepareFalcoArgv([]byte(raw), FalcoFrom, FalcoTo041, FalcoDistributionOfficial)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonFalcoSurfaceOther {
			t.Fatalf("raw=%s prepared=%+v err=%v", raw, prepared, err)
		}
		if !strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"`+FalcoSurfaceOther+`"`) {
			t.Fatalf("raw=%s surface not declared other: %s", raw, prepared.CanonicalInputJSON)
		}
	}
}

func TestPrepareFalcoArgv_GuardsPrecedeArgvClassification(t *testing.T) {
	tests := []struct {
		name, from, to, distribution, reason string
	}{
		{"unreviewed origin", "0.39.0", FalcoTo041, FalcoDistributionOfficial, string(ReasonFalcoPairUnsupported)},
		{"unreviewed target", FalcoFrom, "0.43.0", FalcoDistributionOfficial, string(ReasonFalcoPairUnsupported)},
		{"missing distribution", FalcoFrom, FalcoTo041, "", string(ReasonFalcoGuardUnresolved)},
		{"unknown distribution token", FalcoFrom, FalcoTo042, "vendor_build", string(ReasonFalcoGuardUnresolved)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareFalcoArgv([]byte(falcoRemovedArgv), test.from, test.to, test.distribution)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

func TestPrepareFalcoArgv_BothReviewedTargetsResolve(t *testing.T) {
	for _, to := range []string{FalcoTo041, FalcoTo042} {
		prepared, err := PrepareFalcoArgv([]byte(falcoRemovedArgv), FalcoFrom, to, FalcoDistributionOfficial)
		if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonFalcoRemovedFlagsPresent {
			t.Fatalf("to=%s prepared=%+v err=%v", to, prepared, err)
		}
		if !strings.Contains(string(prepared.CanonicalInputJSON), `"version":"`+to+`"`) {
			t.Fatalf("to=%s canonical=%s", to, prepared.CanonicalInputJSON)
		}
	}
}

// A custom build is a declared fact, not a guard failure: the adapter still
// derives the argv fact and lets the rule's own applicability keep the claim
// UNKNOWN. This must never become a PASS route for unreviewed builds.
func TestPrepareFalcoArgv_CustomBuildStaysDeclaredNotOfficial(t *testing.T) {
	prepared, err := PrepareFalcoArgv([]byte(falcoCleanArgv), FalcoFrom, FalcoTo041, FalcoDistributionCustom)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonFalcoRemovedFlagsAbsent {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if !strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"`+FalcoDistributionCustom+`"`) {
		t.Fatalf("custom build not declared: %s", prepared.CanonicalInputJSON)
	}
}

func TestPrepareFalcoArgv_UnresolvedShapesStayUnknown(t *testing.T) {
	tests := []struct {
		name, raw, reason string
	}{
		{"template marker", `["falco","--snaplen","{{ .Values.snaplen }}"]`, string(ReasonFalcoTemplated)},
		{"shell substitution", `["falco","${EXTRA_ARGS}"]`, string(ReasonFalcoTemplated)},
		{"object root", `{"command":["falco"]}`, string(ReasonFalcoInputUnsupported)},
		{"scalar root", `"falco"`, string(ReasonFalcoInputUnsupported)},
		{"empty array", `[]`, string(ReasonFalcoInputUnsupported)},
		{"non-string item", `["falco",7]`, string(ReasonFalcoInputUnsupported)},
		{"empty token", `["falco",""]`, string(ReasonFalcoInputUnsupported)},
		{"nested array", `["falco",["-A"]]`, string(ReasonFalcoInputUnsupported)},
		{"truncated json", `["falco",`, string(ReasonFalcoInputUnsupported)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareFalcoArgv([]byte(test.raw), FalcoFrom, FalcoTo041, FalcoDistributionOfficial)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

func TestPrepareFalcoArgv_RejectsRawBoundsAndVersionSyntax(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0xff},
		make([]byte, maxInputBytes+1),
	} {
		if _, err := PrepareFalcoArgv(raw, FalcoFrom, FalcoTo041, FalcoDistributionOfficial); err == nil {
			t.Fatalf("accepted raw input of %d bytes", len(raw))
		}
	}
	for _, from := range []string{"", "0.40", "v0.40.0", FalcoTo041} {
		if _, err := PrepareFalcoArgv([]byte(falcoCleanArgv), from, FalcoTo041, FalcoDistributionOfficial); err == nil {
			t.Fatalf("accepted from version %q", from)
		}
	}
}

func TestPrepareFalcoArgv_DigestsAndOmissionsAreStable(t *testing.T) {
	first, err := PrepareFalcoArgv([]byte(falcoRemovedArgv), FalcoFrom, FalcoTo041, FalcoDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareFalcoArgv([]byte(falcoRemovedArgv), FalcoFrom, FalcoTo041, FalcoDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceDigest != second.SourceDigest || first.InputDigest != second.InputDigest {
		t.Fatalf("unstable digests %+v %+v", first, second)
	}
	if first.SourceDigest != digestBytes([]byte(falcoRemovedArgv)) || first.InputDigest != digestBytes(first.CanonicalInputJSON) {
		t.Fatalf("digest bindings %+v", first)
	}
	if len(first.Omissions) != 4 || first.Omissions[3] != OmissionNoWholeUpgrade || first.Omissions[2] != OmissionNoLiveObservation {
		t.Fatalf("omissions = %v", first.Omissions)
	}
}
