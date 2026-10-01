// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const spireCleanArgv = `["spire-server","entry","create","-spiffeID","spiffe://private-trust/workload","-parentID","spiffe://private-trust/agent","-selector","unix:uid:1000"]`
const spireRemovedArgv = `["spire-server","entry","create","-spiffeID","spiffe://private-trust/workload","-ttl","3600"]`

func TestPrepareSpireEntryCreateArgv_BoundedRemovedSpellings(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		state             State
	}{
		{"clean argv", spireCleanArgv, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
		{"bare subcommand", `["spire-server","entry","create"]`, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
		{"absolute path executable", `["/opt/spire/bin/spire-server","entry","create","-selector","unix:uid:1000"]`, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
		{"relative path executable", `["./spire-server","entry","create"]`, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
		{"removed single dash spelling", spireRemovedArgv, string(ReasonSpireRemovedTTLPresent), StatePrepared},
		{"removed double dash spelling", `["spire-server","entry","create","--ttl","3600"]`, string(ReasonSpireRemovedTTLPresent), StatePrepared},
		{"removed single dash attached value", `["spire-server","entry","create","-ttl=3600"]`, string(ReasonSpireRemovedTTLPresent), StatePrepared},
		{"removed double dash attached value", `["spire-server","entry","create","--ttl=3600"]`, string(ReasonSpireRemovedTTLPresent), StatePrepared},
		// A removed spelling supplied as another option's value is still a
		// literal occurrence in the declared argv, which is exactly what the
		// reviewed fact predicate names. It must never be silently skipped.
		{"removed spelling in value position", `["spire-server","entry","create","-selector","-ttl"]`, string(ReasonSpireRemovedTTLPresent), StatePrepared},
		// The replacement options are not the removed spelling and are never
		// validated here; only the two removed spellings are decided.
		{"replacement ttl options are not the removed spelling", `["spire-server","entry","create","-x509SVIDTTL","3600","-jwtSVIDTTL","600"]`, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
		{"single dash long option is not clustered", `["spire-server","entry","create","-socketPath","/run/private-spire/api.sock"]`, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
		{"similar option name is not the removed spelling", `["spire-server","entry","create","-ttlSeconds","3600"]`, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
		{"positional after options", `["spire-server","entry","create","-selector","unix:uid:1000","private-positional"]`, string(ReasonSpireRemovedTTLAbsent), StatePrepared},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareSpireEntryCreateArgv([]byte(test.raw), SpireFrom, SpireTo, SpireDistributionOfficial)
			if err != nil || prepared.Reason != Reason(test.reason) || prepared.State != test.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "private-") {
				t.Fatalf("canonical input retained private tokens: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

// An option delimiter leaves the remaining tokens' treatment unestablished by
// the pinned parser evidence. That must stay UNKNOWN, never a PASS.
func TestPrepareSpireEntryCreateArgv_DelimiterStaysUnknown(t *testing.T) {
	for _, raw := range []string{
		`["spire-server","entry","create","--"]`,
		`["spire-server","entry","create","-"]`,
		`["spire-server","entry","create","--","-ttl"]`,
		`["spire-server","entry","create","-selector","unix:uid:1000","--","3600"]`,
	} {
		prepared, err := PrepareSpireEntryCreateArgv([]byte(raw), SpireFrom, SpireTo, SpireDistributionOfficial)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonSpireArgvUnresolved {
			t.Fatalf("raw=%s prepared=%+v err=%v", raw, prepared, err)
		}
		if strings.Contains(string(prepared.CanonicalInputJSON), `"`+SpireRemovedTTLFact+`","state":"declared"`) {
			t.Fatalf("raw=%s declared a presence predicate: %s", raw, prepared.CanonicalInputJSON)
		}
	}
}

func TestPrepareSpireEntryCreateArgv_OtherCommandSurfacesStayUnknown(t *testing.T) {
	for _, raw := range []string{
		`["spire-server","entry","update","-ttl","3600"]`,
		`["spire-server","entry"]`,
		`["spire-server","token","generate"]`,
		`["spire-agent","api","fetch"]`,
		`["sh","-c","spire-server entry create -ttl 3600"]`,
		`["/bin/sh","spire-server"]`,
		`["spire-server -v","entry","create"]`,
		`["opt/spire/spire-server","entry","create"]`,
		`["spire-server","-socketPath","/run/api.sock","entry","create"]`,
	} {
		prepared, err := PrepareSpireEntryCreateArgv([]byte(raw), SpireFrom, SpireTo, SpireDistributionOfficial)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonSpireSurfaceOther {
			t.Fatalf("raw=%s prepared=%+v err=%v", raw, prepared, err)
		}
		if !strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"`+SpireSurfaceOther+`"`) {
			t.Fatalf("raw=%s surface not declared other: %s", raw, prepared.CanonicalInputJSON)
		}
	}
}

func TestPrepareSpireEntryCreateArgv_GuardsPrecedeArgvClassification(t *testing.T) {
	tests := []struct {
		name, from, to, distribution, reason string
	}{
		{"unreviewed origin", "1.10.3", SpireTo, SpireDistributionOfficial, string(ReasonSpirePairUnsupported)},
		{"unreviewed target", SpireFrom, "1.12.0", SpireDistributionOfficial, string(ReasonSpirePairUnsupported)},
		{"missing distribution", SpireFrom, SpireTo, "", string(ReasonSpireGuardUnresolved)},
		{"unknown distribution token", SpireFrom, SpireTo, "vendor_build", string(ReasonSpireGuardUnresolved)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareSpireEntryCreateArgv([]byte(spireRemovedArgv), test.from, test.to, test.distribution)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

// A custom build is a declared fact, not a guard failure: the adapter still
// derives the argv fact and lets the rule's own applicability keep the claim
// UNKNOWN. This must never become a PASS route for unreviewed builds.
func TestPrepareSpireEntryCreateArgv_CustomBuildStaysDeclaredNotOfficial(t *testing.T) {
	prepared, err := PrepareSpireEntryCreateArgv([]byte(spireCleanArgv), SpireFrom, SpireTo, SpireDistributionCustom)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonSpireRemovedTTLAbsent {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if !strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"`+SpireDistributionCustom+`"`) {
		t.Fatalf("custom build not declared: %s", prepared.CanonicalInputJSON)
	}
}

func TestPrepareSpireEntryCreateArgv_UnresolvedShapesStayUnknown(t *testing.T) {
	tests := []struct {
		name, raw, reason string
	}{
		{"template marker", `["spire-server","entry","create","-ttl","{{ .Values.ttl }}"]`, string(ReasonSpireTemplated)},
		{"shell substitution", `["spire-server","entry","create","${EXTRA_ARGS}"]`, string(ReasonSpireTemplated)},
		{"object root", `{"command":["spire-server","entry","create"]}`, string(ReasonSpireInputUnsupported)},
		{"scalar root", `"spire-server entry create"`, string(ReasonSpireInputUnsupported)},
		{"empty array", `[]`, string(ReasonSpireInputUnsupported)},
		{"non-string item", `["spire-server","entry","create",7]`, string(ReasonSpireInputUnsupported)},
		{"empty token", `["spire-server","entry","create",""]`, string(ReasonSpireInputUnsupported)},
		{"nested array", `["spire-server","entry","create",["-ttl"]]`, string(ReasonSpireInputUnsupported)},
		{"truncated json", `["spire-server","entry",`, string(ReasonSpireInputUnsupported)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareSpireEntryCreateArgv([]byte(test.raw), SpireFrom, SpireTo, SpireDistributionOfficial)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

func TestPrepareSpireEntryCreateArgv_RejectsRawBoundsAndVersionSyntax(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0xff},
		make([]byte, maxInputBytes+1),
	} {
		if _, err := PrepareSpireEntryCreateArgv(raw, SpireFrom, SpireTo, SpireDistributionOfficial); err == nil {
			t.Fatalf("accepted raw input of %d bytes", len(raw))
		}
	}
	for _, from := range []string{"", "1.10", "v1.10.4", SpireTo} {
		if _, err := PrepareSpireEntryCreateArgv([]byte(spireCleanArgv), from, SpireTo, SpireDistributionOfficial); err == nil {
			t.Fatalf("accepted from version %q", from)
		}
	}
}

func TestPrepareSpireEntryCreateArgv_DigestsAndOmissionsAreStable(t *testing.T) {
	first, err := PrepareSpireEntryCreateArgv([]byte(spireRemovedArgv), SpireFrom, SpireTo, SpireDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareSpireEntryCreateArgv([]byte(spireRemovedArgv), SpireFrom, SpireTo, SpireDistributionOfficial)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceDigest != second.SourceDigest || first.InputDigest != second.InputDigest {
		t.Fatalf("unstable digests %+v %+v", first, second)
	}
	if first.SourceDigest != digestBytes([]byte(spireRemovedArgv)) || first.InputDigest != digestBytes(first.CanonicalInputJSON) {
		t.Fatalf("digest bindings %+v", first)
	}
	if len(first.Omissions) != 4 || first.Omissions[3] != OmissionNoWholeUpgrade || first.Omissions[2] != OmissionNoLiveObservation {
		t.Fatalf("omissions = %v", first.Omissions)
	}
}
