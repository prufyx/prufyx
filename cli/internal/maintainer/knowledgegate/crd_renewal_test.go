// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// agedExtractor makes a stored mechanical attestation look derived by an
// earlier build of its extractor, three days before the gate's clock.
func agedExtractor(a map[string]any) {
	ev := a["evidence"].(map[string]any)
	ev["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("0", 64)
	at := gateNow.Add(-72 * time.Hour)
	ev["derivedAt"] = at.Format(time.RFC3339)
	ev["reviewedAt"] = at.Format(time.RFC3339)
	ev["validUntil"] = at.Add(30 * 24 * time.Hour).Format(time.RFC3339)
}

// renewalTrees returns a base that stores the line 90.1 attestation as an
// earlier build derived it, and a head that holds the one the gate's build
// derives (changed by tamper).
func renewalTrees(t *testing.T, tamper func(a map[string]any)) (Tree, Tree) {
	t.Helper()
	base, head := crdAttestedTrees(t, func(_ map[string]any, derived []map[string]any) []map[string]any {
		a := attestationOfLine(derived, "90.1")
		if tamper != nil {
			tamper(a)
		}
		return []map[string]any{a}
	})
	editPack(t, base, cncfRulesPath, func(p *packDoc) {
		var records []map[string]any
		if err := json.Unmarshal(p.fields["lineAttestations"], &records); err != nil {
			t.Fatal(err)
		}
		for _, r := range records {
			agedExtractor(r)
		}
		raw, err := json.Marshal(records)
		if err != nil {
			t.Fatal(err)
		}
		p.fields["lineAttestations"] = raw
	})
	return base, head
}

// A shipped mechanical attestation replaced by one re-derived at a new
// extractor build is one loosening change of that record: re-derived by the
// gate's own build, no approval, and it counts toward the caps.
func TestGateRenewedMechanicalCRDAttestation(t *testing.T) {
	t.Parallel()
	base, head := renewalTrees(t, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
	requireAdmittedButUnsplit(t, r)
	if len(r.Changes) != 1 {
		t.Fatalf("changes %+v", r.Changes)
	}
	c := change(t, r, crdAttestationID("90.1"))
	if c.Proof != ProofRederived || c.Basis != "mechanical" || c.Class != ClassLoosening || !c.OK {
		t.Fatalf("change %+v", c)
	}
	if r.Limits.Loosening != 1 {
		t.Fatalf("limits %+v, want the renewal counted as one loosening change", r.Limits)
	}

	firstRelease := func(a map[string]any) map[string]any {
		return a["releases"].(map[string]any)["from"].([]any)[0].(map[string]any)
	}
	for name, tc := range map[string]struct {
		tamper func(a map[string]any)
		opts   func(o *Options)
		want   string
	}{
		"extractor identity is not the gate's": {func(a map[string]any) {
			a["evidence"].(map[string]any)["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("1", 64)
		}, nil, "this gate runs"},
		"derivedAt is stale": {nil, func(o *Options) { o.Now = gateNow.Add(48 * time.Hour) }, "outside [now-24h, now+5m]"},
		"releases no longer match the tags": {func(a map[string]any) {
			rel := a["releases"].(map[string]any)
			rel["to"] = append(rel["to"].([]any), map[string]any{"version": "90.1.2", "commit": "0000000000000000000000000000000000901000"})
		}, nil, "differs from what extractor"},
		"release commit differs": {func(a map[string]any) { firstRelease(a)["commit"] = "0000000000000000000000000000000000909999" }, nil, "differs from what extractor"},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := renewalTrees(t, tc.tamper)
			o := Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin}
			if tc.opts != nil {
				tc.opts(&o)
			}
			r := runGate(t, o)
			requireFail(t, r, tc.want)
			if c := change(t, r, crdAttestationID("90.1")); c.OK {
				t.Fatalf("admitted %+v", c)
			}
		})
	}
}
