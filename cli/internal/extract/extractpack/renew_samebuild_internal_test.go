// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func sbAtt(mut func(a *lineattest.LineAttestation)) lineattest.LineAttestation {
	a := lineattest.LineAttestation{
		Component: "c", Line: "1.2", FactFamily: "f", Completeness: "complete", RuleIDs: []string{"r.1"},
		Releases: &lineattest.Releases{
			From: []lineattest.Release{{Version: "1.1.0", Commit: "a"}, {Version: "1.1.1", Commit: "b"}},
			To:   []lineattest.Release{{Version: "1.2.0", Commit: "c"}},
		},
		Evidence: lineattest.Evidence{
			Basis:      "mechanical",
			Extractor:  &constraintengine.Extractor{ID: "x.y", Version: "1", CodeDigest: "sha256:aa"},
			DerivedAt:  "2026-10-01T00:00:00Z",
			ReviewedAt: "2026-10-01T00:00:00Z",
			ValidUntil: "2026-10-31T00:00:00Z",
			Sources:    []constraintengine.SourceEvidence{{ID: "s1", URL: "u", Revision: "r", ContentDigest: "d", StartLine: 1, EndLine: 2}},
		},
	}
	if mut != nil {
		mut(&a)
	}
	return a
}

// sbRenewed is sbAtt renewed by the same build at a later time.
func sbRenewed(mut func(a *lineattest.LineAttestation)) lineattest.LineAttestation {
	return sbAtt(func(a *lineattest.LineAttestation) {
		a.Evidence.DerivedAt, a.Evidence.ReviewedAt, a.Evidence.ValidUntil = "2026-10-29T00:00:00Z", "2026-10-29T00:00:00Z", "2026-11-28T00:00:00Z"
		if mut != nil {
			mut(a)
		}
	})
}

func TestRenewableSameBuildTimeOnly(t *testing.T) {
	for _, c := range []struct {
		name      string
		old, nw   lineattest.LineAttestation
		renewable bool
	}{
		{"time only", sbAtt(nil), sbRenewed(nil), true},
		{"nil releases", sbAtt(func(a *lineattest.LineAttestation) { a.Releases = nil }),
			sbRenewed(func(a *lineattest.LineAttestation) { a.Releases = nil }), true},
		{"empty rule ids", sbAtt(func(a *lineattest.LineAttestation) { a.RuleIDs = nil }),
			sbRenewed(func(a *lineattest.LineAttestation) { a.RuleIDs = nil }), true},
		{"old nil, new releases", sbAtt(func(a *lineattest.LineAttestation) { a.Releases = nil }), sbRenewed(nil), false},
		{"old releases, new nil", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Releases = nil }), false},
		{"sources differ", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].ContentDigest = "e" }), false},
		{"source added", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) {
			a.Evidence.Sources = append(a.Evidence.Sources, constraintengine.SourceEvidence{ID: "s2"})
		}), false},
		{"extractor id differs", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.Extractor.ID = "x.z" }), false},
		{"releases shorter", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Releases.From = a.Releases.From[:1] }), false},
		{"releases reordered", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) {
			a.Releases.From[0], a.Releases.From[1] = a.Releases.From[1], a.Releases.From[0]
		}), false},
		{"releases commit differs", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Releases.To[0].Commit = "z" }), false},
		{"completeness differs", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Completeness = "partial" }), false},
		{"rule ids differ", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.RuleIDs = []string{"r.2"} }), false},
		{"derivedAt equal", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) {
			a.Evidence.DerivedAt, a.Evidence.ReviewedAt = "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z"
		}), false},
		{"derivedAt older", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) {
			a.Evidence.DerivedAt, a.Evidence.ReviewedAt = "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"
		}), false},
		{"validUntil earlier", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-30T00:00:00Z" }), false},
		{"validUntil equal", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-31T00:00:00Z" }), false},
		{"validUntil unparseable", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "soon" }), false},
		{"reviewedAt differs from derivedAt", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.ReviewedAt = "2026-10-30T00:00:00Z" }), false},
		{"basis reviewed", sbAtt(func(a *lineattest.LineAttestation) { a.Evidence.Basis = "reviewed" }),
			sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.Basis = "reviewed" }), false},
		{"new basis reviewed", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.Basis = "reviewed" }), false},
		{"extractor absent", sbAtt(func(a *lineattest.LineAttestation) { a.Evidence.Extractor = nil }),
			sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.Extractor = nil }), false},
		{"key differs", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Line = "1.3" }), false},
		// Unchanged behaviour: the releases grew at the same build.
		{"same build, releases grew", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) {
			a.Releases.To = append(a.Releases.To, lineattest.Release{Version: "1.2.1", Commit: "d"})
		}), true},
		// Unchanged behaviour: a new build (version or digest) with equal releases.
		{"new build, digest", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.Extractor.CodeDigest = "sha256:bb" }), true},
		{"new build, version", sbAtt(nil), sbRenewed(func(a *lineattest.LineAttestation) { a.Evidence.Extractor.Version = "2" }), true},
	} {
		if got := renewable(c.old, c.nw); got != c.renewable {
			t.Errorf("%s: renewable = %v, want %v", c.name, got, c.renewable)
		}
	}
}
