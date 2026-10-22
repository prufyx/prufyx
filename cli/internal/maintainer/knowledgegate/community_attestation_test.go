// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Line attestations of a community-catalog target. The synthetic Argo CD
// fixture stands in with its target moved to the community catalog: the
// extractor and the gate decide nothing by the catalog, only by the table row
// of the component, so the records are the ones a community project's target
// derives. Nothing is published.

// argoCatalog is the gate's extractor catalog with the Argo CD extractor
// reading a community-catalog target; attest sets the target's flag.
func argoCatalog(attest bool) map[string]extractcli.Spec {
	catalog := extractcli.Catalog()
	spec := catalog[argoID]
	tg, _ := crdversions.TargetFor("argo-cd")
	tg.Catalog, tg.Attest = crdversions.CatalogCommunity, attest
	spec.New = func(n int) extract.Extractor { return crdversions.NewConcurrent(tg, n) }
	catalog[argoID] = spec
	return catalog
}

// A quiet line of a community-catalog target is admitted by re-derivation
// like a CNCF one: the same proof, the same loosening class.
func TestGateAdmitsACommunityTargetAttestation(t *testing.T) {
	t.Parallel()
	base, head := crdQuietTrees(t, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin, Catalog: argoCatalog(true)})
	requireAdmittedButUnsplit(t, r)
	c := change(t, r, crdAttestationID("90.2"))
	if !c.OK || c.Proof != ProofRederived || c.Basis != "mechanical" || c.Class != ClassLoosening {
		t.Fatalf("change %+v", c)
	}
	// The same record is refused when the community target does not attest.
	r = runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin, Catalog: argoCatalog(false)})
	if c := change(t, r, crdAttestationID("90.2")); c.OK || r.Passed() {
		t.Fatalf("admitted for a target that does not attest: %+v", c)
	}
}

// communityEmptyChange is the empty-list change of an attestation record, as
// the classification builds it.
func communityEmptyChange(a lineattest.LineAttestation) *Change {
	c := emptyListChangeOf(a)
	c.RuleID = crdAttestationID(a.Line)
	c.rhead.DerivedAt, c.rhead.ValidUntil = a.Evidence.DerivedAt, a.Evidence.ValidUntil
	return c
}

// The conditions of an empty-list attestation (emptylist.go) hold for a
// community-catalog target as for a CNCF one: one case per condition, and a
// control that is admitted.
func TestEmptyListConditionsForACommunityTarget(t *testing.T) {
	t.Parallel()
	opts := func(attest bool) Options {
		return Options{Catalog: argoCatalog(attest), Source: argoFixture, Now: gateNow}
	}
	derive := func(t *testing.T, at time.Time) lineattest.LineAttestation {
		t.Helper()
		_, atts := argoDerivation(t, at)
		return parseAttestation(t, attestationOfLine(atts, "90.2"))
	}
	withExtractor := func(a lineattest.LineAttestation, edit func(x *constraintengine.Extractor)) lineattest.LineAttestation {
		x := *a.Evidence.Extractor
		edit(&x)
		a.Evidence.Extractor = &x
		return a
	}
	good := derive(t, gateNow.Add(-time.Hour))

	// Control: admitted before and after re-derivation.
	if err := emptyListPre(communityEmptyChange(good), opts(true)); err != nil {
		t.Fatalf("control refused before re-derivation: %v", err)
	}

	pre := []struct {
		name  string
		att   lineattest.LineAttestation
		attOn bool
		edit  func(c *Change)
		code  string
	}{
		{name: "target does not attest", att: good, attOn: false, code: emptyListTargetNotAttesting},
		{name: "extractor of another component", att: withExtractor(good, func(x *constraintengine.Extractor) { x.ID = "crd.version-removal.istio" }), attOn: true, code: emptyListTargetNotAttesting},
		{name: "wrong code digest", att: withExtractor(good, func(x *constraintengine.Extractor) { x.CodeDigest = "sha256:" + strings.Repeat("0", 64) }), attOn: true, code: emptyListExtractorDigest},
		{name: "wrong extractor version", att: withExtractor(good, func(x *constraintengine.Extractor) { x.Version = "0.0.1" }), attOn: true, code: emptyListExtractorDigest},
		{name: "another repository", att: func() lineattest.LineAttestation {
			a := good
			a.Evidence.Sources = append([]constraintengine.SourceEvidence(nil), good.Evidence.Sources...)
			a.Evidence.Sources[0].URL = strings.Replace(a.Evidence.Sources[0].URL, "argoproj/argo-cd", "someone/else", 1)
			return a
		}(), attOn: true, code: emptyListCitation},
		{name: "derived too long ago", att: derive(t, gateNow.Add(-48*time.Hour)), attOn: true, code: emptyListFreshness},
		{name: "lease of 13 days", att: good, attOn: true, edit: func(c *Change) {
			c.rhead.ValidUntil = gateNow.Add(13 * 24 * time.Hour).Format(time.RFC3339)
		}, code: emptyListFreshness},
	}
	for _, tc := range pre {
		t.Run(tc.name, func(t *testing.T) {
			c := communityEmptyChange(tc.att)
			if tc.edit != nil {
				tc.edit(c)
			}
			err := emptyListPre(c, opts(tc.attOn))
			if err == nil || !strings.HasPrefix(err.Error(), "empty-list/"+tc.code+": ") {
				t.Fatalf("want a refusal empty-list/%s, got %v", tc.code, err)
			}
		})
	}

	t.Run("releases-incomplete", func(t *testing.T) {
		o := opts(true)
		c := communityEmptyChange(good)
		if err := releasesComplete(c, o, map[string][]extract.Tag{}); err != nil {
			t.Fatalf("control: %v", err)
		}
		o.Source = editedTags{FixtureReader: argoFixture, from: 1, calls: new(atomic.Int32), edit: func(tags []extract.Tag) []extract.Tag {
			return append(tags, extract.Tag{Name: "v90.2.1", Commit: otherCommit})
		}}
		err := releasesComplete(c, o, map[string][]extract.Tag{})
		if err == nil || !strings.HasPrefix(err.Error(), "empty-list/"+emptyListReleasesIncomplete+": ") {
			t.Fatalf("want a refusal empty-list/%s, got %v", emptyListReleasesIncomplete, err)
		}
	})

	t.Run("newest-pair-not-empty", func(t *testing.T) {
		// The gate's own run did not derive the newest line empty.
		c := communityEmptyChange(good)
		emptyListPost([]*Change{c}, opts(true))
		requireEmptyListCode(t, c, emptyListNewestPairNotEmpty)
		// Control: derived empty by the run, and the releases are the tags'.
		c = communityEmptyChange(good)
		c.OK = true
		c.derivedGroup = map[string][]byte{c.RuleID: []byte(`{"ruleIds":[]}`)}
		emptyListPost([]*Change{c}, opts(true))
		if !c.OK {
			t.Fatalf("control refused: %+v", c)
		}
	})
}

// The caps count loosening records over every pack together: an attestation
// record of the CNCF pack (where a community project's records sit) and a
// rule of the community-corpus pack are two toward the same per-change and
// per-day limits, so 51 in a day over both is refused.
func TestCapsCountRecordsOfBothPackKinds(t *testing.T) {
	t.Parallel()
	base, head := crdQuietTrees(t, nil)
	ids := readPack(t, base, commRulesPath).activeReviewed()
	if len(ids) == 0 {
		t.Fatal("the community-corpus pack has no rule to loosen")
	}
	editPack(t, head, commRulesPath, func(p *packDoc) { ruleOf(p.find(t, ids[0]))["nextAction"] = "Changed." })
	opts := Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin, Catalog: argoCatalog(true)}
	// The community-target attestation is a real loosening of the CNCF pack.
	r := runGate(t, opts)
	if c := change(t, r, crdAttestationID("90.2")); !c.OK || c.Class != ClassLoosening {
		t.Fatalf("change %+v", c)
	}
	if r.Totals.Loosening != 2 {
		t.Fatalf("totals %+v", r.Totals)
	}
	opts.MaxLoosening = 1
	requireFail(t, runGate(t, opts), "limits: 2 loosening changes, cap 1")
	opts.MaxLoosening = 0
	for _, tc := range []struct {
		before int
		fail   bool
	}{{DefaultMaxDailyLoosening - 2, false}, {DefaultMaxDailyLoosening - 1, true}} {
		before := tc.before
		o := opts
		o.DailyLoosening = &before
		r := runGate(t, o)
		if c, ok := check(r, "limits/daily"); !ok || c.OK == tc.fail {
			t.Fatalf("limits/daily %+v (before %d)", c, tc.before)
		}
	}
}
