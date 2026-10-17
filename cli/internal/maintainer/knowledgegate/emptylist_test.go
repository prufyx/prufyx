// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// Admission of empty-list mechanical line attestations: the five conditions
// of emptylist.go, for both families that attest lines.

const (
	otherCommit = "0000000000000000000000000000000000999999"
	argoID      = "crd.version-removal.argo-cd"
)

// forbiddenSource fails the test on any upstream request: a change refused
// before re-derivation must never reach the upstream.
type forbiddenSource struct{ t *testing.T }

func (f forbiddenSource) Read(extract.RepoRef, string, string) ([]byte, error) {
	f.t.Error("upstream read for a change that must be refused before re-derivation")
	return nil, extract.ErrNotFound
}

func (f forbiddenSource) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	f.t.Error("upstream listing for a change that must be refused before re-derivation")
	return nil, extract.ErrNotFound
}

func (f forbiddenSource) Tags(extract.RepoRef) ([]extract.Tag, error) {
	f.t.Error("tag listing for a change that must be refused before re-derivation")
	return nil, extract.ErrNotFound
}

// editedTags serves a fixture whose tag list is edited from the nth listing
// on (1 = every listing): the first listings are the real ones, so a change
// can pass re-derivation and meet the tags a release published later shows.
type editedTags struct {
	extract.FixtureReader
	from  int
	calls *atomic.Int32
	edit  func([]extract.Tag) []extract.Tag
}

func (e editedTags) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	tags, err := e.FixtureReader.Tags(repo)
	if err != nil {
		return nil, err
	}
	if int(e.calls.Add(1)) >= e.from {
		tags = e.edit(slices.Clone(tags))
	}
	return tags, nil
}

func requireEmptyListCode(t *testing.T, c *Change, code string) {
	t.Helper()
	if c.OK || !strings.HasPrefix(c.Detail, "empty-list/"+code+": ") {
		t.Fatalf("want a refusal empty-list/%s, got %+v", code, c)
	}
}

// setDerivedAt moves derivedAt and reviewedAt together (a mechanical record
// has one time for both) and keeps a lease of 80 days.
func setDerivedAt(a map[string]any, at time.Time) {
	evidenceMap(a)["derivedAt"] = at.Format(time.RFC3339)
	evidenceMap(a)["reviewedAt"] = at.Format(time.RFC3339)
	evidenceMap(a)["validUntil"] = at.Add(80 * 24 * time.Hour).Format(time.RFC3339)
}

func evidenceMap(a map[string]any) map[string]any { return a["evidence"].(map[string]any) }

func sourceMap(a map[string]any, i int) map[string]any {
	return evidenceMap(a)["sources"].([]any)[i].(map[string]any)
}

// k8sQuietTrees adds the extractor's own quiet line 1.31 (tampered by edit)
// to a pack that holds a reviewed attestation of 1.22.
func k8sQuietTrees(t *testing.T, edit func(a map[string]any)) (Tree, Tree) {
	t.Helper()
	return attestedTrees(t, []string{"1.22"}, []string{"1.22"}, func(_ *packDoc, atts []map[string]any) []map[string]any {
		a := derivedAttestation(t, "1.31")
		if edit != nil {
			edit(a)
		}
		return append(atts, a)
	})
}

// k8sRawTrees is attestedTrees without regenerating the files derived from
// the head pack, for records the pack tooling itself would refuse; mutate
// edits the head's list of attestations.
func k8sRawTrees(t *testing.T, mutate func(atts []map[string]any) []map[string]any) (Tree, Tree) {
	t.Helper()
	base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22"}, nil)
	p := readPack(t, head, cncfRulesPath)
	var atts []map[string]any
	if err := json.Unmarshal(p.fields["lineAttestations"], &atts); err != nil {
		t.Fatal(err)
	}
	setAttestations(t, p, mutate(atts))
	p.write(t, head, cncfRulesPath)
	return base, head
}

func k8sQuietTreesRaw(t *testing.T, edit func(a map[string]any)) (Tree, Tree) {
	t.Helper()
	return k8sRawTrees(t, func(atts []map[string]any) []map[string]any {
		a := derivedAttestation(t, "1.31")
		if edit != nil {
			edit(a)
		}
		return append(atts, a)
	})
}

func crdQuietTrees(t *testing.T, edit func(a map[string]any)) (Tree, Tree) {
	t.Helper()
	return crdAttestedTrees(t, func(base90_1 map[string]any, derived []map[string]any) []map[string]any {
		a := attestationOfLine(derived, "90.2")
		if edit != nil {
			edit(a)
		}
		return []map[string]any{base90_1, a}
	})
}

func crdQuietTreesRaw(t *testing.T, edit func(a map[string]any)) (Tree, Tree) {
	t.Helper()
	return crdAttestedTreesWith(t, false, func(base90_1 map[string]any, derived []map[string]any) []map[string]any {
		a := attestationOfLine(derived, "90.2")
		if edit != nil {
			edit(a)
		}
		return []map[string]any{base90_1, a}
	})
}

func TestEmptyListAdmitted(t *testing.T) {
	t.Run("kubernetes", func(t *testing.T) {
		base, head := k8sQuietTrees(t, nil)
		r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
		requireAdmittedButUnsplit(t, r)
		if c := change(t, r, attestationID("1.31")); !c.OK || c.Proof != ProofRederived {
			t.Fatalf("change %+v", c)
		}
		if c, ok := check(r, "empty-list"); !ok || !c.OK || !strings.Contains(c.Detail, "1 empty-list line attestations, 0 refused") {
			t.Fatalf("empty-list check %+v", c)
		}
	})
	t.Run("custom resources", func(t *testing.T) {
		base, head := crdQuietTrees(t, nil)
		r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
		requireAdmittedButUnsplit(t, r)
		if c := change(t, r, crdAttestationID("90.2")); !c.OK || c.Proof != ProofRederived {
			t.Fatalf("change %+v", c)
		}
		if c, ok := check(r, "empty-list"); !ok || !c.OK {
			t.Fatalf("empty-list check %+v", c)
		}
	})
	t.Run("a lease just over 14 days is admitted", func(t *testing.T) {
		base, head := k8sQuietTrees(t, func(a map[string]any) {
			evidenceMap(a)["validUntil"] = gateNow.Add(14*24*time.Hour + time.Second).Format(time.RFC3339)
		})
		requireAdmittedButUnsplit(t, runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin}))
	})
	t.Run("the scheduled run does not pass through the checks", func(t *testing.T) {
		_, head := k8sQuietTrees(t, nil)
		r := runGate(t, Options{Base: head, Head: head, Source: fixtureSource, RederiveAll: true})
		requireAdmittedButUnsplit(t, r)
		if _, ok := check(r, "empty-list"); ok {
			t.Fatal("an unchanged record was checked as an empty-list change")
		}
	})
}

// Each refusal below happens before re-derivation: the change never gets
// Proof=rederived and the upstream is never asked.
func TestEmptyListRefusedBeforeRederivation(t *testing.T) {
	notAttesting := func() map[string]extractcli.Spec {
		catalog := extractcli.Catalog()
		spec := catalog[argoID]
		tg, _ := crdversions.TargetFor("argo-cd")
		tg.Attest = false
		spec.New = func(n int) extract.Extractor { return crdversions.NewConcurrent(tg, n) }
		catalog[argoID] = spec
		return catalog
	}
	cases := []struct {
		name   string
		crd    bool
		edit   func(a map[string]any)
		opts   func(o *Options)
		code   string
		change string
	}{
		{name: "unknown extractor", edit: func(a map[string]any) { evidenceMap(a)["extractor"].(map[string]any)["id"] = "k8s.unknown" }, code: "target-not-attesting"},
		{name: "target does not attest", crd: true, opts: func(o *Options) { o.Catalog = notAttesting() }, code: "target-not-attesting"},
		{name: "extractor of another component", crd: true, edit: func(a map[string]any) {
			evidenceMap(a)["extractor"].(map[string]any)["id"] = "crd.version-removal.istio"
		}, code: "target-not-attesting"},
		{name: "extractor of another family", edit: func(a map[string]any) {
			evidenceMap(a)["extractor"].(map[string]any)["id"] = argoID
		}, code: "target-not-attesting"},

		{name: "wrong code digest", edit: func(a map[string]any) {
			evidenceMap(a)["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("0", 64)
		}, code: "extractor-digest"},
		{name: "wrong extractor version", crd: true, edit: func(a map[string]any) { evidenceMap(a)["extractor"].(map[string]any)["version"] = "0.0.1" }, code: "extractor-digest"},

		{name: "other repository", edit: func(a map[string]any) {
			s := sourceMap(a, 0)
			s["url"] = strings.Replace(s["url"].(string), "kubernetes/kubernetes", "someone/else", 1)
		}, code: "citation"},
		{name: "derived too long ago", edit: func(a map[string]any) { setDerivedAt(a, gateNow.Add(-48*time.Hour)) }, code: "freshness"},
		{name: "derived in the future", edit: func(a map[string]any) { setDerivedAt(a, gateNow.Add(time.Hour)) }, code: "freshness"},
		{name: "lease of 13 days", edit: func(a map[string]any) {
			evidenceMap(a)["validUntil"] = gateNow.Add(13 * 24 * time.Hour).Format(time.RFC3339)
		}, code: "freshness"},
		{name: "lease of exactly 14 days", edit: func(a map[string]any) {
			evidenceMap(a)["validUntil"] = gateNow.Add(14 * 24 * time.Hour).Format(time.RFC3339)
		}, code: "freshness"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var base, head Tree
			id := attestationID("1.31")
			if tc.crd {
				base, head = crdQuietTreesRaw(t, tc.edit)
				id = crdAttestationID("90.2")
			} else {
				base, head = k8sQuietTreesRaw(t, tc.edit)
			}
			o := Options{Base: base, Head: head, Source: forbiddenSource{t}, Author: DefaultBotLogin}
			if tc.opts != nil {
				tc.opts(&o)
			}
			r := runGate(t, o)
			c := change(t, r, id)
			requireEmptyListCode(t, c, tc.code)
			if c.Proof == ProofRederived {
				t.Fatalf("a refused change reached re-derivation: %+v", c)
			}
			if r.Passed() {
				t.Fatal("gate passed")
			}
		})
	}
}

// The pack loader already refuses most malformed citations; the check of
// emptylist.go is the gate's own, kept independent of it.
func TestEmptyListCitationShape(t *testing.T) {
	repo, err := extract.ParseRepo(k8sservedapis.Repo)
	if err != nil {
		t.Fatal(err)
	}
	crdRepo, _ := extract.ParseRepo("github.com/argoproj/argo-cd")
	_, crdAtts := argoDerivation(t, gateNow.Add(-time.Hour))
	good := parseAttestation(t, derivedAttestation(t, "1.31"))
	goodCRD := parseAttestation(t, attestationOfLine(crdAtts, "90.2"))
	if err := emptyListCitationShape(repo, good); err != nil {
		t.Fatalf("the extractor's own record: %v", err)
	}
	if err := emptyListCitationShape(crdRepo, goodCRD); err != nil {
		t.Fatalf("the extractor's own record: %v", err)
	}
	withSource := func(edit func(s *constraintengine.SourceEvidence)) lineattest.LineAttestation {
		a := good
		a.Evidence.Sources = slices.Clone(good.Evidence.Sources)
		edit(&a.Evidence.Sources[0])
		return a
	}
	rev := good.Evidence.Sources[0].Revision
	cases := map[string]lineattest.LineAttestation{
		"tag instead of a commit": withSource(func(s *constraintengine.SourceEvidence) { s.URL = strings.Replace(s.URL, rev, "v1.30.0", 1) }),
		"branch": withSource(func(s *constraintengine.SourceEvidence) {
			s.URL = strings.Replace(s.URL, "/blob/"+rev, "/blob/master", 1)
		}),
		"tree":                    withSource(func(s *constraintengine.SourceEvidence) { s.URL = strings.Replace(s.URL, "/blob/", "/tree/", 1) }),
		"query":                   withSource(func(s *constraintengine.SourceEvidence) { s.URL += "?plain=1" }),
		"fragment":                withSource(func(s *constraintengine.SourceEvidence) { s.URL += "#L1" }),
		"another revision in url": withSource(func(s *constraintengine.SourceEvidence) { s.URL = strings.Replace(s.URL, rev, otherCommit, 1) }),
		"another repository": withSource(func(s *constraintengine.SourceEvidence) {
			s.URL = strings.Replace(s.URL, "kubernetes/kubernetes", "x/y", 1)
		}),
		"no path": withSource(func(s *constraintengine.SourceEvidence) {
			s.URL = strings.TrimSuffix(s.URL, "api/openapi-spec/swagger.json")
		}),
		"path not clean": withSource(func(s *constraintengine.SourceEvidence) {
			s.URL = strings.Replace(s.URL, "api/openapi-spec", "api/../api/openapi-spec", 1)
		}),
		"revision too short": withSource(func(s *constraintengine.SourceEvidence) { s.Revision = "00012400" }),
		"revision upper case": withSource(func(s *constraintengine.SourceEvidence) {
			upper := rev[:39] + "A"
			s.URL, s.Revision = strings.Replace(s.URL, rev, upper, 1), upper
		}),
		"start line 0":     withSource(func(s *constraintengine.SourceEvidence) { s.StartLine = 0 }),
		"end before start": withSource(func(s *constraintengine.SourceEvidence) { s.StartLine, s.EndLine = 5, 4 }),
		"no source":        func() lineattest.LineAttestation { a := good; a.Evidence.Sources = nil; return a }(),
	}
	for name, a := range cases {
		err := emptyListCitationShape(repo, a)
		if err == nil || !strings.HasPrefix(err.Error(), "empty-list/citation: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := goodCRD
	bad.Releases = &lineattest.Releases{From: goodCRD.Releases.From, To: []lineattest.Release{{Version: "90.2.0", Commit: "902000"}}}
	if err := emptyListCitationShape(crdRepo, bad); err == nil || !strings.HasPrefix(err.Error(), "empty-list/citation: ") {
		t.Errorf("release commit: %v", err)
	}
}

// The content digest and the line span are read by the citations check;
// its finding is attached to the empty-list change it names.
func TestEmptyListCitationFinding(t *testing.T) {
	base, head := k8sQuietTrees(t, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin, Citations: namedFinding{id: "lineAttestation " + recordComponent + " 1.31 " + lineattest.FamilyKubernetesRemovedServedGVK}})
	c := change(t, r, attestationID("1.31"))
	requireEmptyListCode(t, c, "citation")
	if !strings.Contains(c.Detail, "contentDigest") && !strings.Contains(c.Detail, rulecheck.CheckCitationDigest) {
		t.Fatalf("detail %q", c.Detail)
	}
	if ck, ok := check(r, "empty-list"); !ok || ck.OK {
		t.Fatalf("empty-list check %+v", ck)
	}
	// A finding for another record still fails the citations check, so no
	// empty list is admitted next to it.
	r = runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin, Citations: namedFinding{id: "lineAttestation other 1.2 x"}})
	c = change(t, r, attestationID("1.31"))
	requireEmptyListCode(t, c, "citation")
	if !strings.Contains(c.Detail, "citations check did not pass") {
		t.Fatalf("detail %q", c.Detail)
	}
	// With no verifier configured the citations check cannot pass: refused.
	r = runGateExact(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
	c = change(t, r, attestationID("1.31"))
	requireEmptyListCode(t, c, "citation")
	if c.Proof == ProofRederived && c.OK {
		t.Fatalf("admitted without a citations check: %+v", c)
	}
}

type namedFinding struct{ id string }

func (n namedFinding) VerifyItems(_ context.Context, items []rulecheck.CitationItem) (rulecheck.CitationReport, error) {
	return rulecheck.CitationReport{Pass: false, SourcesChecked: len(items), FailedRules: []string{n.id}, Findings: []rulecheck.CitationFinding{
		{RuleID: n.id, SourceID: "openapi-1-30-0", Check: rulecheck.CheckCitationDigest, Message: "contentDigest does not match"},
	}}, nil
}

// One empty-list record that the gate's own run does not derive empty (the
// extractor derives a removal for line 1.32) refuses the quiet line 1.31 of
// the same change too.
func TestEmptyListNewestPairNotEmpty(t *testing.T) {
	setup := func(t *testing.T, hide bool) (Tree, Tree) {
		return k8sRawTrees(t, func(atts []map[string]any) []map[string]any {
			atts = append(atts, derivedAttestation(t, "1.31"))
			if hide {
				a := derivedAttestation(t, "1.32")
				a["ruleIds"] = []any{}
				atts = append(atts, a)
			}
			return atts
		})
	}
	base, head := setup(t, true)
	r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
	requireEmptyListCode(t, change(t, r, attestationID("1.31")), "newest-pair-not-empty")
	if c := change(t, r, attestationID("1.32")); c.OK || !strings.Contains(c.Detail, "differs from what extractor") {
		t.Fatalf("the hidden removal: %+v", c)
	}
	if r.Passed() {
		t.Fatal("gate passed")
	}
	// Control: without the hidden removal the quiet line is admitted.
	base, head = setup(t, false)
	if c := change(t, runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin}), attestationID("1.31")); !c.OK {
		t.Fatalf("control: %+v", c)
	}
}

// The releases are read again after re-derivation, from the tags the gate
// sees then (a release published in between, a moved tag).
func TestEmptyListReleasesAtTheGate(t *testing.T) {
	run := func(t *testing.T, base, head Tree, src Source, id string) *Change {
		t.Helper()
		r := runGate(t, Options{Base: base, Head: head, Source: src, Author: DefaultBotLogin})
		return change(t, r, id)
	}
	t.Run("kubernetes anchor tag gone", func(t *testing.T) {
		base, head := k8sQuietTrees(t, nil)
		src := editedTags{FixtureReader: extract.FixtureReader{Root: servedFixture}, from: 2, calls: new(atomic.Int32), edit: func(tags []extract.Tag) []extract.Tag {
			return slices.DeleteFunc(tags, func(tg extract.Tag) bool { return tg.Name == "v1.31.0" })
		}}
		c := run(t, base, head, src, attestationID("1.31"))
		requireEmptyListCode(t, c, "releases-incomplete")
		if c.Proof != ProofRederived {
			t.Fatalf("the change should have passed re-derivation: %+v", c)
		}
	})
	t.Run("custom resources release published later", func(t *testing.T) {
		base, head := crdQuietTrees(t, nil)
		src := editedTags{FixtureReader: argoFixture, from: 2, calls: new(atomic.Int32), edit: func(tags []extract.Tag) []extract.Tag {
			return append(tags, extract.Tag{Name: "v90.2.1", Commit: otherCommit})
		}}
		requireEmptyListCode(t, run(t, base, head, src, crdAttestationID("90.2")), "releases-incomplete")
	})
	t.Run("the real tags are consistent", func(t *testing.T) {
		base, head := crdQuietTrees(t, nil)
		src := editedTags{FixtureReader: argoFixture, from: 2, calls: new(atomic.Int32), edit: func(tags []extract.Tag) []extract.Tag { return tags }}
		if c := run(t, base, head, src, crdAttestationID("90.2")); !c.OK {
			t.Fatalf("change %+v", c)
		}
	})
}

// staticTags serves a fixture with an edited tag list.
type staticTags struct {
	extract.FixtureReader
	edit func([]extract.Tag) []extract.Tag
}

func (s staticTags) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	tags, err := s.FixtureReader.Tags(repo)
	if err != nil {
		return nil, err
	}
	return s.edit(slices.Clone(tags)), nil
}

func parseAttestation(t *testing.T, m map[string]any) lineattest.LineAttestation {
	t.Helper()
	raw, err := json.Marshal([]map[string]any{m})
	if err != nil {
		t.Fatal(err)
	}
	got, err := lineattest.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return got[0]
}

func emptyListChangeOf(a lineattest.LineAttestation) *Change {
	return &Change{Class: ClassLoosening, rhead: &record{attestation: &a, Basis: "mechanical", Extractor: a.Evidence.Extractor}}
}

func TestEmptyListReleasesComplete(t *testing.T) {
	_, crdAtts := argoDerivation(t, gateNow.Add(-time.Hour))
	crd := parseAttestation(t, attestationOfLine(crdAtts, "90.2"))
	k8s := parseAttestation(t, derivedAttestation(t, "1.31"))
	tagOf := func(name, commit string) extract.Tag { return extract.Tag{Name: name, Commit: commit} }
	drop := func(names ...string) func([]extract.Tag) []extract.Tag {
		return func(tags []extract.Tag) []extract.Tag {
			return slices.DeleteFunc(tags, func(tg extract.Tag) bool { return slices.Contains(names, tg.Name) })
		}
	}
	add := func(more ...extract.Tag) func([]extract.Tag) []extract.Tag {
		return func(tags []extract.Tag) []extract.Tag { return append(tags, more...) }
	}
	recommit := func(name, commit string) func([]extract.Tag) []extract.Tag {
		return func(tags []extract.Tag) []extract.Tag {
			for i := range tags {
				if tags[i].Name == name {
					tags[i].Commit = commit
				}
			}
			return tags
		}
	}
	cases := []struct {
		name string
		att  lineattest.LineAttestation
		root string
		edit func([]extract.Tag) []extract.Tag
		line string // overrides the record's line
		ok   bool
	}{
		{name: "crd as tagged", att: crd, root: argoRoot(), ok: true},
		{name: "crd release candidate and other lines are ignored", att: crd, root: argoRoot(), edit: add(tagOf("v90.2.1-rc.1", otherCommit), tagOf("v90.4.0", otherCommit), tagOf("90.2.1", otherCommit), tagOf("v90.2.x", otherCommit)), ok: true},
		{name: "crd same version twice at one commit counts once", att: crd, root: argoRoot(), edit: add(tagOf("v90.2.0", "0000000000000000000000000000000000902000")), ok: true},
		{name: "crd a final release of the previous line is missing", att: crd, root: argoRoot(), edit: drop("v90.1.1")},
		{name: "crd a final release of the line is missing", att: crd, root: argoRoot(), edit: drop("v90.2.0")},
		{name: "crd an extra release", att: crd, root: argoRoot(), edit: add(tagOf("v90.2.1", otherCommit))},
		{name: "crd an extra release of the previous line", att: crd, root: argoRoot(), edit: add(tagOf("v90.1.2", otherCommit))},
		{name: "crd wrong commit", att: crd, root: argoRoot(), edit: recommit("v90.2.0", otherCommit)},
		{name: "crd a version tagged at two commits", att: crd, root: argoRoot(), edit: add(tagOf("v90.2.0", otherCommit))},
		{name: "crd a matching tag without a full commit", att: crd, root: argoRoot(), edit: recommit("v90.2.0", "902000")},
		{name: "crd an extra tag without a full commit", att: crd, root: argoRoot(), edit: add(tagOf("v90.2.1", ""))},
		{name: "crd no release of the line", att: crd, root: argoRoot(), edit: drop("v90.2.0", "v90.3.0-rc.1")},
		{name: "crd no previous minor line", att: crd, root: argoRoot(), line: "90.0"},

		{name: "kubernetes as tagged", att: k8s, root: servedFixture, ok: true},
		{name: "kubernetes patch tags are not required", att: k8s, root: servedFixture, edit: add(tagOf("v1.31.1", otherCommit), tagOf("v1.30.4", otherCommit), tagOf("v1.31.0-rc.1", "x")), ok: true},
		{name: "kubernetes the line's .0 tag is missing", att: k8s, root: servedFixture, edit: drop("v1.31.0")},
		{name: "kubernetes the previous line's .0 tag is missing", att: k8s, root: servedFixture, edit: drop("v1.30.0")},
		{name: "kubernetes cited revision is not the tag commit", att: k8s, root: servedFixture, edit: recommit("v1.31.0", otherCommit)},
		{name: "kubernetes a patch tag without a full commit", att: k8s, root: servedFixture, edit: add(tagOf("v1.31.2", "abc"))},
		{name: "kubernetes the .0 tag at two commits", att: k8s, root: servedFixture, edit: add(tagOf("v1.31.0", otherCommit))},
		{name: "kubernetes the previous minor is below the extractor floor", att: k8s, root: servedFixture, line: "1.19",
			edit: add(tagOf("v1.18.0", "0000000000000000000000000000000000011800"), tagOf("v1.19.0", "0000000000000000000000000000000000011900"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.att
			if tc.line != "" {
				a.Line = tc.line
			}
			edit := tc.edit
			if edit == nil {
				edit = func(tags []extract.Tag) []extract.Tag { return tags }
			}
			opts := Options{Catalog: extractcli.Catalog(), Source: staticTags{FixtureReader: extract.FixtureReader{Root: tc.root}, edit: edit}}
			c := emptyListChangeOf(a)
			err := releasesComplete(c, opts, map[string][]extract.Tag{})
			switch {
			case tc.ok && err != nil:
				t.Fatalf("refused: %v", err)
			case !tc.ok && (err == nil || !strings.HasPrefix(err.Error(), "empty-list/releases-incomplete: ")):
				t.Fatalf("want a refusal empty-list/releases-incomplete, got %v", err)
			}
		})
	}
	if k8sservedapis.MinFromMinor != 19 {
		t.Fatalf("the floor case above assumes line 1.19 is below MinFromMinor+1 (%d)", k8sservedapis.MinFromMinor)
	}
}

func argoRoot() string { return argoFixture.Root }

// Empty-list changes count as loosening, in the totals, the per-change cap and
// the daily cap; nothing is added to or raised in the limits.
func TestEmptyListCountsTowardsTheCaps(t *testing.T) {
	base, head := k8sQuietTrees(t, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
	if r.Totals.Loosening != 1 || r.Limits.Loosening != 1 || r.Limits.MaxLoosening != DefaultMaxLoosening {
		t.Fatalf("totals %+v limits %+v", r.Totals, r.Limits)
	}
	if c := change(t, r, attestationID("1.31")); c.Class != ClassLoosening {
		t.Fatalf("change %+v", c)
	}

	// The cap applies to it: with another loosening change next to it, a cap
	// of one is exceeded, a cap of two is not.
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) { ruleOf(p.find(t, ids[0]))["nextAction"] = "Changed." })
	r = runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin, MaxLoosening: 1})
	if r.Totals.Loosening != 2 || r.Limits.Loosening != 2 {
		t.Fatalf("totals %+v limits %+v", r.Totals, r.Limits)
	}
	requireFail(t, r, "limits: 2 loosening changes, cap 1")
	r = runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin, MaxLoosening: 2})
	if c, _ := check(r, "limits"); !c.OK {
		t.Fatalf("limits %+v", c)
	}

	// The daily cap counts it too.
	_, head = k8sQuietTrees(t, nil)
	for _, tc := range []struct {
		before int
		fail   bool
	}{{DefaultMaxDailyLoosening - 1, false}, {DefaultMaxDailyLoosening, true}} {
		before := tc.before
		r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin, DailyLoosening: &before})
		if c, ok := check(r, "limits/daily"); !ok || c.OK == tc.fail {
			t.Fatalf("limits/daily %+v (before %d)", c, tc.before)
		}
	}
}

// A reviewed empty-list attestation is not in the scope of the empty-list
// checks: it still needs a statement or an owner approval, and is refused
// without one.
func TestEmptyListReviewedStillNeedsApproval(t *testing.T) {
	base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22"}, func(p *packDoc, atts []map[string]any) []map[string]any {
		a := reviewedAttestation(t, p, "1.31")
		if len(a["ruleIds"].([]any)) != 0 {
			t.Fatal("line 1.31 is not empty in the pack")
		}
		return append(atts, a)
	})
	r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
	c := change(t, r, attestationID("1.31"))
	if c.OK || c.Proof == ProofRederived || c.Proof == ProofApproval || strings.HasPrefix(c.Detail, "empty-list/") || !strings.Contains(c.Detail, "owner approval") {
		t.Fatalf("change %+v", c)
	}
	if _, ok := check(r, "empty-list"); ok {
		t.Fatal("a reviewed attestation was checked as an empty-list change")
	}
}
