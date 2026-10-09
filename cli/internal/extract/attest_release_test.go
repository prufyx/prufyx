// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const attestComponent = "pkg:github/kubernetes/kubernetes"

// attestingToy is the toy extractor that also attests one line. component is
// what AttestedComponent returns; the candidate is what it proposes.
type attestingToy struct {
	toyExtractor
	component string
	candidate AttestationCandidate
}

func (attestingToy) AttestedFamilies() []string {
	return []string{lineattest.FamilyKubernetesRemovedServedGVK}
}
func (x attestingToy) AttestedComponent() string { return x.component }
func (x attestingToy) Extract(ctx context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	e, err := x.toyExtractor.Extract(ctx, r, p)
	if err != nil {
		return e, err
	}
	e.Attestations = []AttestationCandidate{x.candidate}
	return e, nil
}

// noComponent hides AttestedComponent: an extractor that attests lines of a
// family with one component only.
type noComponent struct{ x attestingToy }

func (n noComponent) ID() string                          { return n.x.ID() }
func (n noComponent) Version() string                     { return n.x.Version() }
func (n noComponent) Applies(r RepoRef) bool              { return n.x.Applies(r) }
func (n noComponent) SourceFiles() (string, fs.FS)        { return n.x.SourceFiles() }
func (n noComponent) Pairs(ix ReleaseIndex) []VersionPair { return n.x.Pairs(ix) }
func (n noComponent) Extract(ctx context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	return n.x.Extract(ctx, r, p)
}
func (n noComponent) AttestedFamilies() []string { return n.x.AttestedFamilies() }

func attestCandidate(component string) AttestationCandidate {
	return AttestationCandidate{Component: component, Line: "2.0", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK,
		RuleIDs: []string{"example.toy.1-0-0-to-2-0-0"},
		Sources: []SourceRef{{ID: "toy-declaration", Repo: repoRef0(), Commit: testCommit, Path: "decl.go", StartLine: 3, EndLine: 3}}}
}

func repoRef0() RepoRef { r, _ := ParseRepo(testRepo); return r }

func runAttesting(t *testing.T, ex Extractor) error {
	t.Helper()
	fr := FixtureReader{Root: toyFixture(t)}
	_, err := Run(context.Background(), ex, fr, fr, Options{Repo: repoRef(t), DerivedAt: toyTime})
	return err
}

func TestRunRefusesAttestationOfAnotherComponent(t *testing.T) {
	base := toyExtractor{members: []string{"old"}, startLine: 3, endLine: 3}
	err := runAttesting(t, attestingToy{toyExtractor: base, component: attestComponent, candidate: attestCandidate("pkg:github/other/thing")})
	if err == nil || !strings.Contains(err.Error(), "the extractor attests") {
		t.Fatalf("attestation of another component: %v", err)
	}
	// The matching component passes the component check; whatever else the
	// run refuses, it is not the component.
	err = runAttesting(t, attestingToy{toyExtractor: base, component: attestComponent, candidate: attestCandidate(attestComponent)})
	// The toy rule reads no kubernetes fact, so the rule-set check refuses.
	if err == nil || !strings.Contains(err.Error(), "rulecheck rejected attestations") {
		t.Fatalf("matching component did not reach the rule-set check: %v", err)
	}
	// An extractor that is not a ComponentAttester is not component-checked;
	// the family's own component check (Validate) is what refuses.
	err = runAttesting(t, noComponent{attestingToy{toyExtractor: base, candidate: attestCandidate("pkg:github/other/thing")}})
	if err == nil || strings.Contains(err.Error(), "the extractor attests") || !strings.Contains(err.Error(), "is not the component of family") {
		t.Fatalf("non-ComponentAttester: %v", err)
	}
}

func relOf(version, commit string) lineattest.Release {
	return lineattest.Release{Version: version, Commit: commit}
}

func TestStampAttestationReleaseBranch(t *testing.T) {
	fr := FixtureReader{Root: toyFixture(t)}
	repo := repoRef(t)
	rec := NewRecorder(fr)
	// The extractor read testCommit only.
	if _, err := rec.Read(repo, testCommit, "decl.go"); err != nil {
		t.Fatal(err)
	}
	tags := []Tag{{Name: "v1.0.0", Commit: testCommit}, {Name: "v2.0.0", Commit: testNext}}
	id := constraintengine.Extractor{ID: "toy.removal", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("a", 64)}
	stamp := func(r *lineattest.Releases) (lineattest.LineAttestation, error) {
		c := attestCandidate(attestComponent)
		c.Releases = r
		return stampAttestation(c, rec, repo, tags, id, "2026-10-02T00:00:00Z", "2026-12-31T00:00:00Z")
	}
	cases := map[string]*lineattest.Releases{
		"release at a commit never read": {From: []lineattest.Release{relOf("1.0.0", testCommit)}, To: []lineattest.Release{relOf("2.0.0", testNext)}},
		"read commit, untagged version":  {From: []lineattest.Release{relOf("1.0.1", testCommit)}},
		"tagged version, other commit":   {To: []lineattest.Release{relOf("2.0.0", testCommit)}},
		"unrecorded commit":              {To: []lineattest.Release{relOf("2.0.0", "3333333333333333333333333333333333333333")}},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := stamp(r); err == nil || !strings.Contains(err.Error(), "not a recorded release tag") {
				t.Fatalf("accepted or wrong error: %v", err)
			}
		})
	}
	// The release branch is taken only when releases are proposed.
	plain, err := stamp(nil)
	if err != nil || plain.Releases != nil {
		t.Fatalf("no releases: %+v, %v", plain.Releases, err)
	}
	// A recorded release on a read commit is stamped, as a copy of the
	// candidate's, with an empty (not nil) side that was not proposed.
	in := &lineattest.Releases{From: []lineattest.Release{relOf("1.0.0", testCommit)}}
	a, err := stamp(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Releases == nil || len(a.Releases.From) != 1 || a.Releases.To == nil || len(a.Releases.To) != 0 {
		t.Fatalf("stamped releases %+v", a.Releases)
	}
	in.From[0].Version = "changed"
	if a.Releases.From[0].Version != "1.0.0" {
		t.Fatal("stamped releases alias the candidate's")
	}
}

func TestReleaseTagged(t *testing.T) {
	c := testCommit
	tags := []Tag{{Name: "v1.2.3", Commit: c}, {Name: "1.4.0", Commit: c}, {Name: "rel-", Commit: c}, {Name: "v11.2.3", Commit: c}, {Name: "x", Commit: testNext}}
	for _, tc := range []struct {
		version, commit string
		want            bool
	}{
		{"1.2.3", c, true},           // "v" prefix
		{"1.4.0", c, true},           // no prefix
		{"1.2.3", testNext, false},   // another commit
		{"2.3", c, false},            // "v1." ends in a digit or dot: not a version boundary
		{"3", c, false},              // "v1.2." ends in a dot
		{"9.9.9", c, false},          // no such tag
		{"1.2.3", "", false},         // no commit
		{"1.2.3", "deadbeef", false}, // unrelated commit
		// Empty version: a tag matches when its whole name is a
		// non-numeric prefix, so only a tag like "rel-" (or "") does; a
		// tag ending in a digit never names an empty version.
		{"", c, true},
		{"", testNext, true}, // tag "x" at testNext
	} {
		if got := releaseTagged(tags, lineattest.Release{Version: tc.version, Commit: tc.commit}); got != tc.want {
			t.Errorf("releaseTagged(%q at %q) = %v, want %v", tc.version, tc.commit, got, tc.want)
		}
	}
	if releaseTagged([]Tag{{Name: "v1.2.3", Commit: c}}, lineattest.Release{Commit: c}) {
		t.Error("an empty version matched a tag that ends in a digit")
	}
	if releaseTagged(nil, lineattest.Release{Version: "1.0.0", Commit: c}) {
		t.Error("no tags matched")
	}
}
