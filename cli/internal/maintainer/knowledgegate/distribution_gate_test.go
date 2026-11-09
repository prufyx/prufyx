// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

// The tests here use a throwaway deriver of their own: the production
// registry is empty, so the gate admits nothing until an extractor is
// compiled in.

var provIdentity = constraintengine.Extractor{ID: "provider-test", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("c", 64)}

const (
	provExcerptPath = "eks/eks-1-33.txt"
	provFetchedAt   = "2026-10-01T10:00:00Z"
	provPageDigest  = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

var provDateRE = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}`)

func provTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// provDeriver reads the standard-support end date from the one excerpt a
// record cites.
func provDeriver(id constraintengine.Extractor) ProviderDeriver {
	return ProviderDeriver{Identity: id, Derive: func(in ProviderDeriveInput) (distribution.Record, error) {
		if len(in.Sources) != 1 {
			return distribution.Record{}, errors.New("the test deriver reads exactly one excerpt")
		}
		data, err := in.Read(in.Sources[0].Revision, providerexcerpt.Dir+"/"+provExcerptPath)
		if err != nil {
			return distribution.Record{}, err
		}
		date := provDateRE.FindString(string(data[strings.LastIndex(string(data), "---\n"):]))
		if date == "" {
			return distribution.Record{}, errors.New("no date in the excerpt")
		}
		line := "1.33"
		if in.Identity.Distribution == "openshift" {
			line = "4.14"
		}
		r := in.Identity
		r.Lifecycle = []distribution.Lifecycle{{Line: line, StandardEnd: date, Precision: distribution.PrecisionDay}}
		x := id
		r.Evidence = distribution.Evidence{
			State: distribution.StateActive, Basis: constraintengine.BasisMechanical, Extractor: &x,
			DerivedAt: provTime(in.DerivedAt), ReviewedAt: provTime(in.DerivedAt), ValidUntil: provTime(in.ValidUntil), Sources: in.Sources,
		}
		return r, nil
	}}
}

type provFix struct {
	dir      string // git repository holding the excerpt
	baseSHA  string // the commit the excerpt is in (the base)
	later    string // a commit after the base
	entry    providerexcerpt.Entry
	store    *ExcerptStore
	base     Tree
	head     Tree
	derivers map[string]ProviderDeriver
	key      testApprovalKey
}

func gitRun(t *testing.T, dir, date string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_COMMITTER_DATE="+date, "GIT_AUTHOR_DATE="+date)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newProvFix builds a git repository with one committed excerpt (commit date
// commitDate), a manifest and a pin file in the base tree.
func newProvFix(t *testing.T, commitDate, pin string) *provFix {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, commitDate, "init", "-q")
	body := "standard support for this version ends 2026-07-29\n"
	e := providerexcerpt.Entry{
		ID: "eks-1-33", Provider: "eks", Path: provExcerptPath, SourceURL: "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html",
		FetchedAt: provFetchedAt, Anchor: "standard-support", Licence: providerexcerpt.LicenceUnknown, Form: providerexcerpt.FormParaphrase,
	}
	data := []byte(providerexcerpt.FileMagic + "\nsource: " + e.SourceURL + "\nfetchedAt: " + e.FetchedAt + "\nanchor: " + e.Anchor +
		"\nlicence: " + e.Licence + "\nform: " + e.Form + "\npageSha256: " + provPageDigest + "\nsentence: s-1\n---\n" + body)
	e.SHA256 = CandidateDigest(data)
	writeFile(t, filepath.Join(dir, providerexcerpt.Dir, provExcerptPath), data)
	gitRun(t, dir, commitDate, "add", ".")
	gitRun(t, dir, commitDate, "commit", "-q", "-m", "excerpt")
	baseSHA := gitRun(t, dir, commitDate, "rev-parse", "HEAD")
	writeFile(t, filepath.Join(dir, "other.txt"), []byte("later\n"))
	gitRun(t, dir, commitDate, "add", ".")
	gitRun(t, dir, commitDate, "commit", "-q", "-m", "later")
	later := gitRun(t, dir, commitDate, "rev-parse", "HEAD")
	store, err := GitExcerptStore(dir, baseSHA)
	if err != nil {
		t.Fatal(err)
	}
	f := &provFix{dir: dir, baseSHA: baseSHA, later: later, entry: e, store: store, base: Tree{Root: t.TempDir()}, head: Tree{Root: t.TempDir()}, derivers: map[string]ProviderDeriver{provIdentity.ID: provDeriver(provIdentity)}, key: newApprovalKey(t)}
	manifest, err := json.Marshal(providerexcerpt.Manifest{Schema: providerexcerpt.ManifestSchema, Entries: []providerexcerpt.Entry{e}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range []Tree{f.base, f.head} {
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(providerexcerpt.Dir+"/manifest.json")), manifest)
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)), []byte("ref="+strings.Repeat("a", 40)+"\nversion="+pin+"\n"))
	}
	return f
}

func (f *provFix) opts() Options {
	return Options{Layout: DefaultLayout(), Now: gateNow, Base: f.base, Head: f.head, Excerpts: f.store, derivers: f.derivers}
}

func (f *provFix) source(rev string) []constraintengine.SourceEvidence {
	if rev == "" {
		rev = f.baseSHA
	}
	return []constraintengine.SourceEvidence{{
		ID: "src-1", URL: "https://github.com/" + providerexcerpt.Repo + "/blob/" + rev + "/" + providerexcerpt.Dir + "/" + provExcerptPath,
		Revision: rev, ContentDigest: f.entry.SHA256, StartLine: 10, EndLine: 10,
	}}
}

// record derives the record the test deriver derives for a distribution.
func (f *provFix) record(t *testing.T, id, controlPlane string, mapping []distribution.Mapping, derivedAt time.Time, validDays int) distribution.Record {
	t.Helper()
	r, err := f.derivers[provIdentity.ID].Derive(ProviderDeriveInput{
		Identity: distribution.Record{Distribution: id, ControlPlane: controlPlane, KubernetesMapping: mapping},
		Sources:  f.source(""),
		Read:     f.store.Read, DerivedAt: derivedAt, ValidUntil: derivedAt.Add(time.Duration(validDays) * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("fixture record: %v", err)
	}
	return r
}

var provDerivedAt = gateNow.Add(-time.Hour)

func provPack(t *testing.T, records ...distribution.Record) *loadedPack {
	t.Helper()
	layout := DefaultLayout()
	if len(records) == 0 {
		raw := []byte(`{"revision":"1"}`)
		residue, err := distributionResidue(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &loadedPack{Spec: layout.Packs[0], Present: true, Raw: raw, Members: map[string]json.RawMessage{}, Records: map[string]*record{}, DistResidue: residue}
	}
	return provPackSection(t, distribution.Section{Records: records, Applicability: []distribution.Applicability{}})
}

func provPackSection(t *testing.T, section distribution.Section) *loadedPack {
	t.Helper()
	raw, err := distribution.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	return provPackRaw(t, raw)
}

func provPackRaw(t *testing.T, section []byte) *loadedPack {
	t.Helper()
	packRaw := []byte(`{"` + distribution.PackMember + `":` + string(section) + `}`)
	records, order, err := loadRecords(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	residue, err := distributionResidue(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	return &loadedPack{Spec: DefaultLayout().Packs[0], Present: true, Raw: packRaw, Members: map[string]json.RawMessage{distribution.PackMember: section}, Records: records, RecordOrder: order, DistResidue: residue}
}

// provDecide runs what the gate runs for the distribution changes between
// two packs: classification, the checks that need no excerpt, then the
// re-derivation, then the introduction decision.
func provDecide(t *testing.T, f *provFix, base, head *loadedPack, approval []byte) ([]*Change, map[string]bool) {
	t.Helper()
	opts := f.opts()
	cls := &Classification{base: map[string]*loadedPack{"cncf": base}, head: map[string]*loadedPack{"cncf": head}}
	var todo []*Change
	for _, c := range diffPacks(base, head) {
		cls.Changes = append(cls.Changes, c)
		if c.Class == ClassTightening {
			c.OK, c.Proof = true, ProofNoneRequired
			continue
		}
		if c.Member != "" {
			c.fail("only the pack's entries and records may change through this gate; the top-level member " + c.Member + " changed")
			continue
		}
		if c.Section != sectionDistributions {
			t.Fatalf("unexpected change %+v", c)
		}
		if err := distributionPre(c, base, head, opts); err != nil {
			c.fail(err.Error())
			continue
		}
		todo = append(todo, c)
	}
	rederiveDistributions(opts, todo)
	if approval != nil {
		writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(distributionsApprovalPath(opts.Layout, "cncf"))), approval)
	}
	keys := servedKeys(f.key)
	loadKeys := func() (*ApprovalKeys, error) { return &keys, nil }
	return cls.Changes, admitDistributionIntroduction(cls, opts, loadKeys, &baseApprovals{opts: opts})
}

func signDistributions(t *testing.T, key testApprovalKey, base, head *loadedPack) []byte {
	t.Helper()
	_, statement, err := distributionsIntroductionStatement(base, head)
	if err != nil {
		t.Fatal(err)
	}
	subject := ApprovalSubject{Kind: ApprovalSubjectDistributions, Pack: "cncf", RuleID: DistributionsApprovalID, Scope: DistributionsApprovalScope, Candidate: statement}
	raw, _, err := SignApproval(SignApprovalOptions{Subject: subject, CandidateID: "cand-1", Identity: "airstand", Keys: servedKeys(key), Key: key.private, Now: gateNow})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func requireRefused(t *testing.T, changes []*Change, want string) {
	t.Helper()
	requireSomeRefused(t, changes, want, false)
}

// requireSomeRefused: a change that mentions want is refused; unless partial,
// every change is.
func requireSomeRefused(t *testing.T, changes []*Change, want string, partial bool) {
	t.Helper()
	if len(changes) == 0 {
		t.Fatal("no change was classified")
	}
	found := false
	for _, c := range changes {
		if c.OK && !partial {
			t.Fatalf("%s was admitted (%s)", c.RuleID+c.Member, c.Proof)
		}
		if strings.Contains(c.Detail, want) && !c.OK {
			found = true
		}
	}
	if !found {
		t.Fatalf("no refusal mentions %q: %q", want, changes[0].Detail)
	}
}

func requireAdmitted(t *testing.T, changes []*Change) {
	t.Helper()
	if len(changes) == 0 {
		t.Fatal("no change was classified")
	}
	for _, c := range changes {
		if !c.OK {
			t.Fatalf("%s refused: %s", c.RuleID+c.Member, c.Detail)
		}
	}
}

const (
	provGoodPin = "v0.1.0-beta.1"
	provOldPin  = "v0.1.0-beta.0"
	provCommit  = "2026-10-02T00:00:00Z"
)

// A record re-derived from a committed excerpt is admitted: its introduction
// with an owner approval bound to it, a later renewal without one.
func TestProviderRowsAreRederived(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	base := provPack(t)
	head := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30))
	changes, admitted := provDecide(t, f, base, head, signDistributions(t, f.key, base, head))
	requireAdmitted(t, changes)
	if !admitted["cncf"] || changes[0].Proof != ProofRederived {
		t.Fatalf("admitted %v proof %q", admitted, changes[0].Proof)
	}

	// A renewal: the base holds the member with a record derived earlier.
	older := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt.Add(-20*time.Hour), 30))
	changes, admitted = provDecide(t, f, older, head, nil)
	requireAdmitted(t, changes)
	if len(admitted) != 0 || changes[0].Class != ClassLoosening || changes[0].Proof != ProofRederived {
		t.Fatalf("renewal: admitted %v change %+v", admitted, changes[0])
	}
}

func TestProviderRowRefusals(t *testing.T) {
	managed := distribution.ControlPlaneManaged
	good := func(f *provFix, t *testing.T) distribution.Record {
		return f.record(t, "eks", managed, nil, provDerivedAt, 30)
	}
	existing := func(f *provFix, t *testing.T) *loadedPack {
		return provPack(t, f.record(t, "eks", managed, nil, provDerivedAt.Add(-20*time.Hour), 30))
	}
	// mutate edits the record's JSON, so a bypass of the validator's own
	// rules cannot hide a gap in the gate's.
	mutate := func(t *testing.T, r distribution.Record, edit func(m map[string]any)) *loadedPack {
		t.Helper()
		raw, _ := json.Marshal(r)
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		raw, _ = json.Marshal(m)
		var edited distribution.Record
		if err := json.Unmarshal(raw, &edited); err != nil {
			t.Fatal(err)
		}
		return provPack(t, edited)
	}
	evidenceOf := func(m map[string]any) map[string]any { return m["evidence"].(map[string]any) }

	cases := []struct {
		name  string
		pin   string
		date  string
		setup func(f *provFix, t *testing.T) (base, head *loadedPack)
		want  string
		// partial: a renewal of another record in the same change is fine.
		partial bool
	}{
		{"hand-edited date", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) {
				m["lifecycle"].([]any)[0].(map[string]any)["standardEnd"] = "2030-01-01"
			})
		}, "differs from what deriver", false},
		{"an added provider fact", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) {
				m["deprecations"] = []any{map[string]any{"id": "x", "summary": "gone", "firstLine": "1.40"}}
			})
		}, "differs from what deriver", false},
		{"reviewed basis", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) {
				delete(evidenceOf(m), "basis")
				delete(evidenceOf(m), "extractor")
				delete(evidenceOf(m), "derivedAt")
			})
		}, "not admitted, and no approval admits it", false},
		{"unknown deriver", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) { evidenceOf(m)["extractor"].(map[string]any)["id"] = "other" })
		}, "no deriver other is compiled", false},
		{"deriver version", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) { evidenceOf(m)["extractor"].(map[string]any)["version"] = "2.0.0" })
		}, "this gate runs", false},
		{"deriver digest", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) {
				evidenceOf(m)["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("d", 64)
			})
		}, "this gate runs", false},
		{"derived long ago", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), provPack(t, f.record(t, "eks", managed, nil, gateNow.Add(-30*time.Hour), 30))
		}, "outside [now-24h, now+5m]", false},
		{"derived ahead of time", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), provPack(t, f.record(t, "eks", managed, nil, gateNow.Add(time.Hour), 30))
		}, "outside [now-24h, now+5m]", false},
		{"withdrawn row", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return provPack(t), mutate(t, good(f, t), func(m map[string]any) { evidenceOf(m)["state"] = "withdrawn" })
		}, "admitted only when active", false},
		{"no provider facts", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) { delete(m, "lifecycle") })
		}, "nothing to re-derive", false},
		{"a new distribution beside an existing one", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), provPack(t, good(f, t), f.record(t, "gke", managed, nil, provDerivedAt, 30))
		}, "introduced with an owner approval", true},
		{"a removed record", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return provPack(t, f.record(t, "eks", managed, nil, provDerivedAt.Add(-20*time.Hour), 30), f.record(t, "gke", managed, nil, provDerivedAt.Add(-20*time.Hour), 30)),
				provPack(t, good(f, t))
		}, "is not removed through the gate", true},
		{"a changed identity", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			one := []distribution.Mapping{{Line: "4.14", Kubernetes: "1.27"}}
			two := []distribution.Mapping{{Line: "4.14", Kubernetes: "1.27"}, {Line: "4.15", Kubernetes: "1.28"}}
			return provPack(t, f.record(t, "openshift", distribution.ControlPlaneSelfManaged, one, provDerivedAt.Add(-20*time.Hour), 30)),
				provPack(t, f.record(t, "openshift", distribution.ControlPlaneSelfManaged, two, provDerivedAt, 30))
		}, "outside the provider fields", false},
		{"a base record that is reviewed", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			reviewed := mutate(t, f.record(t, "eks", managed, nil, provDerivedAt.Add(-20*time.Hour), 30), func(m map[string]any) {
				delete(evidenceOf(m), "basis")
				delete(evidenceOf(m), "extractor")
				delete(evidenceOf(m), "derivedAt")
			})
			return reviewed, provPack(t, good(f, t))
		}, "its base record is not", false},
		{"a digest the manifest does not hold", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) {
				evidenceOf(m)["sources"].([]any)[0].(map[string]any)["contentDigest"] = "sha256:" + strings.Repeat("9", 64)
			})
		}, "digest differs from the manifest", false},
		{"an excerpt the base does not have", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			rec := f.record(t, "eks", managed, nil, provDerivedAt, 30)
			rec.Evidence.Sources = f.source(f.later)
			return existing(f, t), provPack(t, rec)
		}, "is not part of the base", false},
		{"a span outside the excerpt", provGoodPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), mutate(t, good(f, t), func(m map[string]any) {
				evidenceOf(m)["sources"].([]any)[0].(map[string]any)["endLine"] = 30
			})
		}, "outside the excerpt body", false},
		{"an excerpt fetched after the citing commit", provGoodPin, "2026-09-01T00:00:00Z", func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), provPack(t, good(f, t))
		}, "fetchedAt is after the citing commit", false},
		{"the base still supports an old client", provOldPin, provCommit, func(f *provFix, t *testing.T) (*loadedPack, *loadedPack) {
			return existing(f, t), provPack(t, good(f, t))
		}, "cannot read provider facts", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newProvFix(t, tc.date, tc.pin)
			base, head := tc.setup(f, t)
			changes, admitted := provDecide(t, f, base, head, nil)
			requireSomeRefused(t, changes, tc.want, tc.partial)
			if len(admitted) != 0 {
				t.Fatalf("admitted %v", admitted)
			}
		})
	}
}

func TestProviderIntroductionNeedsAnOwnerApproval(t *testing.T) {
	managed := distribution.ControlPlaneManaged
	build := func(t *testing.T) (*provFix, *loadedPack, *loadedPack) {
		f := newProvFix(t, provCommit, provGoodPin)
		return f, provPack(t), provPack(t, f.record(t, "eks", managed, nil, provDerivedAt, 30))
	}
	t.Run("without an approval", func(t *testing.T) {
		f, base, head := build(t)
		changes, admitted := provDecide(t, f, base, head, nil)
		requireRefused(t, changes, "no owner approval")
		if admitted["cncf"] {
			t.Fatal("admitted")
		}
	})
	t.Run("an approval over other record bytes", func(t *testing.T) {
		f, base, head := build(t)
		other := provPack(t, f.record(t, "eks", managed, nil, provDerivedAt.Add(-time.Minute), 30))
		changes, admitted := provDecide(t, f, base, head, signDistributions(t, f.key, base, other))
		requireRefused(t, changes, "candidate digest")
		if admitted["cncf"] {
			t.Fatal("admitted")
		}
	})
	t.Run("an approval of a key that is not pinned", func(t *testing.T) {
		f, base, head := build(t)
		_, statement, _ := distributionsIntroductionStatement(base, head)
		stranger := newApprovalKey(t)
		raw, _, err := SignApproval(SignApprovalOptions{Subject: ApprovalSubject{Kind: ApprovalSubjectDistributions, Pack: "cncf", RuleID: DistributionsApprovalID, Scope: DistributionsApprovalScope, Candidate: statement}, CandidateID: "c", Identity: "airstand", Keys: servedKeys(stranger), Key: stranger.private, Now: gateNow})
		if err != nil {
			t.Fatal(err)
		}
		changes, admitted := provDecide(t, f, base, head, raw)
		requireRefused(t, changes, "not pinned")
		if admitted["cncf"] {
			t.Fatal("admitted")
		}
	})
	t.Run("an approval of the served-list subject", func(t *testing.T) {
		f, base, head := build(t)
		_, statement, _ := distributionsIntroductionStatement(base, head)
		raw, _, err := SignApproval(SignApprovalOptions{Subject: ApprovalSubject{Kind: ApprovalSubjectServed, Pack: "cncf", RuleID: ServedApprovalID, Scope: ServedApprovalScope, Candidate: statement}, CandidateID: "c", Identity: "airstand", Keys: servedKeys(f.key), Key: f.key.private, Now: gateNow})
		if err != nil {
			t.Fatal(err)
		}
		changes, admitted := provDecide(t, f, base, head, raw)
		requireRefused(t, changes, "introducing the distributions member")
		if admitted["cncf"] {
			t.Fatal("admitted")
		}
	})
	t.Run("an approval the base already holds", func(t *testing.T) {
		f, base, head := build(t)
		raw := signDistributions(t, f.key, base, head)
		writeFile(t, filepath.Join(f.base.Root, filepath.FromSlash(distributionsApprovalPath(DefaultLayout(), "cncf"))), raw)
		changes, admitted := provDecide(t, f, base, head, raw)
		requireRefused(t, changes, "already in the base")
		if admitted["cncf"] {
			t.Fatal("admitted")
		}
	})
	t.Run("a record that is not re-derived leaves its own reason", func(t *testing.T) {
		f, base, head := build(t)
		f.derivers = map[string]ProviderDeriver{}
		changes, admitted := provDecide(t, f, base, head, signDistributions(t, f.key, base, head))
		requireRefused(t, changes, "no deriver provider-test is compiled")
		if admitted["cncf"] {
			t.Fatal("admitted")
		}
	})
	t.Run("a pack added together with the member", func(t *testing.T) {
		f, _, head := build(t)
		absent := &loadedPack{Spec: DefaultLayout().Packs[0], Members: map[string]json.RawMessage{}, Records: map[string]*record{}}
		changes, admitted := provDecide(t, f, absent, head, nil)
		requireRefused(t, changes, "together with its pack")
		if admitted["cncf"] {
			t.Fatal("admitted")
		}
	})
}

// Whatever the section holds besides its records is a pack-member change of
// its own, never carried along by a record change, and the gate refuses it.
func TestProviderApplicabilityStaysAPackMemberChange(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	rec := f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30)
	older := f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt.Add(-20*time.Hour), 30)
	statement := distribution.Applicability{Distribution: "eks", Family: distribution.FamilyRemovedServedGVK, Status: distribution.StatusApplies, Evidence: rec.Evidence}
	section := func(apps ...distribution.Applicability) distribution.Section {
		if apps == nil {
			apps = []distribution.Applicability{}
		}
		return distribution.Section{Records: []distribution.Record{rec}, Applicability: apps}
	}
	for name, tc := range map[string]struct {
		base, head *loadedPack
	}{
		"introduced with a statement":    {provPack(t), provPackSection(t, section(statement))},
		"a statement added to an update": {provPack(t, older), provPackSection(t, section(statement))},
		"a statement removed":            {provPackSection(t, distribution.Section{Records: []distribution.Record{older}, Applicability: []distribution.Applicability{statement}}), provPackSection(t, section())},
	} {
		t.Run(name, func(t *testing.T) {
			changes, admitted := provDecide(t, f, tc.base, tc.head, nil)
			member := false
			for _, c := range changes {
				if c.Member == distribution.PackMember {
					member = true
					if c.Class != ClassLoosening || c.OK {
						t.Fatalf("member change %+v", c)
					}
				}
			}
			if !member {
				t.Fatalf("no pack-member change: %+v", changes)
			}
			if admitted["cncf"] {
				t.Fatal("admitted")
			}
		})
	}
	// And a section that changes nothing but its statements is the member
	// change alone.
	changes := diffPacks(provPackSection(t, section()), provPackSection(t, section(statement)))
	if len(changes) != 1 || changes[0].Member != distribution.PackMember || changes[0].Kinds[0] != KindPackMember {
		t.Fatalf("%+v", changes)
	}
}

// A change that makes a record expire earlier is tightening and needs no
// proof; every other edit of a record is loosening.
func TestProviderRecordChangeClasses(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	managed := distribution.ControlPlaneManaged
	base := provPack(t, f.record(t, "eks", managed, nil, provDerivedAt, 30))
	shorter := provPack(t, f.record(t, "eks", managed, nil, provDerivedAt, 10))
	if changes := diffPacks(base, shorter); len(changes) != 1 || changes[0].Class != ClassTightening {
		t.Fatalf("shorter lease: %+v", changes)
	}
	longer := provPack(t, f.record(t, "eks", managed, nil, provDerivedAt, 60))
	if changes := diffPacks(base, longer); len(changes) != 1 || changes[0].Class != ClassLoosening {
		t.Fatalf("longer lease: %+v", changes)
	}
	if changes := diffPacks(base, provPack(t)); len(changes) == 0 || changes[0].Class != ClassLoosening {
		t.Fatalf("removed: %+v", changes)
	}
}

// With no excerpt store and with the production (empty) registry the gate
// admits nothing, even a record the test deriver would admit.
func TestProviderRowsRefusedWithoutStoreOrCompiledDeriver(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	head := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30))
	older := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt.Add(-20*time.Hour), 30))
	f.store = nil
	changes, _ := provDecide(t, f, older, head, nil)
	requireRefused(t, changes, "no excerpt store")

	f2 := newProvFix(t, provCommit, provGoodPin)
	f2.derivers = nil // the compiled registry
	if len(compiledProviderDerivers) != 0 {
		t.Fatal("the production deriver registry is not empty")
	}
	changes, _ = provDecide(t, f2, older, head, nil)
	requireRefused(t, changes, "is compiled into this gate")

	f3 := newProvFix(t, provCommit, provGoodPin)
	f3.store = &ExcerptStore{Read: f3.store.Read, CommitTime: f3.store.CommitTime}
	changes, _ = provDecide(t, f3, older, head, nil)
	requireRefused(t, changes, "no excerpt store")
}

func TestProviderClientFloor(t *testing.T) {
	write := func(f *provFix, tr Tree, content string) {
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)), []byte(content))
	}
	ref := "ref=" + strings.Repeat("a", 40) + "\n"
	for name, tc := range map[string]struct {
		edit func(f *provFix)
		want string // empty: admitted
	}{
		"both at the floor":        {func(f *provFix) {}, ""},
		"a later release":          {func(f *provFix) { write(f, f.head, ref+"version=v0.2.0\n"); write(f, f.base, ref+"version=v0.1.0\n") }, ""},
		"head below":               {func(f *provFix) { write(f, f.head, ref+"version=v0.1.0-beta.0\n") }, "the head still supports client v0.1.0-beta.0"},
		"base below":               {func(f *provFix) { write(f, f.base, ref+"version=v0.0.9\n") }, "the base still supports client v0.0.9"},
		"an earlier prerelease":    {func(f *provFix) { write(f, f.base, ref+"version=v0.1.0-alpha.9\n") }, "the base still supports"},
		"a missing pin":            {func(f *provFix) { _ = os.Remove(filepath.Join(f.head.Root, filepath.FromSlash(OldestClientPinPath))) }, "the head's oldest supported client pin"},
		"an unreadable pin":        {func(f *provFix) { write(f, f.base, "version=v0.2.0\n") }, "the base's oldest supported client pin"},
		"a pin that is no version": {func(f *provFix) { write(f, f.base, ref+"version=latest\n") }, "not a version"},
		"a pin with extra lines":   {func(f *provFix) { write(f, f.head, ref+"version=v0.2.0\nextra=1\n") }, "does not hold exactly"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProvFix(t, provCommit, provGoodPin)
			tc.edit(f)
			head := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30))
			older := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt.Add(-20*time.Hour), 30))
			changes, _ := provDecide(t, f, older, head, nil)
			if tc.want == "" {
				requireAdmitted(t, changes)
			} else {
				requireRefused(t, changes, tc.want)
			}
		})
	}
}

func TestGitExcerptStore(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	if err := f.store.OnBase(f.baseSHA); err != nil {
		t.Fatalf("the base itself: %v", err)
	}
	if err := f.store.OnBase(f.later); err == nil || !strings.Contains(err.Error(), "not part of the base") {
		t.Fatalf("a commit after the base: %v", err)
	}
	for _, bad := range []string{"", "HEAD", "--all", strings.Repeat("g", 40), f.baseSHA[:12]} {
		if err := f.store.OnBase(bad); err == nil {
			t.Fatalf("revision %q accepted", bad)
		}
	}
	if _, err := GitExcerptStore("", f.baseSHA); err == nil {
		t.Fatal("no git dir accepted")
	}
	if _, err := GitExcerptStore(f.dir, "main"); err == nil {
		t.Fatal("a branch name accepted as the base")
	}
}

// The distributions section is a record section only for a pack that reads
// records, and the identity of a record is never part of a provider change.
func TestDistributionRecordIdentityExcludesProviderFields(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	a := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30))
	b := provPack(t, f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt.Add(-time.Hour), 45))
	ra, rb := a.Records[DistributionRecordID("eks")], b.Records[DistributionRecordID("eks")]
	if string(identityCanonical(ra)) != string(identityCanonical(rb)) {
		t.Fatal("renewing a record changed its identity")
	}
	if strings.Contains(string(identityCanonical(ra)), "lifecycle") || strings.Contains(string(identityCanonical(ra)), "evidence") {
		t.Fatalf("identity holds provider fields: %s", identityCanonical(ra))
	}
	if !recordSection(a.Spec, sectionDistributions) || recordSection(PackSpec{Name: "x"}, sectionDistributions) {
		t.Fatal("recordSection")
	}
	if _, err := extract.Canonical(ra.Raw); err != nil {
		t.Fatal(err)
	}
}

// The schema bump a first introduction needs rides the existing path: it is
// admitted only to the lowest level the content requires and only when every
// record change of the pack is admitted.
func TestProviderIntroductionSchemaBump(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	rec := f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30)
	section, err := distribution.Marshal(distribution.Section{Records: []distribution.Record{rec}, Applicability: []distribution.Applicability{}})
	if err != nil {
		t.Fatal(err)
	}
	spec := DefaultLayout().Packs[0]
	if spec.RequiredSchema == nil {
		t.Fatal("the pack has no schema levels")
	}
	required, err := spec.RequiredSchema([]byte(`{"schema":"prufyx.io/cncf-source-rule-pack/v1alpha8","distributions":` + string(section) + `}`))
	if err != nil || required != "prufyx.io/cncf-source-rule-pack/v1alpha9" {
		t.Fatalf("required %q %v", required, err)
	}
	if got := fmt.Sprint(cncfcheck.PackCarriesProviderFacts(section)); got != "true" {
		t.Fatal("a section with provider facts does not say so")
	}
}

// The schema bump of a first introduction rides admitSchemaChanges: it is
// admitted once every record change of the pack is, to the level the content
// requires, and it is refused beside an applicability statement or an
// unadmitted record.
func TestProviderIntroductionSchemaBumpRidesTheExistingPath(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	rec := f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30)
	apps := []distribution.Applicability{{Distribution: "eks", Family: distribution.FamilyRemovedServedGVK, Status: distribution.StatusApplies, Evidence: rec.Evidence}}
	run := func(t *testing.T, apps []distribution.Applicability, admitRecords bool) error {
		t.Helper()
		base, head := trees(t)
		section, err := distribution.Marshal(distribution.Section{Records: []distribution.Record{rec}, Applicability: append([]distribution.Applicability{}, apps...)})
		if err != nil {
			t.Fatal(err)
		}
		p := readPack(t, head, cncfRulesPath)
		p.fields[distribution.PackMember] = json.RawMessage(section)
		p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha9"`)
		p.write(t, head, cncfRulesPath)
		cls, err := Classify(DefaultLayout(), base, head)
		if err != nil {
			t.Fatal(err)
		}
		var schema *Change
		for _, c := range cls.Changes {
			switch {
			case c.Member == "schema":
				schema = c
			case c.Section == sectionDistributions:
				c.OK = admitRecords
			}
		}
		if schema == nil {
			t.Fatalf("no schema change: %+v", cls.Changes)
		}
		return checkSchemaChange(cls, schema, nil, Options{Layout: DefaultLayout(), Base: base, Head: head})
	}
	if err := run(t, nil, true); err != nil {
		t.Fatalf("the bump with an admitted introduction: %v", err)
	}
	if err := run(t, nil, false); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("the bump beside an unadmitted record: %v", err)
	}
	if err := run(t, apps, true); err == nil || !strings.Contains(err.Error(), "top-level member "+distribution.PackMember+" changed") {
		t.Fatalf("the bump beside an applicability statement: %v", err)
	}
}

// Through the whole gate nothing provider-shaped passes while no deriver is
// compiled in: a mechanical record is refused with its own reason and the
// change is never eligible for automatic merging.
func TestGateRefusesProviderRecordsWithTheProductionRegistry(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	rec := f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30)
	section, err := distribution.Marshal(distribution.Section{Records: []distribution.Record{rec}, Applicability: []distribution.Applicability{}})
	if err != nil {
		t.Fatal(err)
	}
	base, head := trees(t)
	p := readPack(t, head, cncfRulesPath)
	p.fields[distribution.PackMember] = json.RawMessage(section)
	p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha9"`)
	p.write(t, head, cncfRulesPath)
	r, blocked := tryGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin, Excerpts: f.store})
	if !blocked {
		t.Fatal("a provider record passed the gate")
	}
	if r == nil {
		return
	}
	if r.AutoMerge.Eligible {
		t.Fatal("a provider record is eligible for automatic merging")
	}
	refused := false
	for _, c := range r.Changes {
		if c.Section == sectionDistributions {
			refused = true
			if c.OK {
				t.Fatalf("provider record admitted: %+v", c)
			}
		}
	}
	if !refused {
		t.Fatalf("no provider record change: %+v", r.Changes)
	}
}

func TestDistributionsApprovalIsWiredIntoTheApprovalCommands(t *testing.T) {
	rec := ApprovalRecord{
		BaseDigest: ApprovalBaseAbsent, CandidateDigest: "sha256:" + strings.Repeat("a", 64), CandidateID: "c", DecidedAt: "2026-10-03T00:00:00Z",
		Decision: ApprovalDecisionApprove, Identity: "airstand", Pack: "cncf", RuleID: DistributionsApprovalID, Subject: ApprovalSubjectDistributions, Scope: DistributionsApprovalScope,
	}
	if _, err := SignedApprovalBytes(rec); err != nil {
		t.Fatalf("a distributions approval record: %v", err)
	}
	for name, edit := range map[string]func(*ApprovalRecord){
		"a base digest":   func(r *ApprovalRecord) { r.BaseDigest = "sha256:" + strings.Repeat("b", 64) },
		"another scope":   func(r *ApprovalRecord) { r.Scope = "servedAPIs" },
		"another rule id": func(r *ApprovalRecord) { r.RuleID = ServedApprovalID },
	} {
		bad := rec
		edit(&bad)
		if _, err := SignedApprovalBytes(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// The commands read the introduction from a base and a head checkout.
	f := newProvFix(t, provCommit, provGoodPin)
	key := newApprovalKey(t)
	base, head := trees(t)
	key.pinBoth(t, base, head, "airstand")
	section, err := distribution.Marshal(distribution.Section{Records: []distribution.Record{f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30)}, Applicability: []distribution.Applicability{}})
	if err != nil {
		t.Fatal(err)
	}
	p := readPack(t, head, cncfRulesPath)
	p.fields[distribution.PackMember] = json.RawMessage(section)
	p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha9"`)
	p.write(t, head, cncfRulesPath)
	keys := filepath.Join(base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
	keysRaw, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	subject := []string{"--subject", "distributions", "--pack", "cncf", "--base-root", base.Root, "--head-root", head.Root, "--keys", keys, "--keys-digest", pinnedDigest(keysRaw)}
	out := filepath.Join(head.Root, filepath.FromSlash(distributionsApprovalPath(DefaultLayout(), "cncf")))
	r := runApproval(t, nil, signNow, append(append([]string{"sign"}, subject...), "--identity", "airstand", "--candidate-id", "cand-1", "--key", key.keyFile(t, 0o600), "--output", out)...)
	if r.code != 0 || !strings.Contains(r.stdout, "distribution records introduction cncf/"+DistributionsApprovalID) {
		t.Fatalf("sign: %d %s %s", r.code, r.stdout, r.stderr)
	}
	r = runApproval(t, nil, signNow, append(append([]string{"verify"}, subject...), "--approval", out)...)
	if r.code != 0 || !strings.HasPrefix(r.stdout, "approval OK") {
		t.Fatalf("verify: %d %s %s", r.code, r.stdout, r.stderr)
	}
	// An approval of one introduction does not verify another.
	other := copyTree(t, head)
	p = readPack(t, other, cncfRulesPath)
	section, _ = distribution.Marshal(distribution.Section{Records: []distribution.Record{f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt.Add(-time.Minute), 30)}, Applicability: []distribution.Applicability{}})
	p.fields[distribution.PackMember] = json.RawMessage(section)
	p.write(t, other, cncfRulesPath)
	otherSubject := append([]string{}, subject...)
	otherSubject[7] = other.Root
	r = runApproval(t, nil, signNow, append(append([]string{"verify"}, otherSubject...), "--approval", out)...)
	if r.code == 0 {
		t.Fatalf("verify of another introduction: %s", r.stdout)
	}
}

// A deriver reads only the (revision, path) pairs its record cites. Anything
// else is a typed refusal, even when the deriver swallows the error and still
// returns the right record.
func TestProviderDeriverReadsOnlyCitedExcerpts(t *testing.T) {
	managed := distribution.ControlPlaneManaged
	cited := providerexcerpt.Dir + "/" + provExcerptPath
	build := func(t *testing.T, rev, path string, swallow bool) ([]*Change, map[string]bool, *provFix) {
		f := newProvFix(t, provCommit, provGoodPin)
		inner := provDeriver(provIdentity)
		head := provPack(t, f.record(t, "eks", managed, nil, provDerivedAt, 30))
		f.derivers = map[string]ProviderDeriver{provIdentity.ID: {Identity: provIdentity, Derive: func(in ProviderDeriveInput) (distribution.Record, error) {
			r := rev
			switch r {
			case "":
				r = f.baseSHA
			case "later":
				r = f.later
			}
			if _, err := in.Read(r, path); err != nil && !swallow {
				return distribution.Record{}, err
			}
			return inner.Derive(in)
		}}}
		base := provPack(t)
		changes, admitted := provDecide(t, f, base, head, signDistributions(t, f.key, base, head))
		return changes, admitted, f
	}
	t.Run("the cited pair is read", func(t *testing.T) {
		changes, admitted, _ := build(t, "", cited, false)
		requireAdmitted(t, changes)
		if !admitted["cncf"] {
			t.Fatal("not admitted")
		}
	})
	for name, tc := range map[string]struct{ rev, path string }{
		"an uncited path":            {"", "other.txt"},
		"an uncited excerpt":         {"", providerexcerpt.Dir + "/eks/eks-1-34.txt"},
		"a path traversal":           {"", providerexcerpt.Dir + "/eks/../eks/eks-1-33.txt"},
		"a traversal out of the dir": {"", providerexcerpt.Dir + "/../other.txt"},
		"a different revision":       {"later", cited},
		"a symlink-like path":        {"", providerexcerpt.Dir + "/eks/./eks-1-33.txt"},
		"a trailing separator":       {"", cited + "/"},
		"a case variant":             {"", strings.ToUpper(cited)},
	} {
		for _, swallow := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s swallowed=%v", name, swallow), func(t *testing.T) {
				changes, admitted, _ := build(t, tc.rev, tc.path, swallow)
				requireRefused(t, changes, ErrUncitedRead.Error())
				if admitted["cncf"] {
					t.Fatal("admitted")
				}
			})
		}
	}
}

func TestCitedReaderRecordsEveryRead(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	cr, err := newCitedReader(f.source(""), f.store.Read)
	if err != nil {
		t.Fatal(err)
	}
	cited := providerexcerpt.Dir + "/" + provExcerptPath
	if _, err := cr.Read(f.baseSHA, cited); err != nil {
		t.Fatal(err)
	}
	if _, err := cr.Read(f.later, cited); !errors.Is(err, ErrUncitedRead) {
		t.Fatalf("%v", err)
	}
	if len(cr.reads) != 2 || len(cr.refused) != 1 || cr.check() == nil {
		t.Fatalf("reads %v refused %v", cr.reads, cr.refused)
	}
	bad := f.source("")
	bad[0].URL = "https://example.com/x"
	if _, err := newCitedReader(bad, f.store.Read); err == nil {
		t.Fatal("a source that cites no excerpt of this store must refuse")
	}
}

// The first introduction of a distribution record carries records only, and a
// later change never adds, removes or changes an applicability statement: the
// record change itself is refused with a typed reason, not only the member.
func TestProviderRecordChangeRefusesApplicabilityStatements(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	rec := f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt, 30)
	older := f.record(t, "eks", distribution.ControlPlaneManaged, nil, provDerivedAt.Add(-20*time.Hour), 30)
	statement := distribution.Applicability{Distribution: "eks", Family: distribution.FamilyRemovedServedGVK, Status: distribution.StatusApplies, Evidence: rec.Evidence}
	changed := statement
	changed.Status = distribution.StatusNotApplicable
	section := func(r distribution.Record, apps ...distribution.Applicability) distribution.Section {
		if apps == nil {
			apps = []distribution.Applicability{}
		}
		return distribution.Section{Records: []distribution.Record{r}, Applicability: apps}
	}
	for name, tc := range map[string]struct{ base, head *loadedPack }{
		"introduced with a statement": {provPack(t), provPackSection(t, section(rec, statement))},
		"a statement added":           {provPack(t, older), provPackSection(t, section(rec, statement))},
		"a statement removed":         {provPackSection(t, section(older, statement)), provPackSection(t, section(rec))},
		"a statement changed":         {provPackSection(t, section(older, statement)), provPackSection(t, section(rec, changed))},
	} {
		t.Run(name, func(t *testing.T) {
			if err := applicabilityUnchanged(tc.base, tc.head); !errors.Is(err, ErrApplicabilityChange) {
				t.Fatalf("%v", err)
			}
			changes, admitted := provDecide(t, f, tc.base, tc.head, nil)
			sawRecord := false
			for _, c := range changes {
				if c.Section != sectionDistributions {
					continue
				}
				sawRecord = true
				if c.OK || !strings.Contains(c.Detail, ErrApplicabilityChange.Error()) {
					t.Fatalf("record change %+v", c)
				}
			}
			if !sawRecord {
				t.Fatalf("no record change: %+v", changes)
			}
			if admitted["cncf"] {
				t.Fatal("admitted")
			}
		})
	}
	// Unchanged statements ride along: a renewal that keeps them is not
	// refused for them.
	if err := applicabilityUnchanged(provPackSection(t, section(older, statement)), provPackSection(t, section(rec, statement))); err != nil {
		t.Fatalf("%v", err)
	}
	if err := applicabilityUnchanged(nil, provPack(t)); !errors.Is(err, ErrApplicabilityChange) {
		t.Fatalf("%v", err)
	}
}

// Two residues that failed to encode are not "equal": the gate refuses.
func TestApplicabilityUnchangedRefusesUnencodableResidues(t *testing.T) {
	for name, tc := range map[string]struct{ base, head *loadedPack }{
		"both nil":  {&loadedPack{Present: true}, &loadedPack{Present: true}},
		"head nil":  {&loadedPack{Present: true, DistResidue: []byte(`{"applicability":[]}`)}, &loadedPack{Present: true}},
		"base nil":  {&loadedPack{Present: true}, &loadedPack{Present: true, DistResidue: []byte(`{"applicability":[]}`)}},
		"both zero": {&loadedPack{Present: true, DistResidue: []byte{}}, &loadedPack{Present: true, DistResidue: []byte{}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := applicabilityUnchanged(tc.base, tc.head); !errors.Is(err, ErrApplicabilityChange) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := encodeResidue(map[string]any{"x": make(chan int)}); err == nil {
		t.Fatal("a value that cannot be encoded must be an error, not a nil residue")
	}
}

// A deriver that keeps Read and calls it after Derive returned gets a typed
// refusal, and the call is recorded.
func TestCitedReaderRefusesReadsAfterClose(t *testing.T) {
	f := newProvFix(t, provCommit, provGoodPin)
	cr, err := newCitedReader(f.source(""), f.store.Read)
	if err != nil {
		t.Fatal(err)
	}
	cited := providerexcerpt.Dir + "/" + provExcerptPath
	stash := cr.Read
	if err := cr.check(); err != nil {
		t.Fatal(err)
	}
	if _, err := stash(f.baseSHA, cited); !errors.Is(err, ErrUncitedRead) {
		t.Fatalf("a cited read after close must be refused: %v", err)
	}
	if len(cr.refused) != 1 || cr.check() == nil {
		t.Fatalf("refused %v", cr.refused)
	}
}

func TestProviderDeriverStashedReadFailsAfterDerive(t *testing.T) {
	managed := distribution.ControlPlaneManaged
	cited := providerexcerpt.Dir + "/" + provExcerptPath
	f := newProvFix(t, provCommit, provGoodPin)
	inner := provDeriver(provIdentity)
	var stash providerexcerpt.Reader
	head := provPack(t, f.record(t, "eks", managed, nil, provDerivedAt, 30))
	f.derivers = map[string]ProviderDeriver{provIdentity.ID: {Identity: provIdentity, Derive: func(in ProviderDeriveInput) (distribution.Record, error) {
		stash = in.Read
		return inner.Derive(in)
	}}}
	base := provPack(t)
	_, admitted := provDecide(t, f, base, head, signDistributions(t, f.key, base, head))
	if !admitted["cncf"] {
		t.Fatal("not admitted")
	}
	if _, err := stash(f.baseSHA, cited); !errors.Is(err, ErrUncitedRead) {
		t.Fatalf("a read after Derive returned must be refused: %v", err)
	}
}
