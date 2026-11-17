// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogattest"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const clComponent = "prometheus"

var clRepo = extract.RepoRef{Key: "github.com/prometheus/prometheus"}

var clTarget = ce.Target{
	Component: clComponent, Repo: clRepo, Form: ce.FormFile, Path: "CHANGELOG.md",
	HeadingPattern:   `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
	BoundaryPatterns: []string{`^(main|master) / unreleased$`},
}

func clCommit(n int) string { return fmt.Sprintf("%039d%d", 0, n) }

var clBodies = map[string]string{
	"3.5.1": "* [BUGFIX] Fix a crash. #51\n",
	"3.5.0": "* [FEATURE] Add `a`. #50\n* [CHANGE] Remove flag `--b`. #52\n  continued\n",
	"3.4.1": "* [BUGFIX] Fix a leak. #41\n",
	"3.4.0": "* [FEATURE] Add `c`. #40\n",
	"3.3.0": "* [FEATURE] Add `d`. #30\n",
}
var clOrder = []string{"3.5.1", "3.5.0", "3.4.1", "3.4.0", "3.3.0"}

func clTags() []extract.Tag {
	return []extract.Tag{
		{Name: "v3.3.0", Commit: clCommit(0)},
		{Name: "v3.4.0", Commit: clCommit(1)}, {Name: "v3.4.1", Commit: clCommit(2)},
		{Name: "v3.5.0", Commit: clCommit(3)}, {Name: "v3.5.1", Commit: clCommit(4)},
	}
}

func clFileUpTo(v string, override map[string]string) string {
	var b strings.Builder
	b.WriteString("# Changelog\n\n## main / unreleased\n\n")
	on := false
	for _, ver := range clOrder {
		if ver == v {
			on = true
		}
		if !on {
			continue
		}
		body := clBodies[ver]
		if o, ok := override[ver]; ok {
			body = o
		}
		fmt.Fprintf(&b, "## %s / 2025-01-01\n\n%s\n", ver, body)
	}
	return b.String()
}

// clSource serves the changelog of each tag commit and the tag list.
type clSource struct {
	mu    sync.Mutex
	files map[string]string
	tags  []extract.Tag
}

func newCLSource(override map[string]string) *clSource {
	s := &clSource{files: map[string]string{}, tags: clTags()}
	for i, v := range []string{"3.3.0", "3.4.0", "3.4.1", "3.5.0", "3.5.1"} {
		s.files[clCommit(i)+":CHANGELOG.md"] = clFileUpTo(v, override)
	}
	return s
}

func (s *clSource) Read(_ extract.RepoRef, c, p string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.files[c+":"+p]
	if !ok {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
	}
	return []byte(b), nil
}
func (s *clSource) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("no list")
}
func (s *clSource) Tags(extract.RepoRef) ([]extract.Tag, error) {
	return append([]extract.Tag(nil), s.tags...), nil
}

var clNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// clWorld is a head tree with the reviewed dispositions, the options of a
// gate run and a record derived from them.
type clWorld struct {
	t     *testing.T
	src   *clSource
	marks []changelogattest.Mark
	root  string
	opts  Options
	head  *loadedPack
}

func clMark(tag string, it ce.Item) changelogattest.Mark {
	return changelogattest.Mark{ItemDigest: it.Digest, Occurrence: it.Occurrence, Tag: tag, Kind: changelogattest.KindNotOperatorFacing, ReasonClass: "docs",
		State: changelogattest.StateReviewed, ReviewedAt: "2026-11-01T00:00:00Z", ProposedBy: changelogattest.ProposedByPerson}
}

func newCLWorld(t *testing.T) *clWorld {
	t.Helper()
	w := &clWorld{t: t, src: newCLSource(nil), head: &loadedPack{Entries: map[string]*entry{}, Records: map[string]*record{}}}
	for _, tg := range clTags() {
		if tg.Name == "v3.3.0" || tg.Name == "v3.4.0" {
			continue
		}
		e, err := ce.Locate(w.src, clTarget, tg)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range e.Items {
			w.marks = append(w.marks, clMark(tg.Name, it))
		}
	}
	w.root = t.TempDir()
	w.write()
	w.opts = Options{
		Source: w.src, Head: Tree{Root: w.root}, Now: clNow,
		Changelog:       ChangelogConfig{Targets: map[string]ce.Target{clComponent: clTarget}, DispositionsDir: "dispositions"},
		changelogAdmits: func(c string) bool { return c == clComponent },
	}
	return w
}

func (w *clWorld) write() {
	w.t.Helper()
	raw, err := json.Marshal(changelogattest.Dispositions{Component: clComponent, Marks: w.marks})
	if err != nil {
		w.t.Fatal(err)
	}
	w.writeRaw(raw)
}

func (w *clWorld) writeRaw(raw []byte) {
	w.t.Helper()
	dir := filepath.Join(w.root, "dispositions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prometheus.json"), raw, 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func clIdentity(t *testing.T) constraintengine.Extractor {
	t.Helper()
	files, err := extract.CodeFiles(extract.FrameworkSource(), changelogattest.SourceSet())
	if err != nil {
		t.Fatal(err)
	}
	return constraintengine.Extractor{ID: changelogattest.IDPrefix + "prometheus", Version: changelogattest.Version, CodeDigest: extract.CodeDigest(files)}
}

// derive builds the record the gate must admit: the extractor's own
// derivation, stamped, at derivedAt with the lease.
func (w *clWorld) derive(derivedAt time.Time, lease time.Duration) *record {
	w.t.Helper()
	prep := w.prep()
	ex, err := changelogattest.New(prep.slug, prep.cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	tags := clTags()
	var pair extract.VersionPair
	for _, p := range ex.Pairs(extract.ReleaseIndex{Repo: clRepo, Tags: tags}) {
		if p.To == "3.5.0" {
			pair = p
		}
	}
	rd := extract.NewRecorder(w.src)
	res, err := ex.Extract(context.Background(), rd, pair)
	if err != nil {
		w.t.Fatal(err)
	}
	da, vu := derivedAt.UTC().Format(time.RFC3339), derivedAt.Add(lease).UTC().Format(time.RFC3339)
	a, err := stampChangelog(res.Attestations[0], rd, clRepo, tags, clIdentity(w.t), da, vu)
	if err != nil {
		w.t.Fatal(err)
	}
	return clRecord(w.t, a)
}

// prep reads the preparation of the real checks with a record that passes
// the shape checks, to reuse its config.
func (w *clWorld) prep() *changelogPrep {
	w.t.Helper()
	disp, err := changelogattest.LoadDispositions(mustRead(w.t, filepath.Join(w.root, "dispositions", "prometheus.json")), clComponent)
	if err != nil {
		w.t.Fatal(err)
	}
	return &changelogPrep{slug: "prometheus", identity: clIdentity(w.t), cfg: changelogattest.Config{Target: clTarget, Dispositions: disp}}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func clRecord(t *testing.T, a lineattest.LineAttestation) *record {
	t.Helper()
	raw, err := extract.Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	id := *a.Evidence.Extractor
	return &record{Section: sectionAttestations, Basis: constraintengine.BasisMechanical, Extractor: &id, DerivedAt: a.Evidence.DerivedAt, ReviewedAt: a.Evidence.ReviewedAt,
		ValidUntil: a.Evidence.ValidUntil, Canonical: raw, attestation: &a}
}

func (w *clWorld) change(rec *record) *Change {
	return &Change{Pack: "p", RuleID: "r", Section: sectionAttestations, Class: ClassLoosening, rhead: rec}
}

// admit runs the gate's two stages on a change.
func (w *clWorld) admit(rec *record, opts Options) *Change {
	w.t.Helper()
	c := w.change(rec)
	prep, err := changelogPre(c, w.head, opts, true)
	if err != nil {
		c.fail(err.Error())
		return c
	}
	changelogRederive(context.Background(), c, prep, opts)
	return c
}

func requireCLCode(t *testing.T, c *Change, code string) {
	t.Helper()
	if c.OK || !strings.HasPrefix(c.Detail, "changelog/"+code+": ") {
		t.Fatalf("want a refusal changelog/%s, got ok=%v detail=%q", code, c.OK, c.Detail)
	}
	if c.Proof == ProofRederived {
		t.Fatalf("a refused change carries Proof=rederived")
	}
}

func goodRecord(w *clWorld) *record { return w.derive(clNow.Add(-time.Hour), 60*24*time.Hour) }

func TestChangelogAdmitted(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	a := rec.attestation
	// The record's shape, read independently of the stamp.
	if len(a.Evidence.Sources) != 3 || len(a.RuleIDs) != 0 || a.Releases == nil || len(a.Releases.From) != 2 || len(a.Releases.To) != 2 {
		t.Fatalf("record %+v", a)
	}
	for i, ver := range []string{"3.4.1", "3.5.0", "3.5.1"} {
		s := a.Evidence.Sources[i]
		if s.ID != "changelog-"+ver || !strings.HasPrefix(s.URL, "https://github.com/prometheus/prometheus/blob/") || !strings.HasSuffix(s.URL, "/CHANGELOG.md") {
			t.Fatalf("source %d %+v", i, s)
		}
	}
	c := w.admit(rec, w.opts)
	if !c.OK || c.Proof != ProofRederived {
		t.Fatalf("not admitted: %q", c.Detail)
	}
}

// The family's member table is empty: with the real table the gate path
// refuses every component, and nothing attests.
func TestChangelogMemberTableStaysEmpty(t *testing.T) {
	f, _ := lineattest.LookupFamily(lineattest.FamilyChangelogAttestedEntries)
	if len(f.Components()) != 0 {
		t.Fatalf("members %v", f.Components())
	}
	w := newCLWorld(t)
	rec := goodRecord(w)
	opts := w.opts
	opts.changelogAdmits = nil
	c := w.admit(rec, opts)
	requireCLCode(t, c, changelogTargetNotAttesting)
	if !strings.Contains(c.Detail, "not a member") {
		t.Fatal(c.Detail)
	}
	// A component the test table does not list is refused as well.
	opts = w.opts
	opts.changelogAdmits = func(string) bool { return false }
	requireCLCode(t, w.admit(rec, opts), changelogTargetNotAttesting)
}

func TestChangelogTargetNotAttesting(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	t.Run("no target row", func(t *testing.T) {
		o := w.opts
		o.Changelog.Targets = nil
		requireCLCode(t, w.admit(rec, o), changelogTargetNotAttesting)
	})
	t.Run("target row of another component", func(t *testing.T) {
		o := w.opts
		other := clTarget
		other.Component = "other"
		o.Changelog.Targets = map[string]ce.Target{clComponent: other}
		requireCLCode(t, w.admit(rec, o), changelogTargetNotAttesting)
	})
	t.Run("no dispositions directory", func(t *testing.T) {
		o := w.opts
		o.Changelog.DispositionsDir = ""
		requireCLCode(t, w.admit(rec, o), changelogTargetNotAttesting)
	})
	t.Run("no dispositions file", func(t *testing.T) {
		o := w.opts
		o.Changelog.DispositionsDir = "elsewhere"
		requireCLCode(t, w.admit(rec, o), changelogTargetNotAttesting)
	})
	t.Run("not a changelog extractor", func(t *testing.T) {
		r := *rec
		x := *rec.Extractor
		x.ID = "crd.custom_resource_versions.prometheus"
		r.Extractor = &x
		requireCLCode(t, w.admit(&r, w.opts), changelogTargetNotAttesting)
	})
	t.Run("no extractor", func(t *testing.T) {
		r := *rec
		r.Extractor = nil
		requireCLCode(t, w.admit(&r, w.opts), changelogTargetNotAttesting)
	})
	t.Run("reviewed basis is never admitted", func(t *testing.T) {
		r := *rec
		r.Basis = constraintengine.BasisReviewed
		requireCLCode(t, w.admit(&r, w.opts), changelogTargetNotAttesting)
	})
}

func TestChangelogExtractorDigest(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	for name, edit := range map[string]func(x *constraintengine.Extractor){
		"code digest": func(x *constraintengine.Extractor) { x.CodeDigest = strings.Repeat("0", len(x.CodeDigest)) },
		"version":     func(x *constraintengine.Extractor) { x.Version = "0.0.1" },
	} {
		t.Run(name, func(t *testing.T) {
			r := *rec
			x := *rec.Extractor
			edit(&x)
			r.Extractor = &x
			requireCLCode(t, w.admit(&r, w.opts), changelogExtractorDigest)
		})
	}
}

func TestChangelogCitationShape(t *testing.T) {
	w := newCLWorld(t)
	good := goodRecord(w)
	cases := map[string]func(a *lineattest.LineAttestation){
		"a source is missing": func(a *lineattest.LineAttestation) { a.Evidence.Sources = a.Evidence.Sources[:2] },
		"an extra source": func(a *lineattest.LineAttestation) {
			a.Evidence.Sources = append(a.Evidence.Sources, constraintengine.SourceEvidence{ID: "changelog-9.9.9"})
		},
		"a source twice": func(a *lineattest.LineAttestation) { a.Evidence.Sources[1] = a.Evidence.Sources[0] },
		"another revision": func(a *lineattest.LineAttestation) {
			a.Evidence.Sources[0].Revision = clCommit(9)
		},
		"a branch url": func(a *lineattest.LineAttestation) {
			a.Evidence.Sources[0].URL = "https://github.com/prometheus/prometheus/blob/main/CHANGELOG.md"
		},
		"another path": func(a *lineattest.LineAttestation) {
			a.Evidence.Sources[0].URL = clRepo.BlobURL(a.Evidence.Sources[0].Revision, "docs/CHANGELOG.md")
		},
		"no content digest": func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].ContentDigest = "" },
		"short digest":      func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].ContentDigest = "sha256:abc" },
		"no span":           func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].StartLine = 0 },
		"inverted span": func(a *lineattest.LineAttestation) {
			a.Evidence.Sources[0].StartLine, a.Evidence.Sources[0].EndLine = 9, 2
		},
		"the first release of the from line cited": func(a *lineattest.LineAttestation) {
			s := a.Evidence.Sources[0]
			s.ID = "changelog-3.4.0"
			a.Evidence.Sources = append([]constraintengine.SourceEvidence{s}, a.Evidence.Sources[1:]...)
		},
		"no releases": func(a *lineattest.LineAttestation) { a.Releases = nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			a := *good.attestation
			a.Evidence.Sources = append([]constraintengine.SourceEvidence(nil), good.attestation.Evidence.Sources...)
			edit(&a)
			requireCLCode(t, w.admit(clRecord(t, a), w.opts), changelogCitation)
		})
	}
}

func TestChangelogCitationsCheck(t *testing.T) {
	w := newCLWorld(t)
	c := w.change(goodRecord(w))
	c.OK, c.Proof = true, ProofRederived
	cls := &Classification{Changes: []*Change{c}}
	// The citations check did not run: not admitted.
	r := &Report{}
	r.changelogCitations(cls)
	requireCLCode(t, c, changelogCitation)
	if len(r.Checks) != 1 || r.Checks[0].OK {
		t.Fatalf("%+v", r.Checks)
	}
	// It ran and did not pass.
	c.OK, c.Detail = true, ""
	r = &Report{}
	r.add(CheckCitations, false, "digest differs")
	r.changelogCitations(cls)
	requireCLCode(t, c, changelogCitation)
	// It passed.
	c.OK, c.Detail = true, ""
	r = &Report{}
	r.add(CheckCitations, true, "ok")
	r.changelogCitations(cls)
	if !c.OK || len(r.Checks) != 2 || !r.Checks[1].OK {
		t.Fatalf("%v %q %+v", c.OK, c.Detail, r.Checks)
	}
}

func TestChangelogFreshness(t *testing.T) {
	w := newCLWorld(t)
	cases := map[string]*record{
		"derived two days ago":      w.derive(clNow.Add(-48*time.Hour), 60*24*time.Hour),
		"derived in the future":     w.derive(clNow.Add(time.Hour), 60*24*time.Hour),
		"lease of 13 days":          w.derive(clNow.Add(-time.Hour), 13*24*time.Hour),
		"valid until exactly 14 days after the clock": w.derive(clNow.Add(-time.Hour), 14*24*time.Hour+time.Hour),
		"valid until 1s short of 14 days":             w.derive(clNow.Add(-time.Hour), 14*24*time.Hour+time.Hour-time.Second),
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			requireCLCode(t, w.admit(rec, w.opts), changelogFreshness)
		})
	}
	// Just over 14 days after the gate's clock is admitted.
	rec := w.derive(clNow.Add(-time.Hour), 14*24*time.Hour+time.Hour+time.Second)
	if c := w.admit(rec, w.opts); !c.OK {
		t.Fatalf("%s", c.Detail)
	}
}

func TestChangelogReleasesIncomplete(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	t.Run("a final tag of the to line is not named", func(t *testing.T) {
		o := w.opts
		s := newCLSource(nil)
		s.tags = append(s.tags, extract.Tag{Name: "v3.5.2", Commit: clCommit(5)})
		o.Source = s
		requireCLCode(t, w.admit(rec, o), changelogReleasesIncomplete)
	})
	t.Run("a final tag of the from line is not named", func(t *testing.T) {
		o := w.opts
		s := newCLSource(nil)
		s.tags = append(s.tags, extract.Tag{Name: "v3.4.2", Commit: clCommit(5)})
		o.Source = s
		requireCLCode(t, w.admit(rec, o), changelogReleasesIncomplete)
	})
	t.Run("a named release is not a tag", func(t *testing.T) {
		o := w.opts
		s := newCLSource(nil)
		s.tags = s.tags[:4]
		o.Source = s
		requireCLCode(t, w.admit(rec, o), changelogReleasesIncomplete)
	})
	t.Run("a release tag at another commit", func(t *testing.T) {
		o := w.opts
		s := newCLSource(nil)
		s.tags[4].Commit = clCommit(7)
		o.Source = s
		requireCLCode(t, w.admit(rec, o), changelogReleasesIncomplete)
	})
	t.Run("a release candidate is not a release", func(t *testing.T) {
		o := w.opts
		s := newCLSource(nil)
		s.tags = append(s.tags, extract.Tag{Name: "v3.5.2-rc.0", Commit: clCommit(5)})
		o.Source = s
		if c := w.admit(rec, o); !c.OK {
			t.Fatal(c.Detail)
		}
	})
}

func TestChangelogMarkProvenance(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	// mod edits the first mark on disk and returns the restore.
	mod := func(f func(m *changelogattest.Mark)) func() {
		t.Helper()
		saved := append([]changelogattest.Mark(nil), w.marks...)
		f(&w.marks[0])
		w.write()
		return func() { w.marks = saved; w.write() }
	}
	t.Run("a model's proposal no person reviewed", func(t *testing.T) {
		defer mod(func(m *changelogattest.Mark) { m.ProposedBy, m.State = changelogattest.ProposedByModel, "proposed" })()
		requireCLCode(t, w.admit(rec, w.opts), changelogMarkProvenance)
	})
	t.Run("a mark that is not reviewed, whoever proposed it", func(t *testing.T) {
		defer mod(func(m *changelogattest.Mark) { m.State = "proposed" })()
		requireCLCode(t, w.admit(rec, w.opts), changelogMarkProvenance)
	})
	t.Run("no state", func(t *testing.T) {
		defer mod(func(m *changelogattest.Mark) { m.State = "" })()
		requireCLCode(t, w.admit(rec, w.opts), changelogMarkProvenance)
	})
	t.Run("unknown proposer", func(t *testing.T) {
		defer mod(func(m *changelogattest.Mark) { m.ProposedBy = "bot" })()
		requireCLCode(t, w.admit(rec, w.opts), changelogMarkProvenance)
	})
	t.Run("no review time", func(t *testing.T) {
		defer mod(func(m *changelogattest.Mark) { m.ReviewedAt = "" })()
		requireCLCode(t, w.admit(rec, w.opts), changelogMarkProvenance)
	})
	t.Run("dated after the gate's clock", func(t *testing.T) {
		defer mod(func(m *changelogattest.Mark) { m.ReviewedAt = "2026-11-18T00:00:00Z" })()
		requireCLCode(t, w.admit(rec, w.opts), changelogMarkProvenance)
	})
	t.Run("the gate's own check, without the loader", func(t *testing.T) {
		d := &changelogattest.Dispositions{Component: clComponent, Marks: []changelogattest.Mark{clMark("v3.5.0", ce.Item{Digest: strings.Repeat("a", 64), Occurrence: 1})}}
		d.Marks[0].ProposedBy, d.Marks[0].State = changelogattest.ProposedByModel, "proposed"
		err := checkMarkProvenance(d, clNow)
		if err == nil || !strings.HasPrefix(err.Error(), "changelog/"+changelogMarkProvenance+": ") {
			t.Fatal(err)
		}
		d.Marks[0].State = changelogattest.StateReviewed
		if err := checkMarkProvenance(d, clNow); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("not json", func(t *testing.T) {
		w.writeRaw([]byte(`{"component":"prometheus","marks":[],"extra":1}`))
		defer w.write()
		requireCLCode(t, w.admit(rec, w.opts), changelogMarkProvenance)
	})
}

func TestChangelogEntryAmended(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	w.src.files[clCommit(4)+":CHANGELOG.md"] = clFileUpTo("3.5.1", map[string]string{"3.5.0": clBodies["3.5.0"] + "* [CHANGE] Added later. #99\n"})
	c := w.admit(rec, w.opts)
	requireCLCode(t, c, changelogEntryAmended)
}

func TestChangelogRederivation(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	t.Run("the record differs from the derivation", func(t *testing.T) {
		a := *rec.attestation
		a.Evidence.Sources = append([]constraintengine.SourceEvidence(nil), rec.attestation.Evidence.Sources...)
		a.Evidence.Sources[1].ContentDigest = "sha256:" + strings.Repeat("e", 64)
		c := w.admit(clRecord(t, a), w.opts)
		requireCLCode(t, c, changelogRederivation)
		if !strings.Contains(c.Detail, "differs") {
			t.Fatal(c.Detail)
		}
	})
	t.Run("a stated rule the pack does not hold", func(t *testing.T) {
		a := *rec.attestation
		a.RuleIDs = []string{"prom.invented"}
		requireCLCode(t, w.admit(clRecord(t, a), w.opts), changelogRederivation)
	})
	t.Run("an item without a reviewed mark", func(t *testing.T) {
		saved := w.marks
		defer func() { w.marks = saved; w.write() }()
		w.marks = w.marks[1:]
		w.write()
		c := w.admit(rec, w.opts)
		requireCLCode(t, c, changelogRederivation)
		if !strings.Contains(c.Detail, string(ce.ItemUnresolved)) {
			t.Fatal(c.Detail)
		}
	})
	t.Run("an edited item loses its mark", func(t *testing.T) {
		o := w.opts
		o.Source = newCLSource(map[string]string{"3.5.1": "* [BUGFIX] Fix a different crash. #51\n"})
		requireCLCode(t, w.admit(rec, o), changelogRederivation)
	})
	t.Run("an edited section moves the evidence", func(t *testing.T) {
		o := w.opts
		o.Source = newCLSource(map[string]string{"3.4.1": clBodies["3.4.1"] + "* [BUGFIX] More. #42\n"})
		requireCLCode(t, w.admit(rec, o), changelogRederivation)
	})
	t.Run("a tag's entry is missing", func(t *testing.T) {
		s := newCLSource(nil)
		delete(s.files, clCommit(3)+":CHANGELOG.md")
		o := w.opts
		o.Source = s
		c := w.admit(rec, o)
		requireCLCode(t, c, changelogRederivation)
		if !strings.Contains(c.Detail, string(ce.PathMissingAtTag)) {
			t.Fatal(c.Detail)
		}
	})
	t.Run("no upstream source", func(t *testing.T) {
		o := w.opts
		o.Source = nil
		requireCLCode(t, w.admit(rec, o), changelogRederivation)
	})
	t.Run("a rule of the line that is not line-wide", func(t *testing.T) {
		head := &loadedPack{Entries: map[string]*entry{}, Records: map[string]*record{}}
		raw := `{"project":"p","rule":{"id":"prom.anchor","operator":"forbid_set_member","subject":{"component":"prometheus","from":"3.4.0","to":"3.5.0"},"evidence":{"state":"active"}}}`
		head.Entries["prom.anchor"] = &entry{RuleID: "prom.anchor", Raw: json.RawMessage(raw)}
		head.Order = []string{"prom.anchor"}
		c := w.change(rec)
		prep, err := changelogPre(c, head, w.opts, true)
		if err != nil {
			t.Fatal(err)
		}
		changelogRederive(context.Background(), c, prep, w.opts)
		requireCLCode(t, c, changelogRederivation)
		if !strings.Contains(c.Detail, string(ce.RuleNotLineWide)) {
			t.Fatal(c.Detail)
		}
	})
}

// A record in force is re-derived by the same code, without the lease and
// freshness conditions of an admission: it is not a loosening.
func TestChangelogUnchangedRecordRederived(t *testing.T) {
	w := newCLWorld(t)
	old := w.derive(clNow.Add(-40*24*time.Hour), 45*24*time.Hour) // 5 days left, derived 40 days ago
	requireCLCode(t, w.admit(old, w.opts), changelogFreshness)

	cls := &Classification{head: map[string]*loadedPack{"p": w.head}}
	w.head.Records = map[string]*record{"rec": old}
	w.head.RecordOrder = []string{"rec"}
	opts := w.opts
	opts.Layout = Layout{Packs: []PackSpec{{Name: "p"}}}
	opts.Catalog = nil // the catalog is never asked
	run := func() *Report {
		r := &Report{}
		r.rederiveAll(context.Background(), cls, nil, opts)
		return r
	}
	r := run()
	if len(r.Checks) != 1 || !r.Checks[0].OK || r.rederivedUnchanged != 1 {
		t.Fatalf("%+v", r.Checks)
	}
	// A byte of a cited section changes upstream: the record in force fails.
	w.src.files[clCommit(3)+":CHANGELOG.md"] = strings.Replace(w.src.files[clCommit(3)+":CHANGELOG.md"], "Add `a`", "Add `z`", 1)
	r = run()
	if len(r.Checks) != 1 || r.Checks[0].OK || !strings.Contains(r.Checks[0].Detail, "changelog/") {
		t.Fatalf("%+v", r.Checks)
	}
}

// A new final tag voids a record in force.
func TestChangelogUnchangedRecordVoidedByNewTag(t *testing.T) {
	w := newCLWorld(t)
	rec := goodRecord(w)
	w.head.Records = map[string]*record{"rec": rec}
	w.head.RecordOrder = []string{"rec"}
	cls := &Classification{head: map[string]*loadedPack{"p": w.head}}
	opts := w.opts
	opts.Layout = Layout{Packs: []PackSpec{{Name: "p"}}}
	w.src.tags = append(w.src.tags, extract.Tag{Name: "v3.5.2", Commit: clCommit(5)})
	r := &Report{}
	r.rederiveAll(context.Background(), cls, nil, opts)
	if r.Checks[0].OK || !strings.Contains(r.Checks[0].Detail, "changelog/"+changelogReleasesIncomplete) {
		t.Fatalf("%+v", r.Checks)
	}
}

// The empty-list admission does not take a changelog record: it is held to
// the changelog admission only, whatever its rule list.
func TestChangelogRecordIsNotAnEmptyListChange(t *testing.T) {
	w := newCLWorld(t)
	c := w.change(goodRecord(w))
	if !isChangelogRecord(c) || isEmptyListChange(c) {
		t.Fatal("a changelog record is routed to the empty-list admission")
	}
	other := w.change(goodRecord(w))
	other.rhead.attestation.FactFamily = lineattest.FamilyCustomResourceVersions
	if isChangelogRecord(other) || !isEmptyListChange(other) {
		t.Fatal("another family is no longer an empty-list change")
	}
	if isChangelogRecord(&Change{}) || isChangelogRecord(nil) {
		t.Fatal("a change without a record is a changelog record")
	}
}
