// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/servedlists"
)

// servedFake is a pinned upstream: the tags of the Kubernetes repository and
// one specification per commit.
type servedFake struct {
	tags     []extract.Tag
	files    map[string][]byte
	tagsErr  error
	readErr  error
	tagReads int
	reads    int
}

func (f *servedFake) Tags(extract.RepoRef) ([]extract.Tag, error) {
	f.tagReads++
	return f.tags, f.tagsErr
}

func (f *servedFake) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	data, ok := f.files[commit]
	if !ok || path != servedlists.SwaggerPath {
		return nil, extract.ErrNotFound
	}
	return data, nil
}

func (f *servedFake) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("no listings")
}

var servedSwaggerFile = filepath.Join("..", "..", "servedlists", "testdata", "swagger.json")

// servedCommit is the commit of the line's tag in the fake upstream.
func servedCommit(line string) string {
	var n int
	fmt.Sscanf(line, "1.%d", &n)
	return strings.Repeat(fmt.Sprintf("%x", n%16), 39) + "a"
}

// newServedFake has the tags v1.26.0 to v1.31.0, each at its own commit, and
// the same synthetic specification at every commit.
func newServedFake(t *testing.T) *servedFake {
	t.Helper()
	data, err := os.ReadFile(servedSwaggerFile)
	if err != nil {
		t.Fatal(err)
	}
	f := &servedFake{files: map[string][]byte{}}
	for minor := 26; minor <= 31; minor++ {
		line := fmt.Sprintf("1.%d", minor)
		f.tags = append(f.tags, extract.Tag{Name: "v" + line + ".0", Commit: servedCommit(line)})
		f.files[servedCommit(line)] = data
	}
	return f
}

var servedStamp = gateNow.Add(-time.Hour)

func servedRecordFor(t *testing.T, src *servedFake, line string) servedapis.Record {
	t.Helper()
	rec, err := servedlists.Build(context.Background(), src, src, line, servedStamp)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// servedChanges are the new-record changes of the lists, read as the gate
// reads a pack's records.
func servedChanges(t *testing.T, recs ...servedapis.Record) []*Change {
	t.Helper()
	sort.Slice(recs, func(i, j int) bool { return recs[i].Line < recs[j].Line })
	section, err := servedapis.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	loaded, order, err := loadRecords([]byte(`{"` + servedapis.PackMember + `":` + string(section) + `}`))
	if err != nil {
		t.Fatal(err)
	}
	var out []*Change
	for _, id := range order {
		r := loaded[id]
		out = append(out, &Change{Pack: "cncf", RuleID: id, Section: sectionServed, Project: r.Project, Class: ClassLoosening, Kinds: []string{KindNew}, Basis: r.Basis, rhead: r})
	}
	return out
}

// decideServed runs what the gate runs for each served-list change: the
// checks that need no upstream, then the re-derivation.
func decideServed(ctx context.Context, src Source, changes []*Change) {
	opts := Options{Now: gateNow, Layout: DefaultLayout()}
	var todo []*Change
	for _, c := range changes {
		if err := servedPre(c, opts); err != nil {
			c.fail(err.Error())
			continue
		}
		todo = append(todo, c)
	}
	rederive(ctx, src, nil, 1, opts.Layout, todo)
}

func TestServedListsAreRederived(t *testing.T) {
	t.Parallel()
	src := newServedFake(t)
	changes := servedChanges(t, servedRecordFor(t, src, "1.30"), servedRecordFor(t, src, "1.31"))
	src.tagReads = 0
	decideServed(context.Background(), src, changes)
	for _, c := range changes {
		if !c.OK || c.Proof != ProofRederived {
			t.Fatalf("%s: ok %v proof %q: %s", c.RuleID, c.OK, c.Proof, c.Detail)
		}
	}
	if src.tagReads != 1 {
		t.Fatalf("the tags were read %d times for two lists", src.tagReads)
	}
}

func TestServedListRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(t *testing.T, src *servedFake, r *servedapis.Record)
		want string
	}{
		{"reviewed basis", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			r.Evidence.Basis, r.Evidence.Extractor, r.Evidence.DerivedAt = constraintengine.BasisReviewed, nil, ""
		}, "is admitted only when the gate re-derives it"},
		{"wrong code digest", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			x := *r.Evidence.Extractor
			x.CodeDigest = "sha256:" + strings.Repeat("0", 64)
			r.Evidence.Extractor = &x
		}, "this gate runs"},
		{"wrong deriver id", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			x := *r.Evidence.Extractor
			x.ID = "k8s.served-api-removal"
			r.Evidence.Extractor = &x
		}, "this gate runs"},
		{"wrong deriver version", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			x := *r.Evidence.Extractor
			x.Version = "1.0.1"
			r.Evidence.Extractor = &x
		}, "this gate runs"},
		{"stale derivedAt", func(t *testing.T, src *servedFake, r *servedapis.Record) {
			old, err := servedlists.Build(context.Background(), src, src, r.Line, gateNow.Add(-48*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			*r = old
		}, "outside [now-24h"},
		{"one pair more", func(t *testing.T, _ *servedFake, r *servedapis.Record) { r.APIs = append(r.APIs, "v1 Zebra") }, "differs from what deriver"},
		{"one pair less", func(t *testing.T, _ *servedFake, r *servedapis.Record) { r.APIs = r.APIs[1:] }, "differs from what deriver"},
		{"complete instead of partial", func(t *testing.T, _ *servedFake, r *servedapis.Record) { r.Completeness = servedapis.Completeness }, "differs from what deriver"},
		{"a removed API", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			r.APIs = append(r.APIs, "extensions/v1beta1 DaemonSet")
			sort.Strings(r.APIs)
		}, "marks as removed"},
		{"another line's tag commit", func(t *testing.T, src *servedFake, r *servedapis.Record) {
			// The 1.31 specification labelled 1.30.
			old, err := servedlists.Assemble("1.30", servedCommit("1.31"), src.files[servedCommit("1.31")], servedStamp, servedStamp.Add(servedlists.Lease))
			if err != nil {
				t.Fatal(err)
			}
			*r = old
		}, "is not the commit"},
		{"digest of other bytes", func(t *testing.T, src *servedFake, r *servedapis.Record) {
			src.files[servedCommit(r.Line)] = append(append([]byte{}, src.files[servedCommit(r.Line)]...), '\n')
		}, "contentDigest"},
		{"two sources", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			second := r.Evidence.Sources[0]
			second.ID = "openapi-v1.30.0b"
			r.Evidence.Sources = append(r.Evidence.Sources, second)
		}, "exactly one source"},
		{"another file", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			r.Evidence.Sources[0].URL = strings.Replace(r.Evidence.Sources[0].URL, "swagger.json", "other.json", 1)
		}, "cited source is not"},
		{"a source id of another line", func(t *testing.T, _ *servedFake, r *servedapis.Record) { r.Evidence.Sources[0].ID = "openapi-v1.31.0" }, "cited source is not"},
		{"lease longer than the deriver's", func(t *testing.T, _ *servedFake, r *servedapis.Record) {
			r.Evidence.ValidUntil = servedStamp.Add(servedlists.Lease + 12*time.Hour).Format(time.RFC3339)
		}, "validUntil"},
		{"no tag of the line", func(t *testing.T, src *servedFake, r *servedapis.Record) {
			var kept []extract.Tag
			for _, tag := range src.tags {
				if tag.Name != "v1.30.0" {
					kept = append(kept, tag)
				}
			}
			src.tags = kept
		}, "no tag v1.30.0"},
		{"tags unreadable", func(t *testing.T, src *servedFake, r *servedapis.Record) { src.tagsErr = errors.New("frozen") }, "tags of"},
		{"specification unreadable", func(t *testing.T, src *servedFake, r *servedapis.Record) { src.readErr = errors.New("rate limited") }, "rate limited"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := newServedFake(t)
			rec := servedRecordFor(t, src, "1.30")
			tc.edit(t, src, &rec)
			changes := servedChanges(t, rec)
			decideServed(context.Background(), src, changes)
			c := changes[0]
			if c.OK || c.Proof != "" || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("ok %v proof %q detail %q, want a refusal with %q", c.OK, c.Proof, c.Detail, tc.want)
			}
		})
	}

	t.Run("no upstream source", func(t *testing.T) {
		t.Parallel()
		changes := servedChanges(t, servedRecordFor(t, newServedFake(t), "1.30"))
		decideServed(context.Background(), nil, changes)
		if changes[0].OK || !strings.Contains(changes[0].Detail, "no upstream source") {
			t.Fatalf("%+v", changes[0])
		}
	})

	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		src := newServedFake(t)
		changes := servedChanges(t, servedRecordFor(t, src, "1.30"))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		src.reads = 0
		decideServed(ctx, src, changes)
		if changes[0].OK || src.reads != 0 {
			t.Fatalf("ok %v after %d reads", changes[0].OK, src.reads)
		}
	})
}

// A run of upstream read failures stops the pass; the rest are failures, not
// passes, and are not read.
func TestServedListsStopAfterRepeatedUpstreamFailures(t *testing.T) {
	t.Parallel()
	src := newServedFake(t)
	var recs []servedapis.Record
	for minor := 26; minor <= 31; minor++ {
		recs = append(recs, servedRecordFor(t, src, fmt.Sprintf("1.%d", minor)))
	}
	changes := servedChanges(t, recs...)
	src.readErr = errors.New("unavailable")
	src.reads = 0
	decideServed(context.Background(), src, changes)
	for _, c := range changes {
		if c.OK {
			t.Fatalf("%s passed with the upstream down", c.RuleID)
		}
	}
	if src.reads != maxServedUpstreamFailures {
		t.Fatalf("%d reads, want %d", src.reads, maxServedUpstreamFailures)
	}
	if !strings.Contains(changes[len(changes)-1].Detail, "not attempted") {
		t.Fatalf("last: %q", changes[len(changes)-1].Detail)
	}
}

func servedPack(t *testing.T, recs ...servedapis.Record) *loadedPack {
	t.Helper()
	sort.Slice(recs, func(i, j int) bool { return recs[i].Line < recs[j].Line })
	section, err := servedapis.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"` + servedapis.PackMember + `":` + string(section) + `}`)
	records, order, err := loadRecords(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &loadedPack{Spec: PackSpec{Name: "cncf", Records: true}, Present: true, Raw: raw, Members: map[string]json.RawMessage{servedapis.PackMember: section}, Records: records, RecordOrder: order}
}

func TestServedListChangeClasses(t *testing.T) {
	t.Parallel()
	src := newServedFake(t)
	rec := servedRecordFor(t, src, "1.31")
	with := servedPack(t, rec)
	without := &loadedPack{Spec: PackSpec{Name: "cncf", Records: true}, Present: true, Members: map[string]json.RawMessage{}, Records: map[string]*record{}}

	one := func(base, head *loadedPack) *Change {
		t.Helper()
		changes := diffRecords(base, head, sectionServed)
		if len(changes) != 1 {
			t.Fatalf("%d changes", len(changes))
		}
		return changes[0]
	}
	if c := one(with, without); c.Class != ClassTightening || len(c.Kinds) != 1 || c.Kinds[0] != KindRemove || !withdrawsRecord(c) {
		t.Fatalf("removal: %+v", c)
	}
	if c := one(without, with); c.Class != ClassLoosening || c.Kinds[0] != KindNew {
		t.Fatalf("new: %+v", c)
	}
	earlier := rec
	earlier.Evidence.ValidUntil = servedStamp.Add(30 * 24 * time.Hour).Format(time.RFC3339)
	if c := one(with, servedPack(t, earlier)); c.Class != ClassTightening {
		t.Fatalf("an earlier validUntil: %+v", c)
	}
	renewed, err := servedlists.Build(context.Background(), src, src, "1.31", servedStamp.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c := one(with, servedPack(t, renewed)); c.Class != ClassLoosening {
		t.Fatalf("a renewal: %+v", c)
	}
	edited := rec
	edited.APIs = append(append([]string{}, rec.APIs...), "v1 Zebra")
	if c := one(with, servedPack(t, edited)); c.Class != ClassLoosening {
		t.Fatalf("a changed list: %+v", c)
	}
	if !recordSection(PackSpec{Records: true}, sectionServed) || recordSection(PackSpec{}, sectionServed) {
		t.Fatal("servedAPIs is a record section of a pack with records only")
	}
}

// rederive-all re-derives a served list the change leaves alone.
func TestServedListRederiveAllCatchesATamperedUnchangedList(t *testing.T) {
	t.Parallel()
	src := newServedFake(t)
	layout := DefaultLayout()
	run := func(recs ...servedapis.Record) (*Report, Check) {
		cls := &Classification{head: map[string]*loadedPack{}}
		for _, spec := range layout.Packs {
			cls.head[spec.Name] = &loadedPack{Spec: spec, Present: true}
		}
		cls.head["cncf"] = servedPack(t, recs...)
		cls.head["cncf"].Spec = layout.Packs[0]
		r := &Report{}
		r.rederiveAll(context.Background(), cls, nil, Options{Layout: layout, Source: src, Now: gateNow})
		c, ok := check(r, "rederive-all")
		if !ok {
			t.Fatal("no rederive-all check")
		}
		return r, c
	}
	if layout.Packs[0].Name != "cncf" {
		t.Fatalf("the first pack is %s", layout.Packs[0].Name)
	}
	good := servedRecordFor(t, src, "1.31")
	if _, c := run(good); !c.OK || !strings.Contains(c.Detail, "1 of them served-API lists") {
		t.Fatalf("an untouched list: %+v", c)
	}
	tampered := good
	tampered.APIs = append(append([]string{}, good.APIs...), "v1 Zebra")
	r, c := run(tampered)
	if c.OK || !strings.Contains(c.Detail, "differs from what deriver") || r.rederivedUnchanged != 1 {
		t.Fatalf("a tampered unchanged list: %+v (%d re-derived)", c, r.rederivedUnchanged)
	}
	// The list's age does not matter to an unchanged list.
	old, err := servedlists.Build(context.Background(), src, src, "1.31", gateNow.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, c := run(old); !c.OK {
		t.Fatalf("an old unchanged list: %+v", c)
	}
}

// signServedIntroduction signs the approval of the introduction between base
// and head packs.
func signServedIntroduction(t *testing.T, key testApprovalKey, base, head *loadedPack) []byte {
	t.Helper()
	_, statement, err := servedIntroductionStatement(base, head)
	if err != nil {
		t.Fatal(err)
	}
	subject := ApprovalSubject{Kind: ApprovalSubjectServed, Pack: "cncf", RuleID: ServedApprovalID, Scope: ServedApprovalScope, Candidate: statement}
	raw, _, err := SignApproval(SignApprovalOptions{Subject: subject, CandidateID: "cand-1", Identity: "airstand", Keys: servedKeys(key), Key: key.private, Now: servedStamp})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func servedKeys(key testApprovalKey) ApprovalKeys {
	return ApprovalKeys{
		Schema: ApprovalKeysSchema, Role: ApprovalKeyRole, Owners: []string{"airstand"},
		Keys: []ApprovalKey{{KeyID: ApprovalKeyID(key.public), PublicKey: hex.EncodeToString(key.public), NotAfter: "2027-10-01T00:00:00Z"}},
	}
}

func TestServedIntroductionNeedsAnOwnerApproval(t *testing.T) {
	t.Parallel()
	src := newServedFake(t)
	key := newApprovalKey(t)
	keys := servedKeys(key)
	loadKeys := func() (*ApprovalKeys, error) { return &keys, nil }
	layout := DefaultLayout()
	basePack := func() *loadedPack {
		return &loadedPack{Spec: layout.Packs[0], Present: true, Raw: []byte(`{"base":1}`), Members: map[string]json.RawMessage{}}
	}
	headPack := func(lines ...string) *loadedPack {
		var recs []servedapis.Record
		for _, l := range lines {
			recs = append(recs, servedRecordFor(t, src, l))
		}
		p := servedPack(t, recs...)
		p.Spec = layout.Packs[0]
		return p
	}
	type scene struct {
		cls     *Classification
		opts    Options
		changes []*Change
		head    *loadedPack
	}
	setup := func(t *testing.T, base *loadedPack, head *loadedPack) scene {
		t.Helper()
		cls := &Classification{base: map[string]*loadedPack{"cncf": base}, head: map[string]*loadedPack{"cncf": head}}
		var recs []servedapis.Record
		for _, id := range head.RecordOrder {
			recs = append(recs, *head.Records[id].served)
		}
		changes := servedChanges(t, recs...)
		for _, c := range changes {
			c.OK, c.Proof = true, ProofRederived
		}
		cls.Changes = changes
		return scene{cls: cls, changes: changes, head: head, opts: Options{Layout: layout, Now: gateNow, Base: Tree{Root: t.TempDir()}, Head: Tree{Root: t.TempDir()}}}
	}
	approve := func(s scene, raw []byte) {
		writeFile(t, filepath.Join(s.opts.Head.Root, filepath.FromSlash(servedApprovalPath(layout, "cncf"))), raw)
	}
	decide := func(s scene) map[string]bool {
		return admitServedIntroduction(s.cls, s.opts, loadKeys, &baseApprovals{opts: s.opts})
	}
	refused := func(t *testing.T, s scene, got map[string]bool, want string) {
		t.Helper()
		if got["cncf"] {
			t.Fatal("the introduction was admitted")
		}
		for _, c := range s.changes {
			if c.OK || !strings.Contains(c.Detail, want) {
				t.Fatalf("%s: ok %v detail %q, want %q", c.RuleID, c.OK, c.Detail, want)
			}
		}
	}

	t.Run("without an approval", func(t *testing.T) {
		s := setup(t, basePack(), headPack("1.30", "1.31"))
		refused(t, s, decide(s), "no owner approval")
	})
	t.Run("with a valid approval", func(t *testing.T) {
		base, head := basePack(), headPack("1.30", "1.31")
		s := setup(t, base, head)
		approve(s, signServedIntroduction(t, key, base, head))
		got := decide(s)
		if !got["cncf"] {
			t.Fatalf("refused: %+v", s.changes[0])
		}
		for _, c := range s.changes {
			if !c.OK || c.Proof != ProofRederived {
				t.Fatalf("%s: %+v", c.RuleID, c)
			}
		}
	})
	t.Run("an approval over other list bytes", func(t *testing.T) {
		base := basePack()
		s := setup(t, base, headPack("1.30", "1.31"))
		approve(s, signServedIntroduction(t, key, base, headPack("1.30")))
		refused(t, s, decide(s), "candidate digest")
	})
	t.Run("an approval over the same lists in another pack", func(t *testing.T) {
		base, head := basePack(), headPack("1.30", "1.31")
		s := setup(t, base, head)
		approve(s, signServedIntroduction(t, key, base, head))
		s.cls.base["cncf"] = &loadedPack{Spec: layout.Packs[0], Present: true, Raw: []byte(`{"base":2}`), Members: map[string]json.RawMessage{}}
		refused(t, s, decide(s), "candidate digest")
	})
	t.Run("an approval of another key", func(t *testing.T) {
		base, head := basePack(), headPack("1.30")
		s := setup(t, base, head)
		other := newApprovalKey(t)
		_, statement, _ := servedIntroductionStatement(base, head)
		raw, _, err := SignApproval(SignApprovalOptions{Subject: ApprovalSubject{Kind: ApprovalSubjectServed, Pack: "cncf", RuleID: ServedApprovalID, Scope: ServedApprovalScope, Candidate: statement}, CandidateID: "c", Identity: "airstand", Keys: servedKeys(other), Key: other.private, Now: servedStamp})
		if err != nil {
			t.Fatal(err)
		}
		approve(s, raw)
		refused(t, s, decide(s), "not pinned")
	})
	t.Run("an approval the base already holds", func(t *testing.T) {
		base, head := basePack(), headPack("1.31")
		s := setup(t, base, head)
		raw := signServedIntroduction(t, key, base, head)
		approve(s, raw)
		writeFile(t, filepath.Join(s.opts.Base.Root, filepath.FromSlash(servedApprovalPath(layout, "cncf"))), raw)
		refused(t, s, decide(s), "already in the base")
	})
	t.Run("a list that is not re-derived leaves its own reason", func(t *testing.T) {
		base, head := basePack(), headPack("1.30", "1.31")
		s := setup(t, base, head)
		approve(s, signServedIntroduction(t, key, base, head))
		s.changes[0].fail("re-derivation failed: nothing")
		if got := decide(s); got["cncf"] || s.changes[0].Detail != "re-derivation failed: nothing" {
			t.Fatalf("%v %q", got, s.changes[0].Detail)
		}
	})
	t.Run("a pack added together with the member", func(t *testing.T) {
		absent := &loadedPack{Spec: layout.Packs[0], Members: map[string]json.RawMessage{}}
		head := headPack("1.30", "1.31")
		s := setup(t, absent, head)
		approve(s, signServedIntroduction(t, key, basePack(), head))
		refused(t, s, decide(s), "may not be introduced together with the pack")
	})
	t.Run("a later change needs none", func(t *testing.T) {
		base := headPack("1.30")
		head := headPack("1.30", "1.31")
		s := setup(t, base, head)
		if got := decide(s); len(got) != 0 {
			t.Fatalf("decided %v", got)
		}
		for _, c := range s.changes {
			if !c.OK {
				t.Fatalf("%s: %q", c.RuleID, c.Detail)
			}
		}
	})
}

func TestServedApprovalIsWiredIntoTheApprovalCommands(t *testing.T) {
	t.Parallel()
	rec := ApprovalRecord{
		BaseDigest: ApprovalBaseAbsent, CandidateDigest: "sha256:" + strings.Repeat("a", 64), CandidateID: "c", DecidedAt: "2026-10-03T00:00:00Z",
		Decision: ApprovalDecisionApprove, Identity: "airstand", Pack: "cncf", RuleID: ServedApprovalID, Subject: ApprovalSubjectServed, Scope: ServedApprovalScope,
	}
	if _, err := SignedApprovalBytes(rec); err != nil {
		t.Fatalf("a servedAPIs approval record: %v", err)
	}
	for name, edit := range map[string]func(*ApprovalRecord){
		"a base digest":   func(r *ApprovalRecord) { r.BaseDigest = "sha256:" + strings.Repeat("b", 64) },
		"another scope":   func(r *ApprovalRecord) { r.Scope = "registryDigest" },
		"another rule id": func(r *ApprovalRecord) { r.RuleID = "member.registryDigest" },
	} {
		bad := rec
		edit(&bad)
		if _, err := SignedApprovalBytes(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// servedHeadTree puts the lists of the given lines into the head pack, at the
// schema level they need. The files derived from the pack are not regenerated:
// the support inventory does not list served-API lists yet, so those checks
// are not the subject here.
func servedHeadTree(t *testing.T, head Tree, src *servedFake, lines ...string) {
	t.Helper()
	var recs []servedapis.Record
	for _, l := range lines {
		recs = append(recs, servedRecordFor(t, src, l))
	}
	section, err := servedapis.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	p := readPack(t, head, cncfRulesPath)
	p.fields[servedapis.PackMember] = json.RawMessage(section)
	p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha10"`)
	p.write(t, head, cncfRulesPath)
}

// The whole route: the owner signs the introduction with the approval
// command, the gate admits the re-derived lists with it, refuses without it,
// and a later list needs no approval.
func TestGateAndCommandServedIntroduction(t *testing.T) {
	t.Parallel()
	src := newServedFake(t)
	key := newApprovalKey(t)
	base, head := trees(t)
	key.pinBoth(t, base, head, "airstand")
	servedHeadTree(t, head, src, "1.30", "1.31")
	gate := func(base, head Tree) *Report {
		return runGate(t, Options{Base: base, Head: head, Source: src})
	}

	t.Run("without an approval", func(t *testing.T) {
		r := gate(base, head)
		requireFail(t, r, "no owner approval")
		if r.Passed() {
			t.Fatal("passed")
		}
	})

	keys := filepath.Join(base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
	keysRaw, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	subject := []string{"--subject", "servedAPIs", "--pack", "cncf", "--base-root", base.Root, "--head-root", head.Root, "--keys", keys, "--keys-digest", pinnedDigest(keysRaw)}
	out := filepath.Join(head.Root, filepath.FromSlash(servedApprovalPath(DefaultLayout(), "cncf")))
	r := runApproval(t, nil, signNow, append(append([]string{"sign"}, subject...), "--identity", "airstand", "--candidate-id", "cand-1", "--key", key.keyFile(t, 0o600), "--output", out)...)
	if r.code != 0 || !strings.Contains(r.stdout, "served-API lists introduction cncf/"+ServedApprovalID) {
		t.Fatalf("sign: %d %s %s", r.code, r.stdout, r.stderr)
	}
	r = runApproval(t, nil, signNow, append(append([]string{"verify"}, subject...), "--approval", out)...)
	if r.code != 0 || !strings.HasPrefix(r.stdout, "approval OK") {
		t.Fatalf("verify: %d %s %s", r.code, r.stdout, r.stderr)
	}

	t.Run("with the approval", func(t *testing.T) {
		report := gate(base, head)
		lists := requireServedAdmitted(t, report)
		if lists != 2 || report.AutoMerge.Eligible {
			t.Fatalf("%d lists, auto-merge eligible %v", lists, report.AutoMerge.Eligible)
		}
	})

	t.Run("one more list in the head than the approval names", func(t *testing.T) {
		more := copyTree(t, head)
		servedHeadTree(t, more, src, "1.29", "1.30", "1.31")
		writeFile(t, filepath.Join(more.Root, filepath.FromSlash(servedApprovalPath(DefaultLayout(), "cncf"))), mustRead(t, out))
		requireFail(t, gate(base, more), "candidate digest")
	})

	t.Run("a list whose bytes the upstream does not give", func(t *testing.T) {
		other := newServedFake(t)
		other.files[servedCommit("1.31")] = append(append([]byte{}, other.files[servedCommit("1.31")]...), '\n')
		requireFail(t, runGate(t, Options{Base: base, Head: head, Source: other}), "contentDigest")
	})

	t.Run("a later list needs no approval", func(t *testing.T) {
		// The merged change is the new base; one more list arrives alone.
		merged := copyTree(t, head)
		key.pin(t, merged, "airstand")
		next := copyTree(t, merged)
		servedHeadTree(t, next, src, "1.29", "1.30", "1.31")
		report := runGate(t, Options{Base: merged, Head: next, Source: src})
		if n := requireServedAdmitted(t, report); n != 1 {
			t.Fatalf("%d lists", n)
		}
	})
}

// requireServedAdmitted requires every change of the report, the lists and
// the schema level move with them, to be admitted and the record-file check
// to hold, and returns the number of lists.
func requireServedAdmitted(t *testing.T, r *Report) int {
	t.Helper()
	lists := 0
	for _, c := range r.Changes {
		if !c.OK {
			t.Fatalf("%s %s %s not admitted: %s", c.Pack, c.Section, c.RuleID, c.Detail)
		}
		if c.Section == sectionServed {
			lists++
			if c.Proof != ProofRederived {
				t.Fatalf("%s: proof %q", c.RuleID, c.Proof)
			}
		}
	}
	if c, ok := check(r, "knowledge-records"); !ok || !c.OK {
		t.Fatalf("knowledge-records: %+v", c)
	}
	return lists
}
