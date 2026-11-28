// SPDX-License-Identifier: AGPL-3.0-only

package changelogrenew

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

const (
	testID    = "changelog.listed.prometheus"
	testOldAt = "2026-11-01T00:00:00Z"
	testAt    = "2026-12-01T00:00:00Z"
	testUntil = "2027-02-19T00:00:00Z"
	testOld   = 40
	testLease = 80
)

var testNow = time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC)

// upstream is a synthetic Prometheus repository: one changelog file at each
// release tag, newest entry first.
type upstream struct{ versions []string }

func commitOf(version string) string {
	return strings.Repeat("0", 34) + fmt.Sprintf("%06s", strings.ReplaceAll(version, ".", "0"))
}

func (u upstream) Tags(extract.RepoRef) ([]extract.Tag, error) {
	var out []extract.Tag
	for _, v := range u.versions {
		out = append(out, extract.Tag{Name: "v" + v, Commit: commitOf(v)})
	}
	return out, nil
}

func (u upstream) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) { return nil, nil }

func (u upstream) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Changelog\n\n## main / unreleased\n\n")
	on := false
	for i := len(u.versions) - 1; i >= 0; i-- {
		v := u.versions[i]
		on = on || commitOf(v) == commit
		if on {
			fmt.Fprintf(&b, "## %s / 2025-01-01\n\n* [BUGFIX] Fix %s. #1\n\n", v, v)
		}
	}
	if !on || path != "CHANGELOG.md" {
		return nil, extract.ErrNotFound
	}
	return []byte(b.String()), nil
}

var baseVersions = []string{"3.3.0", "3.4.0", "3.4.1", "3.5.0", "3.5.1"}

func testRepo(t *testing.T) extract.RepoRef {
	t.Helper()
	repo, err := extract.ParseRepo(extractcli.Catalog()[testID].Repo)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func derive(t *testing.T, u upstream, at string, days int) *extract.Output {
	t.Helper()
	when, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatal(err)
	}
	out, err := extract.Run(context.Background(), extractcli.Catalog()[testID].New(1), u, u,
		extract.Options{Repo: testRepo(t), DerivedAt: when, Lease: time.Duration(days) * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Attestations) == 0 {
		t.Fatal("the run attests nothing")
	}
	return out
}

func runFiles(t *testing.T, out *extract.Output) map[string][]byte {
	t.Helper()
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func writeRun(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func packOf(t *testing.T, atts []lineattest.LineAttestation) []byte {
	t.Helper()
	raw, err := lineattest.Marshal(atts)
	if err != nil {
		t.Fatal(err)
	}
	p := &extractpack.Pack{Members: map[string]json.RawMessage{"schema": json.RawMessage(`"synthetic"`), lineattest.PackMember: raw}}
	out, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// fixture is a base pack derived at testOldAt, with the lines 3.4 and 3.5, and
// one good run at testAt.
type fixture struct {
	base  []lineattest.LineAttestation
	files map[string][]byte
	opts  Options
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	u := upstream{baseVersions}
	base := derive(t, u, testOldAt, testOld).Attestations
	if len(base) != 2 || base[0].Line != "3.4" || base[1].Line != "3.5" {
		t.Fatalf("fixture lines %+v", base)
	}
	files := runFiles(t, derive(t, u, testAt, testLease))
	current, err := Current(extractcli.Catalog()[testID].New(1))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{base: base, files: files, opts: Options{Pack: packOf(t, base), Extractor: testID, Repo: testRepo(t), Current: current,
		RunDir: writeRun(t, files), SecondRunDir: writeRun(t, files), DerivedAt: testAt, LeaseDays: testLease, Max: MaxRecords, Now: testNow}}
}

// key is the key of the base record i.
func (f *fixture) key(i int) string { return f.base[i].Key().String() }

// repack writes the edited base records back to the pack.
func (f *fixture) repack(t *testing.T) { f.opts.Pack = packOf(t, f.base) }

// both replaces both runs by files.
func (f *fixture) both(t *testing.T, files map[string][]byte) {
	f.opts.RunDir, f.opts.SecondRunDir = writeRun(t, files), writeRun(t, files)
}

// repin rewrites the manifest after edit changed it or a file, so that every
// file is pinned again.
func repin(t *testing.T, files map[string][]byte, edit func(m map[string]any, outputs map[string]any)) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for k, v := range files {
		out[k] = v
	}
	var m map[string]any
	if err := json.Unmarshal(out[extract.FileManifest], &m); err != nil {
		t.Fatal(err)
	}
	outputs := m["outputs"].(map[string]any)
	for name, data := range out {
		if name != extract.FileManifest {
			outputs[name] = sum(data)
		}
	}
	if edit != nil {
		edit(m, outputs)
	}
	raw, err := extract.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	out[extract.FileManifest] = raw
	return out
}

// editAttestations changes the run's attestations and pins them again.
func editAttestations(t *testing.T, files map[string][]byte, edit func(a []map[string]any)) map[string][]byte {
	t.Helper()
	var list []map[string]any
	dec := json.NewDecoder(bytes.NewReader(files[extract.FileAttestations]))
	dec.UseNumber()
	if err := dec.Decode(&list); err != nil {
		t.Fatal(err)
	}
	edit(list)
	raw, err := extract.Canonical(list)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for k, v := range files {
		out[k] = v
	}
	out[extract.FileAttestations] = raw
	return repin(t, out, nil)
}

func firstSource(a map[string]any) map[string]any {
	return a["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)
}

// refusal is the exact text of a refusal.
func refusal(code, detail string) string { return "changelog-renewal/" + code + ": " + detail }

// requireRefusal requires Assemble to return no result and exactly want.
func requireRefusal(t *testing.T, opts Options, want string) {
	t.Helper()
	res, err := Assemble(opts)
	if res != nil {
		t.Fatalf("a refusal returned a result %+v", res)
	}
	if err == nil || err.Error() != want {
		t.Fatalf("error %q\nwant  %q", fmt.Sprint(err), want)
	}
}

func parsedSection(t *testing.T, raw []byte) []lineattest.LineAttestation {
	t.Helper()
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	list, err := section(p)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// changedMembers lists the member names of the lines that differ.
func changedMembers(t *testing.T, base, head []byte) map[string]int {
	t.Helper()
	before, after := strings.Split(string(base), "\n"), strings.Split(string(head), "\n")
	if len(before) != len(after) {
		t.Fatalf("%d lines became %d", len(before), len(after))
	}
	out := map[string]int{}
	for i := range before {
		if before[i] != after[i] {
			name, _, _ := strings.Cut(strings.TrimSpace(after[i]), ":")
			out[strings.Trim(name, `"`)]++
		}
	}
	return out
}

func TestAssembleMovesOnlyTheTimes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	res, err := Assemble(f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renewed) != 2 || len(res.ListChanged)+len(res.NotDerived)+len(res.Deferred)+res.LeftOut+len(res.Previous) != 0 {
		t.Fatalf("result %+v", res)
	}
	got := changedMembers(t, f.opts.Pack, res.Pack)
	if len(got) != 3 || got["derivedAt"] != 2 || got["reviewedAt"] != 2 || got["validUntil"] != 2 {
		t.Fatalf("changed members %v", got)
	}
	for _, a := range parsedSection(t, res.Pack) {
		if a.Evidence.DerivedAt != testAt || a.Evidence.ReviewedAt != testAt || a.Evidence.ValidUntil != testUntil {
			t.Fatalf("%s: %+v", a.Key(), a.Evidence)
		}
	}
}

func TestAssembleRefuses(t *testing.T) {
	t.Parallel()
	changed := "the record differs in more than evidence.derivedAt, reviewedAt and validUntil"
	for name, edit := range map[string]func(t *testing.T, f *fixture) string{
		// Run mismatch.
		"second run differs by one byte": func(t *testing.T, f *fixture) string {
			f.opts.SecondRunDir = writeRun(t, editAttestations(t, f.files, func(a []map[string]any) { firstSource(a[0])["endLine"] = 2 }))
			return refusal(CodeRunMismatch, "the two runs differ in "+extract.FileAttestations)
		},
		"second run holds one more file": func(t *testing.T, f *fixture) string {
			if err := os.WriteFile(filepath.Join(f.opts.SecondRunDir, "extra"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			return refusal(CodeRunMismatch, "the two runs do not hold the same files")
		},
		"second run lacks a file": func(t *testing.T, f *fixture) string {
			if err := os.Remove(filepath.Join(f.opts.SecondRunDir, extract.FileVectors)); err != nil {
				t.Fatal(err)
			}
			return refusal(CodeRunMismatch, "the two runs do not hold the same files")
		},
		"one directory twice": func(_ *testing.T, f *fixture) string {
			f.opts.SecondRunDir = f.opts.RunDir
			return refusal(CodeRunMismatch, "the two run directories are one directory")
		},
		"second run missing": func(_ *testing.T, f *fixture) string {
			f.opts.SecondRunDir += "-none"
			return refusal(CodeRun, "both run directories must exist")
		},
		"run directory is a symlink": func(t *testing.T, f *fixture) string {
			link := filepath.Join(t.TempDir(), "run")
			if err := os.Symlink(f.opts.RunDir, link); err != nil {
				t.Fatal(err)
			}
			f.opts.RunDir = link
			return refusal(CodeRun, link+" is not a directory")
		},
		"symlink in a run": func(t *testing.T, f *fixture) string {
			link := filepath.Join(f.opts.RunDir, "link")
			if err := os.Symlink(extract.FileVectors, link); err != nil {
				t.Fatal(err)
			}
			return refusal(CodeRun, link+" is not a plain run file within the limits")
		},
		// Unpinned files.
		"file the manifest does not list": func(t *testing.T, f *fixture) string {
			files := repin(t, f.files, nil)
			files["extra.json"] = []byte("{}")
			f.both(t, files)
			return refusal(CodeUnpinned, "run file extra.json is not pinned by the manifest")
		},
		"file differs from its pin": func(t *testing.T, f *fixture) string {
			files := repin(t, f.files, nil)
			files[extract.FileVectors] = []byte("[] ")
			f.both(t, files)
			return refusal(CodeUnpinned, "run file "+extract.FileVectors+" is not pinned by the manifest")
		},
		"pinned file absent": func(t *testing.T, f *fixture) string {
			f.both(t, repin(t, f.files, func(_, outputs map[string]any) { outputs["reads/none.tsv"] = sum(nil) }))
			return refusal(CodeUnpinned, "run file reads/none.tsv, which the manifest pins, is missing")
		},
		"cited file never read": func(t *testing.T, f *fixture) string {
			files := map[string][]byte{}
			for name, data := range f.files {
				if !strings.HasPrefix(name, extract.DirReads+"/") {
					files[name] = data
				}
			}
			f.both(t, repin(t, files, func(_, outputs map[string]any) {
				for name := range outputs {
					if strings.HasPrefix(name, extract.DirReads+"/") {
						delete(outputs, name)
					}
				}
			}))
			return refusal(CodeUnpinned, f.key(0)+": the runs did not read source "+f.base[0].Evidence.Sources[0].ID+" with the cited content")
		},
		"cited content never read": func(t *testing.T, f *fixture) string {
			f.both(t, editAttestations(t, f.files, func(a []map[string]any) { firstSource(a[0])["contentDigest"] = sum([]byte("other")) }))
			return refusal(CodeUnpinned, f.key(0)+": the runs did not read source "+f.base[0].Evidence.Sources[0].ID+" with the cited content")
		},
		"source at another commit than its release": func(t *testing.T, f *fixture) string {
			f.both(t, editAttestations(t, f.files, func(a []map[string]any) {
				s := firstSource(a[0])
				other := commitOf("9.9.9")
				s["url"] = strings.ReplaceAll(s["url"].(string), s["revision"].(string), other)
				s["revision"] = other
			}))
			version := strings.TrimPrefix(f.base[0].Evidence.Sources[0].ID, "changelog-")
			return refusal(CodeUnpinned, f.key(0)+": release "+version+" has no source at its own commit")
		},
		"base source of another repository": func(t *testing.T, f *fixture) string {
			s := &f.base[0].Evidence.Sources[0]
			s.URL = strings.Replace(s.URL, "prometheus/prometheus", "someone/fork", 1)
			f.repack(t)
			return refusal(CodeUnpinned, f.key(0)+": source "+s.ID+" is not a file of "+f.opts.Repo.Key+" at its revision")
		},
		// Changed list or range.
		"changed range": func(t *testing.T, f *fixture) string {
			f.base[0].Evidence.Sources[0].EndLine++
			f.repack(t)
			return f.key(0) + ": " + refusal(CodeChanged, changed)
		},
		"changed cited file": func(t *testing.T, f *fixture) string {
			f.base[0].Evidence.Sources[0].URL += ".old"
			f.repack(t)
			return f.key(0) + ": " + refusal(CodeChanged, changed)
		},
		"base names a release the runs do not": func(t *testing.T, f *fixture) string {
			f.base[0].Releases.To = append(f.base[0].Releases.To, lineattest.Release{Version: f.base[0].Line + ".7", Commit: commitOf("7.7.7")})
			f.repack(t)
			return refusal(CodeUnpinned, f.key(0)+": there is not exactly one source per release of the line")
		},
		"base from-release at another commit": func(t *testing.T, f *fixture) string {
			f.base[0].Releases.From[0].Commit = commitOf("8.8.8")
			f.repack(t)
			return f.key(0) + ": " + refusal(CodeChanged, changed)
		},
		// Other extractor.
		"another extractor asked for": func(_ *testing.T, f *fixture) string {
			f.opts.Extractor = "changelog.listed.fluentd"
			return refusal(CodeOtherExtractor, "the run is of extractor "+testID+" on "+f.opts.Repo.Key)
		},
		"another family of extractor": func(_ *testing.T, f *fixture) string {
			f.opts.Extractor = "crd.version-removal.prometheus"
			return refusal(CodeOtherExtractor, "only a changelog.listed.<project> extractor is renewed here")
		},
		"prefix only": func(_ *testing.T, f *fixture) string {
			f.opts.Extractor = ListedIDPrefix
			return refusal(CodeOtherExtractor, "only a changelog.listed.<project> extractor is renewed here")
		},
		"another repository": func(_ *testing.T, f *fixture) string {
			f.opts.Repo.Key = "github.com/someone/fork"
			return refusal(CodeOtherExtractor, "the run is of extractor "+testID+" on github.com/prometheus/prometheus")
		},
		"a record of another build inside the run": func(t *testing.T, f *fixture) string {
			f.both(t, editAttestations(t, f.files, func(a []map[string]any) {
				a[0]["evidence"].(map[string]any)["extractor"].(map[string]any)["version"] = "9.0.0"
			}))
			return refusal(CodeOtherExtractor, f.key(0)+" is not a listed record of the run's extractor")
		},
		// Lease.
		"lease member in a run record": func(t *testing.T, f *fixture) string {
			files := editAttestations(t, f.files, func(a []map[string]any) { a[0]["evidence"].(map[string]any)["lease"] = "pinned" })
			f.both(t, files)
			_, err := lineattest.Parse(files[extract.FileAttestations])
			if err == nil {
				t.Fatal("a lease member was read")
			}
			return refusal(CodeRun, "attestations: "+err.Error())
		},
		"lease member in the base": func(t *testing.T, f *fixture) string {
			f.opts.Pack = bytes.Replace(f.opts.Pack, []byte(`"basis": "mechanical",`), []byte("\"basis\": \"mechanical\",\n        \"lease\": \"pinned\","), 1)
			p, err := extractpack.ParsePack(f.opts.Pack)
			if err == nil {
				_, err = section(p)
			}
			if err == nil || !strings.Contains(err.Error(), "lease") {
				t.Fatalf("the edit added no refused lease member: %v", err)
			}
			return refusal(CodeInput, "the base pack: "+err.Error())
		},
		"lease of 91 days": func(_ *testing.T, f *fixture) string {
			f.opts.LeaseDays = 91
			return refusal(CodeLease, "the lease must be 1-90 days")
		},
		"lease of 0 days": func(_ *testing.T, f *fixture) string {
			f.opts.LeaseDays = 0
			return refusal(CodeLease, "the lease must be 1-90 days")
		},
		"run lease over 90 days": func(t *testing.T, f *fixture) string {
			f.both(t, repin(t, f.files, func(m, _ map[string]any) { m["validUntil"] = "2027-06-01T00:00:00Z" }))
			return refusal(CodeLease, "the run's lease ends 2027-06-01T00:00:00Z, not "+testUntil)
		},
		"run lease is not the requested one": func(_ *testing.T, f *fixture) string {
			f.opts.LeaseDays = testLease - 1
			return refusal(CodeLease, "the run's lease ends "+testUntil+", not 2027-02-18T00:00:00Z")
		},
		"end not later than before": func(t *testing.T, f *fixture) string {
			f.both(t, runFiles(t, derive(t, upstream{baseVersions}, testAt, 5)))
			f.opts.LeaseDays = 5
			return f.key(0) + ": " + refusal(CodeLease, "validUntil is not later than the base one")
		},
		// Derivation time.
		"future T": func(_ *testing.T, f *fixture) string {
			f.opts.Now = testNow.Add(-2 * time.Hour)
			return refusal(CodeDerivationTime, "the derivation time "+testAt+" is in the future")
		},
		"old T": func(_ *testing.T, f *fixture) string {
			f.opts.Now = testNow.Add(24 * time.Hour)
			return refusal(CodeDerivationTime, "the derivation time "+testAt+" is more than 24 hours old")
		},
		"no clock": func(_ *testing.T, f *fixture) string {
			f.opts.Now = time.Time{}
			return refusal(CodeDerivationTime, "the derivation time "+testAt+" is in the future")
		},
		"T not UTC": func(_ *testing.T, f *fixture) string {
			f.opts.DerivedAt = "2026-12-01T01:00:00+01:00"
			return refusal(CodeDerivationTime, `"2026-12-01T01:00:00+01:00" is not a UTC time like 2026-10-02T00:00:00Z`)
		},
		"run at another T": func(_ *testing.T, f *fixture) string {
			f.opts.DerivedAt = "2026-12-01T00:00:01Z"
			return refusal(CodeDerivationTime, "the run was derived at "+testAt+", not 2026-12-01T00:00:01Z")
		},
		"T not after the base derivation": func(t *testing.T, f *fixture) string {
			f.base = derive(t, upstream{baseVersions}, testAt, testOld).Attestations
			f.repack(t)
			return f.key(0) + ": " + refusal(CodeDerivationTime, "derivedAt must be a new derivation later than the base one and equal reviewedAt")
		},
		// Date-only edit: the dates moved by hand, without a run of that time.
		"date-only edit of an old run": func(t *testing.T, f *fixture) string {
			old := runFiles(t, derive(t, upstream{baseVersions}, testOldAt, testOld))
			f.both(t, repin(t, old, func(m, _ map[string]any) { m["derivedAt"], m["validUntil"] = testAt, testUntil }))
			return refusal(CodeRun, f.key(0)+" does not carry the run's times")
		},
		// Pack and run shape.
		"base not canonical": func(_ *testing.T, f *fixture) string {
			f.opts.Pack = append(f.opts.Pack, '\n')
			return refusal(CodeInput, "the base pack is not in its canonical rendering")
		},
		"manifest absent": func(t *testing.T, f *fixture) string {
			files := repin(t, f.files, nil)
			delete(files, extract.FileManifest)
			f.both(t, files)
			return refusal(CodeRun, "the run has no manifest")
		},
		"manifest with a repeated member": func(t *testing.T, f *fixture) string {
			files := repin(t, f.files, nil)
			files[extract.FileManifest] = bytes.Replace(files[extract.FileManifest], []byte(`"repo":`), []byte(`"repo":"x","repo":`), 1)
			f.both(t, files)
			err := strictjson.Check(files[extract.FileManifest])
			if err == nil {
				t.Fatal("a repeated member was read")
			}
			return refusal(CodeRun, "manifest: "+err.Error())
		},
		"run with rules": func(t *testing.T, f *fixture) string {
			f.both(t, repin(t, f.files, func(m, _ map[string]any) { m["totals"].(map[string]any)["rules"] = 1 }))
			return refusal(CodeRun, "a listed-entries run holds neither rules nor drafts")
		},
		"cap of zero": func(_ *testing.T, f *fixture) string {
			f.opts.Max = 0
			return refusal(CodeInput, "the record cap must be 1-200")
		},
		"cap too high": func(_ *testing.T, f *fixture) string {
			f.opts.Max = MaxRecords + 1
			return refusal(CodeInput, "the record cap must be 1-200")
		},
		"nothing due": func(t *testing.T, f *fixture) string {
			f.base = derive(t, upstream{baseVersions}, testOldAt, 80).Attestations
			f.repack(t)
			return refusal(CodeNothing, "no due record of "+testID+" was renewed (0 due, 0 with a changed list, 0 not derived)")
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			want := edit(t, f)
			requireRefusal(t, f.opts, want)
		})
	}
}

// A line with a new upstream release is not renewed: its record stays as it is,
// the other lines are renewed and a new line is not added.
func TestAssembleLeavesChangedListsAndNewLines(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.both(t, runFiles(t, derive(t, upstream{append(slices.Clone(baseVersions), "3.5.2", "3.6.0")}, testAt, testLease)))
	res, err := Assemble(f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.ListChanged, []string{f.key(1)}) || !slices.Equal(res.Renewed, []string{f.key(0)}) || res.LeftOut != 1 {
		t.Fatalf("result %+v", res)
	}
	head := parsedSection(t, res.Pack)
	if len(head) != 2 {
		t.Fatalf("%d records", len(head))
	}
	x, err1 := json.Marshal(f.base[1])
	y, err2 := json.Marshal(head[1])
	if err1 != nil || err2 != nil || !bytes.Equal(x, y) {
		t.Fatalf("the changed line moved: %s", y)
	}
}

func TestAssembleCapAndMissingLine(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.opts.Max = 1
	res, err := Assemble(f.opts)
	if err != nil || !slices.Equal(res.Renewed, []string{f.key(0)}) || !slices.Equal(res.Deferred, []string{f.key(1)}) {
		t.Fatalf("result %+v %v", res, err)
	}
	// The runs no longer attest the newest line.
	f = newFixture(t)
	f.both(t, runFiles(t, derive(t, upstream{[]string{"3.3.0", "3.4.0", "3.4.1"}}, testAt, testLease)))
	res, err = Assemble(f.opts)
	if err != nil || !slices.Equal(res.NotDerived, []string{f.key(1)}) || !slices.Equal(res.Renewed, []string{f.key(0)}) {
		t.Fatalf("result %+v %v", res, err)
	}
}

// Ninety due records and a cap of 45 take two changes: the first renews the 45
// that end soonest and lists the other 45, the second, derived on the first
// one's result at a new time, renews exactly those. None is lost or repeated.
func TestAssembleTwoChangesOfFortyFive(t *testing.T) {
	t.Parallel()
	var versions []string
	for minor := 3; minor <= 93; minor++ {
		versions = append(versions, fmt.Sprintf("3.%d.0", minor))
	}
	u := upstream{versions}
	base := derive(t, u, testOldAt, testOld).Attestations
	if len(base) != 90 {
		t.Fatalf("%d records", len(base))
	}
	// Later records in the section end sooner, all of them an older build.
	oldEnd := time.Date(2026, 12, 11, 0, 0, 0, 0, time.UTC)
	var soonest, latest []string
	for i := range base {
		base[i].Evidence.ValidUntil = oldEnd.Add(time.Duration(len(base)-i) * time.Hour).Format(time.RFC3339)
		older := *base[i].Evidence.Extractor
		older.CodeDigest = sum([]byte("older build"))
		base[i].Evidence.Extractor = &older
		if i >= 45 {
			soonest = append(soonest, base[i].Key().String())
		} else {
			latest = append(latest, base[i].Key().String())
		}
	}
	slices.Sort(soonest)
	slices.Sort(latest)
	current, err := Current(extractcli.Catalog()[testID].New(1))
	if err != nil {
		t.Fatal(err)
	}
	change := func(pack []byte, at string, days int) *Result {
		t.Helper()
		files := runFiles(t, derive(t, u, at, days))
		when, err := time.Parse(time.RFC3339, at)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Assemble(Options{Pack: pack, Extractor: testID, Repo: testRepo(t), Current: current,
			RunDir: writeRun(t, files), SecondRunDir: writeRun(t, files), DerivedAt: at, LeaseDays: days, Max: 45, Now: when.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	first := change(packOf(t, base), testAt, 80)
	if !slices.Equal(first.Renewed, soonest) || !slices.Equal(first.Deferred, latest) {
		t.Fatalf("first change renewed %v, deferred %v", first.Renewed, first.Deferred)
	}
	const secondAt = "2026-12-02T00:00:00Z"
	second := change(first.Pack, secondAt, 87)
	if !slices.Equal(second.Renewed, latest) || len(second.Deferred)+len(second.ListChanged)+len(second.NotDerived) != 0 {
		t.Fatalf("second change %+v", second)
	}
	ends := map[string]map[string]bool{}
	for _, a := range parsedSection(t, second.Pack) {
		at := a.Evidence.DerivedAt
		if ends[at] == nil {
			ends[at] = map[string]bool{}
		}
		ends[at][a.Evidence.ValidUntil] = true
		want := slices.Contains(first.Renewed, a.Key().String())
		if (at == testAt) != want || (at == secondAt) == want || *a.Evidence.Extractor != current {
			t.Fatalf("%s: %+v", a.Key(), a.Evidence)
		}
	}
	week := func(at string) string {
		t.Helper()
		if len(ends[at]) != 1 {
			t.Fatalf("ends of %s: %v", at, ends[at])
		}
		for end := range ends[at] {
			when, err := time.Parse(time.RFC3339, end)
			if err != nil {
				t.Fatal(err)
			}
			y, w := when.ISOWeek()
			return fmt.Sprintf("%d-W%02d", y, w)
		}
		return ""
	}
	if week(testAt) == week(secondAt) {
		t.Fatalf("both changes end in %s", week(testAt))
	}
}

func TestTimeOnly(t *testing.T) {
	t.Parallel()
	u := upstream{baseVersions}
	old := derive(t, u, testOldAt, testOld).Attestations[0]
	good := derive(t, u, testAt, testLease).Attestations[0]
	if err := TimeOnly(rawRecord(t, old, nil), rawRecord(t, good, nil)); err != nil {
		t.Fatal(err)
	}
	changed := refusal(CodeChanged, "the record differs in more than evidence.derivedAt, reviewedAt and validUntil")
	otherBuild := refusal(CodeOtherExtractor, "the new record names another extractor or build than the base record")
	notLater := refusal(CodeDerivationTime, "derivedAt must be a new derivation later than the base one and equal reviewedAt")
	badLife := refusal(CodeLease, "validUntil must be more than 0 and at most 90 days after derivedAt")
	for name, tc := range map[string]struct {
		want string
		edit func(r, e map[string]any)
	}{
		"lease member added":  {changed, func(_, e map[string]any) { e["lease"] = "pinned" }},
		"other member added":  {changed, func(r, _ map[string]any) { r["note"] = "x" }},
		"releases changed":    {changed, func(r, _ map[string]any) { r["releases"].(map[string]any)["from"] = []any{} }},
		"sources changed":     {changed, func(_, e map[string]any) { e["sources"] = []any{} }},
		"rule ids changed":    {changed, func(r, _ map[string]any) { r["ruleIds"] = []any{"x"} }},
		"line changed":        {changed, func(r, _ map[string]any) { r["line"] = "9.9" }},
		"extractor changed":   {otherBuild, func(_, e map[string]any) { e["extractor"].(map[string]any)["id"] = "changelog.listed.tuf" }},
		"digest changed":      {otherBuild, func(_, e map[string]any) { e["extractor"].(map[string]any)["codeDigest"] = "sha256:00" }},
		"version changed":     {otherBuild, func(_, e map[string]any) { e["extractor"].(map[string]any)["version"] = "9.0.0" }},
		"no extractor":        {refusal(CodeOtherExtractor, "the new record does not name an extractor id, version and codeDigest"), func(_, e map[string]any) { delete(e, "extractor") }},
		"derivedAt not later": {notLater, func(_, e map[string]any) { e["derivedAt"], e["reviewedAt"] = testOldAt, testOldAt }},
		"reviewedAt differs":  {notLater, func(_, e map[string]any) { e["reviewedAt"] = testOldAt }},
		"over 90 days":        {badLife, func(_, e map[string]any) { e["validUntil"] = "2027-03-01T00:00:01Z" }},
		"ends at derivation":  {badLife, func(_, e map[string]any) { e["validUntil"] = testAt }},
		"ends not later": {refusal(CodeLease, "validUntil is not later than the base one"),
			func(_, e map[string]any) { e["validUntil"] = old.Evidence.ValidUntil }},
		"unreadable end": {refusal(CodeInput, "the new record's times cannot be read"), func(_, e map[string]any) { e["validUntil"] = "later" }},
		"reviewed basis": {refusal(CodeInput, "the new record is not mechanical"), func(_, e map[string]any) { e["basis"] = "reviewed" }},
		"another fact family": {refusal(CodeInput, "the new record is not a changelog.listed_entries record with evidence"),
			func(r, _ map[string]any) { r["factFamily"] = lineattest.FamilyCustomResourceVersions }},
	} {
		if err := TimeOnly(rawRecord(t, old, nil), rawRecord(t, good, tc.edit)); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
	repeated := bytes.Replace(rawRecord(t, good, nil), []byte(`"line":`), []byte(`"line":"9.9","line":`), 1)
	cause := strictjson.Check(repeated)
	if cause == nil {
		t.Fatal("a repeated member was read")
	}
	want := refusal(CodeInput, "the new record: "+cause.Error())
	if err := TimeOnly(rawRecord(t, old, nil), repeated); err == nil || err.Error() != want {
		t.Errorf("repeated member: %v, want %s", err, want)
	}
	// Exactly 90 days is allowed.
	if err := TimeOnly(rawRecord(t, old, nil), rawRecord(t, good, func(_, e map[string]any) { e["validUntil"] = "2027-03-01T00:00:00Z" })); err != nil {
		t.Fatal(err)
	}
}

// rawRecord is a as JSON, after edit on the record and its evidence.
func rawRecord(t *testing.T, a lineattest.LineAttestation, edit func(r, e map[string]any)) []byte {
	t.Helper()
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if edit == nil {
		return data
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	edit(m, m["evidence"].(map[string]any))
	if data, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	return data
}

// The shipped pack can be rewritten with nothing but the renewal, and every
// listed record in it satisfies the pinning requirement of a renewal.
func TestShippedListedRecordsCanBeRenewed(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	list, err := section(p)
	if err != nil {
		t.Fatal(err)
	}
	if same, err := render(p, list); err != nil || !bytes.Equal(same, raw) {
		t.Fatalf("the shipped pack is not canonical: %v", err)
	}
	listed := 0
	for _, a := range list {
		if a.FactFamily != lineattest.FamilyChangelogListedEntries {
			continue
		}
		listed++
		spec, ok := extractcli.Catalog()[a.Evidence.Extractor.ID]
		if !ok {
			t.Fatalf("%s: unknown extractor", a.Key())
		}
		repo, err := extract.ParseRepo(spec.Repo)
		if err != nil {
			t.Fatal(err)
		}
		if err := Pinned(a, repo); err != nil {
			t.Error(err)
		}
	}
	if listed == 0 {
		t.Fatal("no listed record")
	}
}
