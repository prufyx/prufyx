// SPDX-License-Identifier: AGPL-3.0-only

package istionotes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

var (
	commitA = strings.Repeat("a", 40)
	repo    = extract.RepoRef{Key: "github.com/istio/istio"}
)

type memReader struct {
	files   map[string]string
	modes   map[string]string
	shuffle *rand.Rand
	readErr error
	extra   []extract.TreeEntry
}

func (m *memReader) Read(_ extract.RepoRef, _, p string) ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	if d, ok := m.files[p]; ok {
		return []byte(d), nil
	}
	return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
}

func (m *memReader) List(_ extract.RepoRef, _, dir string) ([]extract.TreeEntry, error) {
	var out []extract.TreeEntry
	for p := range m.files {
		if strings.HasPrefix(p, dir+"/") {
			mode := "100644"
			if v, ok := m.modes[p]; ok {
				mode = v
			}
			out = append(out, extract.TreeEntry{Mode: mode, Type: "blob", Path: p})
		}
	}
	out = append(out, m.extra...)
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if m.shuffle != nil {
		m.shuffle.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	}
	return out, nil
}

func fixtures(t testing.TB, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join("testdata", dir))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("testdata", dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[NotesDir+"/"+e.Name()] = string(b)
	}
	return out
}

func scan(t testing.TB, r extract.PinnedReader) *Result {
	t.Helper()
	res, err := Scan(context.Background(), r, Target{Repo: repo}, commitA)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestPositiveFixtures(t *testing.T) {
	res := scan(t, &memReader{files: fixtures(t, "ok")})
	if len(res.Ledger) != 0 {
		t.Fatalf("ledger %v", res.Ledger)
	}
	type k struct{ file, typ, action, member, kind string }
	var got []k
	for _, c := range res.Candidates {
		got = append(got, k{strings.TrimPrefix(c.File, NotesDir+"/"), c.Type, c.Action, c.Member, c.Kind})
		if c.EvidenceBasis == "mechanical" || c.EvidenceBasis != "draft" || !c.NeedsReview {
			t.Fatalf("basis %+v", c)
		}
		if !strings.HasPrefix(c.SourceURL, "https://github.com/istio/istio/blob/"+commitA+"/releasenotes/notes/") {
			t.Fatalf("url %s", c.SourceURL)
		}
		if c.Quote == "" || c.StartLine < 1 || c.EndLine < c.StartLine {
			t.Fatalf("span %+v", c)
		}
	}
	want := []k{
		{"field-deprecated.yaml", "field", "deprecated", "networking.istio.io/VirtualService/spec/http/mirrorPercent", "VirtualService"},
		{"field-deprecated.yaml", "field", "deprecated", "networking.istio.io/VirtualService/spec/http/mirrorPercent", "VirtualService"},
		{"flag-removed.yaml", "flag", "removed", "old-flag", ""},
		{"future-removal.yaml", "flag", "deprecated", "legacy-mode", ""},
		{"kind-removed.yaml", "crd_kind", "removed", "", "ProxyConfig"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if res.FilesRead != 5 {
		t.Fatalf("files read %d", res.FilesRead)
	}
}

func TestSpan(t *testing.T) {
	res := scan(t, &memReader{files: fixtures(t, "ok")})
	for _, c := range res.Candidates {
		if strings.HasSuffix(c.File, "flag-removed.yaml") {
			// releaseNotes literal block: "- |" is line 7, text on line 8.
			if c.StartLine != 8 || c.EndLine != 8 || !c.SpanExact || c.Section != SectionReleaseNotes {
				t.Fatalf("%+v", c)
			}
		}
		if strings.HasSuffix(c.File, "kind-removed.yaml") && c.SpanExact {
			t.Fatalf("plain scalar span must not be exact: %+v", c)
		}
	}
}

func TestNegativeFixtures(t *testing.T) {
	want := map[string]string{
		"unknown-field":     ReasonParse,
		"alias":             ReasonParse,
		"duplicate-key":     ReasonParse,
		"two-docs":          ReasonParse,
		"bad-version":       ReasonSchema,
		"bad-kind":          ReasonKindUnknown,
		"not-string":        ReasonParse,
		"no-token":          ReasonNoToken,
		"unclassified":      ReasonUnclassified,
		"mixed-action":      ReasonAmbiguous,
		"negated":           ReasonAmbiguous,
		"replacement":       ReasonAmbiguous,
		"kind-conflict":     ReasonAmbiguous,
		"gateway-ambiguous": ReasonUnclassified,
		"code-fence":        ReasonUnclassified,
		"tag":               ReasonParse,
		"bad-area":          ReasonParse,
	}
	files := fixtures(t, "neg")
	if len(files) != len(want) {
		t.Fatalf("%d fixtures, %d expectations", len(files), len(want))
	}
	for name, code := range want {
		t.Run(name, func(t *testing.T) {
			p := NotesDir + "/" + name + ".yaml"
			res := scan(t, &memReader{files: map[string]string{p: files[p]}})
			if len(res.Candidates) != 0 {
				t.Fatalf("candidates %+v", res.Candidates)
			}
			if len(res.Ledger) != 1 || res.Ledger[0] != (LedgerEntry{Code: code, Item: p}) {
				t.Fatalf("ledger %+v, want %s", res.Ledger, code)
			}
		})
	}
}

func TestNegativeDoesNotHideOthers(t *testing.T) {
	files := fixtures(t, "ok")
	for p, c := range fixtures(t, "neg") {
		files[p] = c
	}
	res := scan(t, &memReader{files: files})
	if len(res.Ledger) != 17 || len(res.Candidates) != 5 {
		t.Fatalf("ledger %d candidates %d", len(res.Ledger), len(res.Candidates))
	}
}

func TestDeterministic(t *testing.T) {
	files := fixtures(t, "ok")
	for p, c := range fixtures(t, "neg") {
		files[p] = c
	}
	var first []byte
	for i := 0; i < 20; i++ {
		b, err := json.Marshal(scan(t, &memReader{files: files, shuffle: rand.New(rand.NewSource(int64(i)))}))
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = b
		} else if string(first) != string(b) {
			t.Fatalf("run %d differs", i)
		}
	}
	res := scan(t, &memReader{files: files})
	if !sort.SliceIsSorted(res.Candidates, func(i, j int) bool { return lessCandidate(res.Candidates[i], res.Candidates[j]) }) {
		t.Fatal("candidates unsorted")
	}
}

func one(body string) *memReader {
	return &memReader{files: map[string]string{NotesDir + "/a.yaml": body}}
}

const head = "apiVersion: release-notes/v2\nkind: removal\narea: installation\n"

func TestStructuralFaults(t *testing.T) {
	big := head + "releaseNotes:\n  - Removed `--a`.\n#" + strings.Repeat("x", MaxNoteBytes) + "\n"
	longText := head + "releaseNotes:\n  - Removed `--a` " + strings.Repeat("y", MaxQuoteBytes) + "\n"
	longFlag := head + "releaseNotes:\n  - Removed `--" + strings.Repeat("z", 150) + "`.\n"
	many := head + "releaseNotes:\n"
	for i := 0; i < MaxCandidatesPerNote+1; i++ {
		many += fmt.Sprintf("  - Removed `--f%d`.\n", i)
	}
	odd := head + "releaseNotes:\n  - Removed `--a and more.\n"
	cases := []struct {
		name string
		r    *memReader
		code string
	}{
		{"too large", one(big), ReasonTooLarge},
		{"text too large", one(longText), ReasonTextTooLarge},
		{"member refused", one(longFlag), ReasonMember},
		{"too many per note", one(many), ReasonTooManyCandidates},
		{"odd backticks", one(odd), ReasonUnclassified},
		{"empty file", one(""), ReasonParse},
		{"not mapping", one("- a\n"), ReasonParse},
		{"dir missing", &memReader{files: map[string]string{"other/a.yaml": "x"}}, ReasonDirMissing},
		{"symlink", &memReader{files: map[string]string{NotesDir + "/a.yaml": head}, modes: map[string]string{NotesDir + "/a.yaml": "120000"}}, ReasonEntryNotFile},
		{"submodule", &memReader{files: map[string]string{NotesDir + "/b.yaml": head + "releaseNotes: [x]\n"}, extra: []extract.TreeEntry{{Mode: "160000", Type: "commit", Path: NotesDir + "/a.yaml"}}}, ReasonEntryNotFile},
		{"subtree", &memReader{files: map[string]string{NotesDir + "/b.yaml": head + "releaseNotes: [x]\n"}, extra: []extract.TreeEntry{{Mode: "040000", Type: "tree", Path: NotesDir + "/sub.yaml"}}}, ReasonEntryNotFile},
		{"non yaml", &memReader{files: map[string]string{NotesDir + "/README.md": "x"}}, ReasonUnsafeName},
		{"hostile name", &memReader{files: map[string]string{NotesDir + "/a b.yaml": "x"}}, ReasonUnsafeName},
		{"nested path", &memReader{files: map[string]string{NotesDir + "/a.yaml": "x"}, extra: []extract.TreeEntry{{Mode: "100644", Type: "blob", Path: NotesDir + "/d/e.yaml"}}}, ReasonUnsafeName},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scan(t, c.r)
			if len(res.Candidates) != 0 {
				t.Fatalf("candidates %+v", res.Candidates)
			}
			found := false
			for _, e := range res.Ledger {
				if e.Code == c.code {
					found = true
				}
			}
			if !found {
				t.Fatalf("ledger %+v lacks %s", res.Ledger, c.code)
			}
		})
	}
}

func TestTooManyFiles(t *testing.T) {
	m := &memReader{files: map[string]string{}}
	for i := 0; i <= MaxFiles; i++ {
		m.files[fmt.Sprintf("%s/n%d.yaml", NotesDir, i)] = head
	}
	res := scan(t, m)
	if len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonTooManyFiles || res.FilesRead != 0 {
		t.Fatalf("%+v", res.Ledger)
	}
}

func TestIOErrorsAbort(t *testing.T) {
	boom := errors.New("boom")
	r := one(head)
	r.readErr = boom
	if _, err := Scan(context.Background(), r, Target{Repo: repo}, commitA); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, one(head), Target{Repo: repo}, commitA); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	for _, sha := range []string{"", "main", strings.Repeat("A", 40), commitA[:39]} {
		if _, err := Scan(context.Background(), one(head), Target{Repo: repo}, sha); err == nil {
			t.Fatalf("sha %q accepted", sha)
		}
	}
}

func TestPanicBecomesLedger(t *testing.T) {
	res, err := Scan(context.Background(), nil, Target{Repo: repo}, commitA)
	if err != nil || len(res.Candidates) != 0 || len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonPanic {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestOnlyReleaseAndUpgradeAreRead(t *testing.T) {
	body := head + "docs:\n  - Removed `--docs-flag`.\nsecurityNotes:\n  - Removed `--sec-flag`.\n"
	res := scan(t, one(body))
	if len(res.Candidates) != 0 || len(res.Ledger) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestLedgerCanonical(t *testing.T) {
	l := ledgerSet{}
	l.add("ZED_CODE", "b")
	l.add("ALPHA_CODE", "z")
	l.add("ALPHA_CODE", "a")
	got := l.canonical()
	if len(got) != 3 || got[0].Item != "a" || got[1].Item != "z" || got[2].Code != "ZED_CODE" {
		t.Fatalf("%+v", got)
	}
	bad := ledgerSet{}
	bad.add("lower", "x")
	if g := bad.canonical(); len(g) != 1 || g[0].Code != LedgerInvalid {
		t.Fatalf("%+v", g)
	}
	bad = ledgerSet{}
	bad.add("OK_CODE", "bad item with space")
	if g := bad.canonical(); len(g) != 1 || g[0].Code != LedgerInvalid {
		t.Fatalf("%+v", g)
	}
	over := ledgerSet{}
	for i := 0; i <= MaxLedgerEntries; i++ {
		over.add("OK_CODE", fmt.Sprintf("i%d", i))
	}
	if g := over.canonical(); len(g) != 1 || g[0].Code != LedgerOverflow {
		t.Fatalf("%+v", g)
	}
}

func TestResultJSONGolden(t *testing.T) {
	res := scan(t, &memReader{files: map[string]string{NotesDir + "/a.yaml": head + "releaseNotes:\n  - |\n    Removed `--old`.\n"}})
	b, _ := json.Marshal(res)
	want := `{"schema":"prufyx.io/istio-notes-scan/v1","commit":"` + commitA + `","filesRead":1,"candidates":[{"type":"flag","action":"removed","member":"old","file":"releasenotes/notes/a.yaml","noteKind":"removal","area":"installation","section":"releaseNotes","quote":"Removed ` + "`--old`" + `.","startLine":6,"endLine":6,"spanExact":true,"sourceUrl":"https://github.com/istio/istio/blob/` + commitA + `/releasenotes/notes/a.yaml","evidenceBasis":"draft","needsReview":true}],"ledger":[]}`
	if string(b) != want {
		t.Fatalf("\n%s\n%s", b, want)
	}
}

func TestSourceSetCoversEncoder(t *testing.T) {
	files, err := extract.CodeFiles(SourceSet())
	if err != nil {
		t.Fatal(err)
	}
	var own, enc, tests int
	for _, f := range files {
		switch {
		case strings.HasSuffix(f.Path, "_test.go"):
			tests++
		case strings.Contains(f.Path, "membercode_membercode.go"):
			enc++
		case strings.Contains(f.Path, "scan.go"):
			own++
		}
	}
	if own != 1 || enc != 1 || tests != 0 {
		t.Fatalf("own %d encoder %d tests %d: %+v", own, enc, tests, files)
	}
	again, _ := extract.CodeFiles(SourceSet())
	if fmt.Sprint(files) != fmt.Sprint(again) {
		t.Fatal("source set unstable")
	}
}

func TestNeverMechanical(t *testing.T) {
	if EvidenceBasis != "draft" {
		t.Fatal(EvidenceBasis)
	}
	src, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "BasisMechanical") || strings.Contains(string(src), "constraintengine") {
		t.Fatal("scan.go must not reference mechanical basis")
	}
}
