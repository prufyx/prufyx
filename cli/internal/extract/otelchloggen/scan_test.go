// SPDX-License-Identifier: AGPL-3.0-only

package otelchloggen

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	gotoken "go/token"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"gopkg.in/yaml.v3"
)

var (
	commitA = strings.Repeat("a", 40)
	repo    = extract.RepoRef{Key: "github.com/open-telemetry/opentelemetry-collector"}
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
		out[ChloggenDir+"/"+e.Name()] = string(b)
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
	type k struct{ file, typ, action, member, comp string }
	var got []k
	for _, c := range res.Candidates {
		got = append(got, k{strings.TrimPrefix(c.File, ChloggenDir+"/"), c.Type, c.Action, c.Member, c.Component})
		if c.EvidenceBasis == "mechanical" || c.EvidenceBasis != "draft" || !c.NeedsReview {
			t.Fatalf("basis %+v", c)
		}
		if !strings.HasPrefix(c.SourceURL, "https://github.com/open-telemetry/opentelemetry-collector/blob/"+commitA+"/.chloggen/") {
			t.Fatalf("url %s", c.SourceURL)
		}
		if c.Quote == "" || c.StartLine < 1 || c.EndLine < c.StartLine {
			t.Fatalf("span %+v", c)
		}
	}
	want := []k{
		{"breaking-dropped-key.yaml", "config_key", "removed_or_changed", "retry_legacy", "exporter/otlp"},
		{"breaking-removed-flag.yaml", "flag", "removed", "legacy-flag", "unknown"},
		{"breaking-removed-key.yaml", "config_key", "removed", "protocols.legacy_http", "receiver/otlp"},
		{"deprecation-future-flag.yaml", "flag", "deprecated", "legacy-mode", "unknown"},
		{"deprecation-key-subtext.yaml", "config_key", "deprecated", "send_batch_legacy", "processor/batch"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if res.FilesRead != 5 {
		t.Fatalf("files read %d", res.FilesRead)
	}
}

func TestSpan(t *testing.T) {
	res := scan(t, &memReader{files: map[string]string{
		ChloggenDir + "/a.yaml": "change_type: breaking\ncomponent: service\nnote: |\n  Remove the `--a` flag.\nissues: [1]\n",
		ChloggenDir + "/b.yaml": "change_type: breaking\ncomponent: service\nnote: Remove the `--b` flag.\nissues: [1]\nsubtext: |\n  Plain words.\n",
	}})
	if len(res.Candidates) != 2 {
		t.Fatalf("%+v", res)
	}
	a, b := res.Candidates[0], res.Candidates[1]
	if a.StartLine != 4 || a.EndLine != 4 || !a.SpanExact {
		t.Fatalf("%+v", a)
	}
	if b.StartLine != 3 || b.EndLine != 6 || b.SpanExact || b.Quote != "Remove the `--b` flag.\nPlain words." {
		t.Fatalf("%+v", b)
	}
}

func TestNegativeFixtures(t *testing.T) {
	want := map[string]string{
		"unknown-field":            ReasonParse,
		"alias":                    ReasonParse,
		"duplicate-key":            ReasonParse,
		"two-docs":                 ReasonParse,
		"tag":                      ReasonParse,
		"not-string":               ReasonParse,
		"no-issues":                ReasonParse,
		"issue-not-int":            ReasonParse,
		"empty-note":               ReasonParse,
		"bad-component":            ReasonParse,
		"bad-change-type":          ReasonChangeTypeUnknown,
		"component-unknown":        ReasonComponentUnknown,
		"may-be-removed":           ReasonAmbiguous,
		"planned":                  ReasonAmbiguous,
		"removal-in":               ReasonAmbiguous,
		"next-release":             ReasonAmbiguous,
		"will-be-deprecated":       ReasonAmbiguous,
		"negated":                  ReasonAmbiguous,
		"replacement":              ReasonAmbiguous,
		"defaults":                 ReasonAmbiguous,
		"not-adjacent":             ReasonAmbiguous,
		"mixed-action":             ReasonAmbiguous,
		"feature-gate":             ReasonAmbiguous,
		"deprecation-says-removed": ReasonAmbiguous,
		"deprecation-no-verb":      ReasonAmbiguous,
		"breaking-says-deprecated": ReasonAmbiguous,
		"subtext-negates":          ReasonAmbiguous,
		"no-token":                 ReasonNoToken,
		"unclassified":             ReasonUnclassified,
		"code-fence":               ReasonUnclassified,
	}
	files := fixtures(t, "neg")
	if len(files) != len(want) {
		t.Fatalf("%d fixtures, %d expectations", len(files), len(want))
	}
	for name, code := range want {
		t.Run(name, func(t *testing.T) {
			p := ChloggenDir + "/" + name + ".yaml"
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
	if len(res.Ledger) != 30 || len(res.Candidates) != 5 {
		t.Fatalf("ledger %d candidates %d", len(res.Ledger), len(res.Candidates))
	}
}

// Replacement, negation, default and gate prose withholds a text at any token
// count, and the verb must stand next to every token.
func TestChecksHoldAtAnyTokenCount(t *testing.T) {
	cases := map[string]string{
		"one token replaced":  "Remove the `--a` flag, replaced by config.",
		"three tokens negate": "Remove `--a`, `--b` and `--c`, but `--a` is not removed.",
		"three tokens modal":  "Remove `--a`, `--b` and `--c`, which may be removed later.",
		"three default":       "Remove `--a`, `--b` and `--c`; the default differs.",
		"verb after list":     "Remove `--a`, `--b` and `--c`, plus see `--d`.",
		"gate":                "Remove `--a` and the gate.",
	}
	for name, note := range cases {
		t.Run(name, func(t *testing.T) {
			res := scan(t, one(frag("breaking", "service", note)))
			if len(res.Candidates) != 0 || len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonAmbiguous {
				t.Fatalf("%+v", res)
			}
		})
	}
	ok := scan(t, one(frag("breaking", "service", "Remove `--a`, `--b` and `--c`.")))
	if len(ok.Candidates) != 3 || len(ok.Ledger) != 0 {
		t.Fatalf("%+v", ok)
	}
}

func TestInertChangeTypesAndToolFiles(t *testing.T) {
	files := map[string]string{
		ChloggenDir + "/a.yaml":        frag("enhancement", "service", "Remove the `--a` flag."),
		ChloggenDir + "/b.yaml":        frag("bug_fix", "service", "Deprecate the `--b` flag."),
		ChloggenDir + "/c.yaml":        frag("new_component", "anything", "Remove the `--c` flag."),
		ChloggenDir + "/TEMPLATE.yaml": "change_type: ''\n",
		ChloggenDir + "/config.yaml":   "entries: x\n",
	}
	res := scan(t, &memReader{files: files})
	if len(res.Candidates) != 0 || len(res.Ledger) != 0 || res.FilesRead != 3 {
		t.Fatalf("%+v", res)
	}
	// The skip is by exact name only.
	res = scan(t, &memReader{files: map[string]string{ChloggenDir + "/config2.yaml": "entries: x\n"}})
	if len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonParse {
		t.Fatalf("%+v", res)
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
	return &memReader{files: map[string]string{ChloggenDir + "/a.yaml": body}}
}

func frag(changeType, component, note string) string {
	return "change_type: " + changeType + "\ncomponent: " + component + "\nnote: '" + strings.ReplaceAll(note, "'", "''") + "'\nissues: [1]\n"
}

const head = "change_type: breaking\ncomponent: service\nissues: [1]\n"

func TestStructuralFaults(t *testing.T) {
	big := head + "note: Remove `--a`.\n#" + strings.Repeat("x", MaxFragmentBytes) + "\n"
	longText := head + "note: Remove `--a` " + strings.Repeat("y", MaxQuoteBytes) + "\n"
	longFlag := head + "note: Remove `--" + strings.Repeat("z", 150) + "`.\n"
	odd := head + "note: Remove `--a and more.\n"
	manyIssues := "change_type: breaking\ncomponent: service\nnote: Remove `--a`.\nissues: [" + strings.Repeat("1,", MaxIssues) + "1]\n"
	cases := []struct {
		name string
		r    *memReader
		code string
	}{
		{"too large", one(big), ReasonTooLarge},
		{"text too large", one(longText), ReasonTextTooLarge},
		{"member refused", one(longFlag), ReasonMember},
		{"odd backticks", one(odd), ReasonUnclassified},
		{"too many issues", one(manyIssues), ReasonParse},
		{"empty file", one(""), ReasonParse},
		{"not mapping", one("- a\n"), ReasonParse},
		{"dir missing", &memReader{files: map[string]string{"other/a.yaml": "x"}}, ReasonDirMissing},
		{"symlink", &memReader{files: map[string]string{ChloggenDir + "/a.yaml": head}, modes: map[string]string{ChloggenDir + "/a.yaml": "120000"}}, ReasonEntryNotFile},
		{"submodule", &memReader{files: map[string]string{ChloggenDir + "/b.yaml": head}, extra: []extract.TreeEntry{{Mode: "160000", Type: "commit", Path: ChloggenDir + "/a.yaml"}}}, ReasonEntryNotFile},
		{"subtree", &memReader{files: map[string]string{ChloggenDir + "/b.yaml": head}, extra: []extract.TreeEntry{{Mode: "040000", Type: "tree", Path: ChloggenDir + "/sub.yaml"}}}, ReasonEntryNotFile},
		{"non yaml", &memReader{files: map[string]string{ChloggenDir + "/README.md": "x"}}, ReasonUnsafeName},
		{"hostile name", &memReader{files: map[string]string{ChloggenDir + "/a b.yaml": "x"}}, ReasonUnsafeName},
		{"nested path", &memReader{files: map[string]string{ChloggenDir + "/a.yaml": "x"}, extra: []extract.TreeEntry{{Mode: "100644", Type: "blob", Path: ChloggenDir + "/d/e.yaml"}}}, ReasonUnsafeName},
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
		m.files[fmt.Sprintf("%s/n%d.yaml", ChloggenDir, i)] = head
	}
	res := scan(t, m)
	if len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonTooManyFiles || res.FilesRead != 0 {
		t.Fatalf("%+v", res.Ledger)
	}
}

func TestIOErrorsAbort(t *testing.T) {
	boom := errors.New("boom")
	r := one(head + "note: x\n")
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

func TestLedgerCarriesNoSourceText(t *testing.T) {
	secret := "ZZSECRETPROSE"
	res := scan(t, one(frag("breaking", "service", "Remove `--a` instead of "+secret+".")))
	b, _ := json.Marshal(res.Ledger)
	if len(res.Ledger) != 1 || strings.Contains(string(b), secret) {
		t.Fatalf("%s", b)
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
	res := scan(t, &memReader{files: map[string]string{ChloggenDir + "/a.yaml": "change_type: breaking\ncomponent: service\nnote: |\n  Remove `--old`.\nissues: [1]\n"}})
	b, _ := json.Marshal(res)
	want := `{"schema":"prufyx.io/otel-chloggen-scan/v1","commit":"` + commitA + `","filesRead":1,"candidates":[{"type":"flag","action":"removed","member":"old","component":"unknown","file":".chloggen/a.yaml","changeType":"breaking","section":"note","quote":"Remove ` + "`--old`" + `.","startLine":4,"endLine":4,"spanExact":true,"sourceUrl":"https://github.com/open-telemetry/opentelemetry-collector/blob/` + commitA + `/.chloggen/a.yaml","evidenceBasis":"draft","needsReview":true}],"ledger":[]}`
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

func nonTestSources(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range m {
		if !strings.HasSuffix(f, "_test.go") {
			out = append(out, f)
		}
	}
	if len(out) < 5 {
		t.Fatalf("sources %v", out)
	}
	return out
}

func TestNeverMechanical(t *testing.T) {
	if EvidenceBasis != "draft" {
		t.Fatal(EvidenceBasis)
	}
	for _, f := range nonTestSources(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(b)), "mechanical") {
			t.Fatalf("%s mentions the mechanical basis", f)
		}
	}
	res := scan(t, &memReader{files: fixtures(t, "ok")})
	if len(res.Candidates) == 0 {
		t.Fatal("no candidates")
	}
	for _, c := range res.Candidates {
		if c.EvidenceBasis != "draft" || !c.NeedsReview {
			t.Fatalf("%+v", c)
		}
		if c.Type == TypeFlag && c.Component != ComponentUnknown {
			t.Fatalf("flag without unknown component: %+v", c)
		}
	}
}

var importAllow = map[string]bool{
	"bytes": true, "context": true, "embed": true, "errors": true, "fmt": true,
	"io": true, "io/fs": true, "path": true, "regexp": true, "sort": true,
	"strconv": true, "strings": true, "testing/fstest": true,
	"gopkg.in/yaml.v3": true,
	"github.com/prufyx/prufyx/cli/internal/extract":            true,
	"github.com/prufyx/prufyx/cli/internal/extract/membercode": true,
}

func disallowedImports(name string, src any) ([]string, error) {
	f, err := parser.ParseFile(gotoken.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if !importAllow[p] {
			bad = append(bad, p)
		}
	}
	return bad, nil
}

func TestImportAllowlist(t *testing.T) {
	for _, f := range nonTestSources(t) {
		bad, err := disallowedImports(f, nil)
		if err != nil || len(bad) > 0 {
			t.Fatalf("%s: %v %v", f, bad, err)
		}
	}
	// The guard is load-bearing: it refuses network, exec and file access.
	src := "package x\nimport (\n\"net/http\"\n\"os/exec\"\n\"os\"\n\"unsafe\"\n)\n"
	bad, err := disallowedImports("x.go", src)
	if err != nil || len(bad) != 4 {
		t.Fatalf("%v %v", bad, err)
	}
}

func TestBoundsAreEnforced(t *testing.T) {
	// Exactly at the limit is accepted, one over is withheld.
	base := head + "note: Remove `--a`.\n#"
	atLimit := base + strings.Repeat("x", MaxFragmentBytes-len(base)-1) + "\n"
	if len(atLimit) != MaxFragmentBytes {
		t.Fatal(len(atLimit))
	}
	if res := scan(t, one(atLimit)); len(res.Candidates) != 1 || len(res.Ledger) != 0 {
		t.Fatalf("%+v", res)
	}
	over := head + "note: Remove `--a`.\n#" + strings.Repeat("x", MaxFragmentBytes) + "\n"
	if res := scan(t, one(over)); len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonTooLarge {
		t.Fatalf("%+v", res.Ledger)
	}
	quote := func(n int) string {
		pad := n - len("Remove `--a` ")
		return head + "note: 'Remove `--a` " + strings.Repeat("y", pad) + "'\n"
	}
	if res := scan(t, one(quote(MaxQuoteBytes))); len(res.Candidates) != 1 {
		t.Fatalf("%+v", res)
	}
	if res := scan(t, one(quote(MaxQuoteBytes+1))); len(res.Candidates) != 0 || res.Ledger[0].Code != ReasonTextTooLarge {
		t.Fatalf("%+v", res)
	}
	issues := func(n int) string {
		return "change_type: breaking\ncomponent: service\nnote: Remove `--a`.\nissues: [" + strings.Repeat("1,", n-1) + "1]\n"
	}
	if res := scan(t, one(issues(MaxIssues))); len(res.Candidates) != 1 {
		t.Fatalf("%+v", res)
	}
	if res := scan(t, one(issues(MaxIssues+1))); len(res.Candidates) != 0 || res.Ledger[0].Code != ReasonParse {
		t.Fatalf("%+v", res)
	}
	toks := func(n int) string {
		var l []string
		for i := 0; i < n; i++ {
			l = append(l, fmt.Sprintf("`--f%d`", i))
		}
		return head + "note: Remove " + strings.Join(l, ", ") + ".\n"
	}
	if res := scan(t, one(toks(MaxCandidatesPerFragment))); len(res.Candidates) != MaxCandidatesPerFragment {
		t.Fatalf("%d %+v", len(res.Candidates), res.Ledger)
	}
	if res := scan(t, one(toks(MaxCandidatesPerFragment+1))); len(res.Candidates) != 0 || res.Ledger[0].Code != ReasonTooManyCandidates {
		t.Fatalf("%+v", res)
	}
	m := &memReader{files: map[string]string{}}
	for i := 0; i < MaxCandidates/MaxCandidatesPerFragment+1; i++ {
		m.files[fmt.Sprintf("%s/n%03d.yaml", ChloggenDir, i)] = toks(MaxCandidatesPerFragment)
	}
	res := scan(t, m)
	if len(res.Candidates) != 0 || len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonTooManyCandidates {
		t.Fatalf("%d %+v", len(res.Candidates), res.Ledger)
	}
}

func TestNestingDepth(t *testing.T) {
	deep := head + "note: " + strings.Repeat("[", maxDepth+2) + "a" + strings.Repeat("]", maxDepth+2) + "\n"
	_, err := decodeFragment([]byte(deep))
	if err == nil || !strings.Contains(err.Error(), "nested too deep") {
		t.Fatalf("%v", err)
	}
	if res := scan(t, one(deep)); len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonParse {
		t.Fatalf("%+v", res)
	}
	// A scalar exactly at maxDepth passes the depth check, one deeper fails.
	nest := func(n int) *yaml.Node {
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(strings.Repeat("[", n)+"1"+strings.Repeat("]", n)), &root); err != nil {
			t.Fatal(err)
		}
		return &root
	}
	// document 0, n sequences 1..n, scalar n+1.
	if err := checkNode(nest(maxDepth-1), 0); err != nil {
		t.Fatal(err)
	}
	if err := checkNode(nest(maxDepth), 0); err == nil {
		t.Fatal("over the depth limit accepted")
	}
}
