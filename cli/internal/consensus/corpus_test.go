// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// The synthetic fixture: two releases of the Kubernetes repository.
const (
	corpusDir   = "testdata/injection"
	fromCommit  = "0000000000000000000000000000000000014000"
	toCommit    = "0000000000000000000000000000000000014100"
	fromTag     = "v1.40.0"
	toTag       = "v1.41.0"
	changelogAt = "CHANGELOG/CHANGELOG-1.41.md"
)

type corpusCase struct {
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Claims      []Claim `json:"claims"`
	Expect      struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	} `json:"expect"`
	Tamper string `json:"tamper"`
}

// copyTree copies a directory tree.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// fixtureWith returns a fixture tree: the shared base with changelog as
// the later release's release notes.
func fixtureWith(t *testing.T, changelog []byte) string {
	t.Helper()
	root := t.TempDir()
	copyTree(t, filepath.Join(corpusDir, "base"), root)
	p := filepath.Join(root, "github.com", "kubernetes", "kubernetes", "commits", toCommit, filepath.FromSlash(changelogAt))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, changelog, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// honestBundle pins the release notes of a fixture as a correct pipeline
// would: the claims are the only thing an attacker controls besides the
// text itself.
func honestBundle(t *testing.T, root string, claims []Claim) *Bundle {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "github.com", "kubernetes", "kubernetes", "commits", toCommit, filepath.FromSlash(changelogAt)))
	if err != nil {
		t.Fatal(err)
	}
	normalised := FileDigest(nil)
	if n, err := Normalise(src, SectionSpec{Repo: KubernetesRepo, Path: changelogAt, Version: toTag}); err == nil {
		normalised = n.Digest()
	}
	return &Bundle{
		Schema: BundleSchema,
		Source: Source{Repo: KubernetesRepo, Commit: toCommit, Path: changelogAt, FileSHA256: FileDigest(src),
			Section: toTag, NormaliserVersion: NormaliserVersion, NormalisedSHA256: normalised},
		FromRelease: FromRelease{Repo: KubernetesRepo, Commit: fromCommit, Tag: fromTag},
		ToRelease:   ToRelease{Tag: toTag},
		Claims:      claims,
	}
}

func fixtureInputs(root string) Inputs {
	r := extract.FixtureReader{Root: root}
	return Inputs{Reader: r, Tags: r, History: FixtureHistory{Root: root}, Inventory: &ExtractorInventories{Reader: r}}
}

func verifyFixture(t *testing.T, root string, b *Bundle) *Report {
	t.Helper()
	rep, err := Verify(context.Background(), b, fixtureInputs(root))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return rep
}

func loadCases(t *testing.T, kind string) map[string]corpusCase {
	t.Helper()
	dirs, err := os.ReadDir(filepath.Join(corpusDir, kind))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]corpusCase{}
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(corpusDir, kind, d.Name(), "case.json"))
		if err != nil {
			t.Fatal(err)
		}
		var c corpusCase
		if err := strictjson.Decode(raw, &c); err != nil {
			t.Fatalf("%s: %v", d.Name(), err)
		}
		out[d.Name()] = c
	}
	return out
}

func runCase(t *testing.T, kind, id string, c corpusCase) *Report {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(corpusDir, kind, id, "CHANGELOG-1.41.md"))
	if err != nil {
		t.Fatal(err)
	}
	root := fixtureWith(t, text)
	b := honestBundle(t, root, c.Claims)
	switch c.Tamper {
	case "":
	case "fileSha256":
		b.Source.FileSHA256 = FileDigest([]byte("other bytes"))
	case "fromCommit":
		b.FromRelease.Commit = toCommit
	default:
		t.Fatalf("%s: unknown tamper %q", id, c.Tamper)
	}
	return verifyFixture(t, root, b)
}

func sortedKeys(m map[string]corpusCase) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every injection case yields zero verified claims, each for the reason
// the case was written to exercise.
func TestInjectionCorpusZeroVerified(t *testing.T) {
	cases := loadCases(t, "cases")
	if len(cases) < 24 {
		t.Fatalf("%d injection cases, want at least 24", len(cases))
	}
	categories := map[string]bool{}
	verified := 0
	for _, id := range sortedKeys(cases) {
		c := cases[id]
		categories[c.Category] = true
		rep := runCase(t, "cases", id, c)
		for _, cl := range rep.Claims {
			if cl.Verdict == VerdictVerified {
				verified++
				t.Errorf("%s: claim %s verified (%s)", id, cl.ID, c.Description)
				continue
			}
			if cl.Verdict != c.Expect.Verdict || cl.Reason != c.Expect.Reason {
				t.Errorf("%s: claim %s is %s:%s (%s), want %s:%s", id, cl.ID, cl.Verdict, cl.Reason, cl.Detail, c.Expect.Verdict, c.Expect.Reason)
			}
		}
		if rep.Summary.Verified != 0 {
			t.Errorf("%s: summary counts %d verified", id, rep.Summary.Verified)
		}
	}
	if verified != 0 {
		t.Fatalf("%d injected claims verified, want 0", verified)
	}
	if len(categories) < 16 {
		t.Fatalf("%d categories, want at least 16", len(categories))
	}
}

// Real-shaped synthetic removals, present in the synthetic inventory and
// referencing a pull request of the range, verify.
func TestPositiveControlsVerify(t *testing.T) {
	controls := loadCases(t, "controls")
	if len(controls) < 6 {
		t.Fatalf("%d positive controls, want at least 6", len(controls))
	}
	for _, id := range sortedKeys(controls) {
		c := controls[id]
		rep := runCase(t, "controls", id, c)
		if !rep.AllVerified() {
			raw, _ := json.MarshalIndent(rep.Claims, "", "  ")
			t.Errorf("%s: not every claim verified:\n%s", id, raw)
			continue
		}
		for _, cl := range rep.Claims {
			if len(cl.Citations) != len(cl.Names) || len(cl.Provenance) == 0 || cl.Inventory == nil || cl.Inventory.FromDigest == "" || cl.Inventory.ToDigest == "" {
				t.Errorf("%s: verified claim %s without its evidence: %+v", id, cl.ID, cl)
			}
		}
	}
}
