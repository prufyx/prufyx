// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Every registered extractor's code digest must cover the non-test Go files
// of its package and only reviewed *.json data files at the package's top
// level, with the bytes on disk. Every such data file, and every file any
// non-test //go:embed directive in the package reads, must be covered by the
// digest of at least one id registered from that package: a data file read
// through an embed that no digest covers would otherwise be silently
// unattested. A package may give each id only the data file of its own
// (crd.version-removal: target-<project>.json; its own tests pin that each
// target file is covered by exactly its id).
func TestEveryExtractorDigestCoversItsPackageOnDisk(t *testing.T) {
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("empty catalog")
	}
	coveredBy := map[string]map[string]bool{} // package dir -> covered base names
	jsonIDs := map[string]map[string]int{}    // package dir -> data file -> ids covering it
	ids := map[string]int{}                   // package dir -> registered ids
	for id, spec := range cat {
		ex := spec.New(1)
		src, ok := ex.(extract.CodeSource)
		if !ok {
			t.Fatalf("%s: does not expose its source", id)
		}
		dir, own := src.SourceFiles()
		files, err := extract.CodeFiles(extract.SourceSet{Dir: dir, Files: own})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		disk := filepath.Join("..", strings.TrimPrefix(dir, "extract/"))
		if strings.TrimPrefix(dir, "extract/") == dir {
			t.Fatalf("%s: source dir %q is not under extract/", id, dir)
		}
		if coveredBy[disk] == nil {
			coveredBy[disk] = map[string]bool{}
			jsonIDs[disk] = map[string]int{}
		}
		ids[disk]++
		goFiles, err := filepath.Glob(filepath.Join(disk, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		covered := map[string]bool{}
		for _, f := range files {
			if path.Dir(f.Path) != dir {
				t.Errorf("%s: %s is not at the top level of %s", id, f.Path, dir)
			}
			base := path.Base(f.Path)
			if !strings.HasSuffix(base, ".go") && !strings.HasSuffix(base, ".json") || strings.HasSuffix(base, "_test.go") {
				t.Errorf("%s: %s is neither code nor a data file", id, f.Path)
			}
			covered[base] = true
			coveredBy[disk][base] = true
			if strings.HasSuffix(base, ".json") {
				jsonIDs[disk][base]++
			}
			data, err := os.ReadFile(filepath.Join(disk, base))
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			sum := sha256.Sum256(data)
			if f.SHA256 != hex.EncodeToString(sum[:]) {
				t.Errorf("%s: %s: embedded bytes differ from the file on disk", id, f.Path)
			}
		}
		for _, f := range goFiles {
			if !strings.HasSuffix(f, "_test.go") && !covered[filepath.Base(f)] {
				t.Errorf("%s: the digest does not cover %s", id, f)
			}
		}
	}
	// A data file is either shared by every id of its package or belongs to
	// exactly one of them: one id's digest never covers another id's data.
	for disk, files := range jsonIDs {
		for f, n := range files {
			if n != 1 && n != ids[disk] {
				t.Errorf("%s: %s is covered by %d of the package's %d ids", disk, f, n, ids[disk])
			}
		}
	}
	for disk, covered := range coveredBy {
		var want []string
		for _, pat := range []string{"*.go", "*.json"} {
			m, err := filepath.Glob(filepath.Join(disk, pat))
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range m {
				if !strings.HasSuffix(f, "_test.go") {
					want = append(want, filepath.Base(f))
				}
			}
		}
		sort.Strings(want)
		var got []string
		for f := range covered {
			got = append(got, f)
		}
		sort.Strings(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: the digests cover %v, package files are %v", disk, got, want)
		}
		// Every file a non-test //go:embed in the package reads is covered.
		for _, f := range want {
			if !strings.HasSuffix(f, ".go") {
				continue
			}
			fh, err := os.Open(filepath.Join(disk, f))
			if err != nil {
				t.Fatal(err)
			}
			sc := bufio.NewScanner(fh)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if !strings.HasPrefix(line, "//go:embed ") {
					continue
				}
				for _, pat := range strings.Fields(strings.TrimPrefix(line, "//go:embed ")) {
					m, err := filepath.Glob(filepath.Join(disk, pat))
					if err != nil || len(m) == 0 {
						t.Errorf("%s: %s: embed pattern %q matches nothing (%v)", disk, f, pat, err)
					}
					for _, e := range m {
						if st, err := os.Stat(e); err == nil && st.IsDir() {
							t.Errorf("%s: %s: embed pattern %q reads a directory, outside the digest", disk, f, pat)
							continue
						}
						if strings.HasSuffix(e, "_test.go") {
							continue
						}
						if !covered[filepath.Base(e)] || filepath.Dir(e) != disk {
							t.Errorf("%s: %s embeds %s, which no code digest covers", disk, f, e)
						}
					}
				}
			}
			fh.Close()
		}
	}
}

// digestOf is the code digest a run of the registered extractor records
// (extract.Run): the framework's source set and the extractor's own.
func digestOf(t *testing.T, id string) string {
	t.Helper()
	spec, ok := Catalog()[id]
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	dir, own := spec.New(1).(extract.CodeSource).SourceFiles()
	files, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: dir, Files: own})
	if err != nil {
		t.Fatal(err)
	}
	return extract.CodeDigest(files)
}

// The Kubernetes extractors' code digests are pinned: published rules and
// line attestations carry them, and a change elsewhere (a data file of
// another extractor, a new target) must not move them. A deliberate change
// to the framework or to one of these packages updates the pin, and every
// record that carries the old digest is re-derived.
func TestKubernetesCodeDigestsArePinned(t *testing.T) {
	for id, want := range map[string]string{
		"k8s.served-api-removal":   "sha256:7b94e1ed652afa63355671bd20e6f131da603822aa53cf8f45cf2790a00955e6",
		"k8s.feature-gate-removal": "sha256:42790ac0fe961d135e3843ef4096b795ca79ac931d009c65e54cfdbd417472eb",
	} {
		if got := digestOf(t, id); got != want {
			t.Errorf("%s: code digest %s, pinned %s", id, got, want)
		}
	}
}
