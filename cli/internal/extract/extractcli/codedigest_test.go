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

// Every registered extractor's code digest must cover exactly the non-test Go
// files and the top-level reviewed *.json data files of its package, with the
// bytes on disk, and every file any non-test //go:embed directive in the
// package reads must be among them. A data file read through a separate embed
// that the digest's source set omits would otherwise be silently unattested.
func TestEveryExtractorDigestCoversItsPackageOnDisk(t *testing.T) {
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("empty catalog")
	}
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
		var want []string
		for _, pat := range []string{"*.go", "*.json"} {
			m, err := filepath.Glob(filepath.Join(disk, pat))
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range m {
				if !strings.HasSuffix(f, "_test.go") {
					want = append(want, path.Join(dir, filepath.Base(f)))
				}
			}
		}
		sort.Strings(want)
		var got []string
		covered := map[string]bool{}
		for _, f := range files {
			got = append(got, f.Path)
			covered[filepath.Base(f.Path)] = true
			data, err := os.ReadFile(filepath.Join(disk, filepath.Base(f.Path)))
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			sum := sha256.Sum256(data)
			if f.SHA256 != hex.EncodeToString(sum[:]) {
				t.Errorf("%s: %s: embedded bytes differ from the file on disk", id, f.Path)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: digest covers %v, package files are %v", id, got, want)
		}
		// Every file a non-test //go:embed in the package reads is covered.
		for _, f := range want {
			if !strings.HasSuffix(f, ".go") {
				continue
			}
			fh, err := os.Open(filepath.Join(disk, filepath.Base(f)))
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
						t.Errorf("%s: %s: embed pattern %q matches nothing (%v)", id, f, pat, err)
					}
					for _, e := range m {
						if st, err := os.Stat(e); err == nil && st.IsDir() {
							t.Errorf("%s: %s: embed pattern %q reads a directory, outside the digest", id, f, pat)
							continue
						}
						if strings.HasSuffix(e, "_test.go") {
							continue
						}
						if !covered[filepath.Base(e)] || filepath.Dir(e) != disk {
							t.Errorf("%s: %s embeds %s, which the code digest does not cover", id, f, e)
						}
					}
				}
			}
			fh.Close()
		}
	}
}
