// SPDX-License-Identifier: AGPL-3.0-only

package docstables

import (
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Every row of a generated table has as many cells as its header: a value
// holding "|" is escaped, never a cell boundary.
func TestTablesAreWellFormed(t *testing.T) {
	boundary := regexp.MustCompile(`(^|[^\\])\|`)
	for _, f := range Generate() {
		cells := 0
		for _, line := range strings.Split(f.Content, "\n") {
			if !strings.HasPrefix(line, "|") {
				cells = 0
				continue
			}
			n := len(boundary.FindAllString(line, -1))
			if cells == 0 {
				cells = n
			} else if n != cells {
				t.Errorf("%s: %d cell boundaries, header has %d: %s", f.Path, n, cells, line)
			}
		}
	}
}

// Each target and each project of the data has exactly one row.
func TestOneRowPerEntry(t *testing.T) {
	files := Generate()
	for _, tg := range crdversions.Targets {
		if n := strings.Count(files[0].Content, "\n| `"+tg.ExtractorID()+"` |"); n != 1 {
			t.Errorf("%s: %d rows", tg.ExtractorID(), n)
		}
	}
	for _, p := range customresources.Projects() {
		if n := strings.Count(files[1].Content, "\n| `"+p.Slug+"` | "); n != 1+boolInt(p.Community()) {
			t.Errorf("%s: %d rows", p.Slug, n)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestCRDTargetsRendersRemoteChannelsAndEscapes(t *testing.T) {
	raw := []byte(`{"schema": "prufyx.io/crd-version-targets/v1", "targets": [
  {"project": "a", "name": "A", "repo": "github.com/x/a", "component": "pkg:github/x/a", "factProject": "a", "tagPrefixes": ["v", ""], "minFrom": "1.2",
   "paths": [{"path": "crds", "directory": true, "recursive": true, "match": "^(a|b)\\.yaml$", "guard": "crd"}, {"path": "extra.yaml", "optional": true}],
   "exclude": [], "remote": {"fromLine": "1.4", "kustomization": "config/kustomization.yaml", "repo": "github.com/x/b", "directory": "crd", "pins": [{"tag": "v1.0.0", "commit": "0123456789abcdef0123456789abcdef01234567"}]}},
  {"project": "c", "name": "C", "repo": "github.com/x/c", "component": "pkg:github/x/c", "factProject": "c", "tagPrefixes": [""], "minFrom": "0.1",
   "paths": [{"path": "std/crd.yaml"}], "exclude": [], "declaredChannel": "standard", "channels": [{"name": "experimental", "paths": [{"path": "exp/crd.yaml"}]}]}
]}`)
	targets, err := crdversions.LoadTargets(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := CRDTargets(targets)
	for _, want := range []string{
		"| `crd.version-removal.a` | CNCF | `github.com/x/a` | `vX.Y.Z`, then `X.Y.Z` | 1.2 | no | files matching `^(a\\|b)\\.yaml$` anywhere under `crds`, `extra.yaml` (when present); from 1.4: the files listed by `crd/kustomization.yaml` of `github.com/x/b`, at the tag `config/kustomization.yaml` names (1 pinned tags) | 0 |",
		"| `crd.version-removal.c` | CNCF | `github.com/x/c` | `X.Y.Z` | 0.1 | no | channel `standard` (declared): `std/crd.yaml`; channel `experimental`: `exp/crd.yaml` | 0 |",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("missing row %s in\n%s", want, got)
		}
	}
}
