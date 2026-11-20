// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogattest"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// The listed-entries extractors are exactly the reviewed rows the family
// admits: one per such row, none without a row, each attesting only its own row's component.
func TestCatalogListedExtractorsAreTheReviewedRows(t *testing.T) {
	if err := changelogentries.LoadError(); err != nil {
		t.Fatal(err)
	}
	cat := Catalog()
	want := map[string]bool{}
	for _, row := range changelogentries.Reviewed {
		id := changelogattest.ListedIDPrefix + row.Component
		// A row whose component the listed family does not admit (a CRD-family
		// component such as antrea) is refused by NewListed and has no
		// extractor; the catalog must not carry one for it.
		if purl, ok := changelogentries.ComponentPURL(row); ok {
			if f, _ := lineattest.LookupFamily(lineattest.FamilyChangelogListedEntries); !f.Admits(purl) {
				if _, has := cat[id]; has {
					t.Fatalf("extractor %s exists for a component the listed family does not admit", id)
				}
				continue
			}
		}
		want[id] = true
		spec, ok := cat[id]
		if !ok {
			t.Fatalf("no extractor for the reviewed row %s", row.Component)
		}
		if spec.Repo != row.Repo.Key {
			t.Fatalf("%s reads %s, the row names %s", id, spec.Repo, row.Repo.Key)
		}
		ex := spec.New(1)
		att, ok := ex.(extract.LineAttester)
		if !ok || len(att.AttestedFamilies()) != 1 || att.AttestedFamilies()[0] != lineattest.FamilyChangelogListedEntries {
			t.Fatalf("%s does not attest exactly the listed family", id)
		}
		purl, ok := changelogentries.ComponentPURL(row)
		if !ok || ex.(extract.ComponentAttester).AttestedComponent() != purl {
			t.Fatalf("%s attests %s, not the component of its row", id, ex.(extract.ComponentAttester).AttestedComponent())
		}
		if f, _ := lineattest.LookupFamily(lineattest.FamilyChangelogListedEntries); !f.Admits(purl) {
			t.Fatalf("the family does not admit %s", purl)
		}
	}
	for id := range cat {
		if strings.HasPrefix(id, changelogattest.ListedIDPrefix) && !want[id] {
			t.Fatalf("extractor %s has no reviewed row", id)
		}
	}
}
