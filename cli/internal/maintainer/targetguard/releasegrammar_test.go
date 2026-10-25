// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"slices"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Switching between tag prefixes and a release scheme changes how a target
// reads its tags: one identity change, reviewed once, not a loss of every
// prefix. Dropping the grammar altogether still narrows.
func TestReleaseGrammarSwitch(t *testing.T) {
	prefixes := func(ps ...string) crdversions.Target {
		return crdversions.Target{Project: "p", Repo: "github.com/o/p", Component: "pkg:github/o/p", TagPrefixes: ps}
	}
	scheme := crdversions.Target{Project: "p", Repo: "github.com/o/p", Component: "pkg:github/o/p", ReleaseScheme: crdversions.SchemeCalverEdge}
	none := crdversions.Target{Project: "p", Repo: "github.com/o/p", Component: "pkg:github/o/p"}
	for _, c := range []struct {
		name       string
		base, head crdversions.Target
		want       []Removal
	}{
		{"prefixes to scheme", prefixes("v", ""), scheme, []Removal{{Kind: KindIdentity, Project: "p", Detail: "releaseGrammar:scheme:calver-edge"}}},
		{"scheme to prefixes", scheme, prefixes("v"), []Removal{{Kind: KindIdentity, Project: "p", Detail: "releaseGrammar:tagPrefixes"}}},
		{"scheme unchanged", scheme, scheme, nil},
		{"prefixes unchanged", prefixes("v"), prefixes("v"), nil},
		{"scheme removed", scheme, none, []Removal{{Kind: KindNarrowed, Project: "p", Detail: "releaseScheme:calver-edge"}}},
		{"prefixes removed", prefixes("v"), none, []Removal{{Kind: KindNarrowed, Project: "p", Detail: "tagPrefix:v"}}},
		{"prefix dropped", prefixes("v", ""), prefixes("v"), []Removal{{Kind: KindNarrowed, Project: "p", Detail: "tagPrefix:"}}},
		{"grammar added", none, scheme, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Diff(Inputs{Targets: []crdversions.Target{c.base}}, Inputs{Targets: []crdversions.Target{c.head}})
			if !slices.EqualFunc(got, c.want, func(a, b Removal) bool { return a.id() == b.id() }) {
				t.Fatalf("Diff = %+v, want %+v", got, c.want)
			}
		})
	}
}
