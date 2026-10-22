// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// A new project's row may list only kinds the newest release defines: a kind
// of a shared group that the existing owner ships must not be claimable.
func TestCheckRowKindsRefusesKindTheReleaseDoesNotDefine(t *testing.T) {
	inv := &crdversions.Inventory{CRDs: []crdversions.CRD{
		{Name: "alphas.shared.example.org", Group: "shared.example.org", Kind: "Alpha"},
	}}
	row := func(g customresources.Group) customresources.Project {
		return customresources.Project{Slug: "pa", Groups: []customresources.Group{g}}
	}
	for _, tc := range []struct {
		name string
		inv  *crdversions.Inventory
		row  customresources.Project
		want string // error substring; empty is accepted
	}{
		{"defined kind", inv, row(customresources.Group{Name: "shared.example.org", Kinds: []string{"Alpha"}}), ""},
		{"whole group", inv, row(customresources.Group{Name: "shared.example.org"}), ""},
		{"kind not defined", inv, row(customresources.Group{Name: "shared.example.org", Kinds: []string{"Alpha", "Beta"}}), "the row lists kind Beta of shared.example.org, which the newest release does not define"},
		{"group not defined", inv, row(customresources.Group{Name: "other.example.org", Kinds: []string{"Alpha"}}), "kind Alpha of other.example.org"},
		{"no inventory", nil, row(customresources.Group{Name: "shared.example.org", Kinds: []string{"Alpha"}}), "no inventory"},
	} {
		err := checkRowKinds(tc.inv, tc.row)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
	}
}
