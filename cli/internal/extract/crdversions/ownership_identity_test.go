// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import "testing"

func TestRemovalDefinitionsFailClosed(t *testing.T) {
	f := &CRD{Name: "alphas." + synthGroup, Group: synthGroup, Kind: "Alpha", Versions: []CRDVersion{{Name: "v1beta1", Served: true}, {Name: "v1", Served: true}}}
	later := &CRD{Name: f.Name, Group: f.Group, Kind: f.Kind, Versions: []CRDVersion{{Name: "v1", Served: true}}}
	rm := Removal{CRD: f.Name, Member: synthGroup + "/v1beta1/Alpha", Version: "v1beta1", FromTag: "v1.0.0", Reason: ReasonAbsent}
	state := func(c *CRD) *tagState { return &tagState{byName: map[string]*CRD{c.Name: c}} }
	for _, name := range []string{"missing-source", "wrong-member", "wrong-later-kind", "missing-later", "wrong-cited-kind", "earlier-missing-version", "earlier-unserved-version", "later-still-served", "wrong-removal-reason"} {
		t.Run(name, func(t *testing.T) {
			a, b := *f, *later
			fa, ta := state(&a), state(&b)
			r := rm
			states := map[string]*tagState{r.FromTag: fa}
			switch name {
			case "missing-source":
				delete(states, r.FromTag)
			case "wrong-member":
				r.Member = synthGroup + "/v1beta1/Other"
			case "wrong-later-kind":
				b.Kind = "Other"
			case "missing-later":
				ta.byName = map[string]*CRD{}
			case "wrong-cited-kind":
				c := a
				c.Kind = "Other"
				states[r.FromTag] = state(&c)
			case "earlier-missing-version":
				a.Versions = []CRDVersion{{Name: "v1", Served: true}}
			case "earlier-unserved-version":
				a.Versions = []CRDVersion{{Name: "v1beta1", Served: false}, {Name: "v1", Served: true}}
			case "later-still-served":
				b.Versions = append(b.Versions, CRDVersion{Name: "v1beta1", Served: true})
			case "wrong-removal-reason":
				r.Reason = ReasonUnserved
			}
			if _, _, err := removalDefinitions(states, fa, ta, []Removal{r}); err == nil {
				t.Fatal("contradictory identity accepted")
			}
		})
	}
}
