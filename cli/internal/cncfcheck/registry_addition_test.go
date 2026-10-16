// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestAddedFactDefinitionIsInert: a fact definition no rule reads changes no
// verdict. Every case of the reviewed vectors gives the same report under the
// shipped registry and under the shipped registry plus one synthetic
// definition (the pack's registryDigest moved to match), apart from the
// registry and pack digests the report names.
func TestAddedFactDefinitionIsInert(t *testing.T) {
	landscape, err := packagedFiles.ReadFile("data/landscape-projects.json")
	if err != nil {
		t.Fatal(err)
	}
	priority, err := packagedFiles.ReadFile("data/priority-portfolio.json")
	if err != nil {
		t.Fatal(err)
	}
	packRaw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := assemble(landscape, priority, packRaw, compiledDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	added := constraintengine.FactDefinition{ID: "component.argo_cd.synthetic_registry_addition", Component: "pkg:github/argoproj/argo-cd", Type: constraintengine.FactBool}
	headDefinitions := append(compiledDefinitions(), added)
	headRegistry, err := constraintengine.NewCompiledRegistry(headDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	baseDigest := base.registry.Digest()
	if bytes.Count(packRaw, []byte(baseDigest)) != 1 {
		t.Fatal("the pack names its registry digest other than exactly once")
	}
	headPack := bytes.Replace(packRaw, []byte(baseDigest), []byte(headRegistry.Digest()), 1)
	head, err := assemble(landscape, priority, headPack, headDefinitions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assemble(landscape, priority, headPack, compiledDefinitions()); err == nil {
		t.Fatal("the shipped registry admits a pack naming another registry digest")
	}
	normalise := strings.NewReplacer(headRegistry.Digest(), baseDigest, digest(headPack), digest(packRaw))
	clock := reviewClock(t)
	cases, evaluated, decided := 0, 0, 0
	for _, vector := range reviewedVectors(t) {
		for _, scenario := range vector.Cases {
			want, wantErr := base.check(vector.Project, vector.RuleID, scenario.Input, clock)
			got, gotErr := head.check(vector.Project, vector.RuleID, scenario.Input, clock)
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("%s/%s: error %v under the shipped registry, %v with the addition", vector.RuleID, scenario.Name, wantErr, gotErr)
			}
			wantRaw, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			gotRaw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if normalise.Replace(string(gotRaw)) != string(wantRaw) {
				t.Fatalf("%s/%s: the report changes with an added fact definition no rule reads", vector.RuleID, scenario.Name)
			}
			cases++
			if wantErr == nil {
				evaluated++
				for _, claim := range want.Check.Claims {
					if claim.Status != "UNKNOWN" {
						decided++
					}
				}
			}
		}
	}
	if cases == 0 || evaluated == 0 || decided == 0 {
		t.Fatalf("%d vector cases, %d evaluated, %d decided claims: the comparison is empty", cases, evaluated, decided)
	}
	t.Logf("%d vector cases, %d evaluated, %d decided claims", cases, evaluated, decided)
}
