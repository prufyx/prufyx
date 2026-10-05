// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// TestScopeRouteCannotReadCustomResourceSets: `assess --scope-input`
// evaluates only this package's attested community corpus. That corpus can
// never hold a rule over a custom-resource version set, so the scope route
// cannot pass one: no set fact is registered, no project of the reviewed
// custom-resource table has an identity here, and a set rule is refused at
// load even over a registered set fact.
func TestScopeRouteCannotReadCustomResourceSets(t *testing.T) {
	for _, d := range definitions() {
		if d.Type == constraintengine.FactSet || strings.HasSuffix(d.ID, ".custom_resource_versions_set") {
			t.Fatalf("community corpus registers %s (%s)", d.ID, d.Type)
		}
	}
	b := testBundle(t)
	for _, p := range customresources.Projects() {
		for _, identity := range b.identities {
			if identity.Component == p.Component {
				t.Fatalf("custom-resource project %s has a community identity", p.Slug)
			}
		}
	}

	registryRaw, err := packaged.ReadFile("data/projects.json")
	if err != nil {
		t.Fatal(err)
	}
	packRaw, err := packaged.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadRaw(registryRaw, packRaw, definitions()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	const setFact = "component.loki.custom_resource_versions_set"
	var pack map[string]any
	if err := json.Unmarshal(packRaw, &pack); err != nil {
		t.Fatal(err)
	}
	entries := pack["entries"].([]any)
	// insert places entry after the last loki entry, keeping the
	// project/rule order the loader requires.
	last := -1
	for i, item := range entries {
		if item.(map[string]any)["project"] == "loki" {
			last = i
		}
	}
	loki := entries[last].(map[string]any)
	insert := func(entry map[string]any) []byte {
		t.Helper()
		edited := map[string]any{}
		for k, v := range pack {
			edited[k] = v
		}
		edited["entries"] = append(append(append([]any{}, entries[:last+1]...), entry), entries[last+1:]...)
		raw, err := json.Marshal(edited)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	const id = "loki.zz-custom-resource-version"
	// Control: a copy of the last loki rule under the new id loads, so the
	// position and id are admissible.
	copied := map[string]any{"project": "loki", "description": loki["description"], "requiredFacts": loki["requiredFacts"], "rule": map[string]any{}}
	for k, v := range loki["rule"].(map[string]any) {
		copied["rule"].(map[string]any)[k] = v
	}
	copied["rule"].(map[string]any)["id"] = id
	if _, err := loadRaw(registryRaw, insert(copied), definitions()); err != nil {
		t.Fatalf("control entry refused: %v", err)
	}
	rule := map[string]any{
		"id": id, "operator": "forbid_set_member",
		"subject":      loki["rule"].(map[string]any)["subject"],
		"setCondition": map[string]any{"side": "proposed", "component": lokiComponent, "factId": setFact, "members": []string{"loki.grafana.com/v1beta1/LokiStack"}},
		"evidence":     loki["rule"].(map[string]any)["evidence"],
		"reasonCode":   "CRD_VERSION_NOT_SERVED", "nextAction": "change the apiVersion",
	}
	withSetRule := insert(map[string]any{"project": "loki", "description": "Test-only set rule.", "rule": rule,
		"requiredFacts": []any{map[string]any{"side": "proposed", "id": setFact, "component": lokiComponent, "type": "set", "enumTokens": nil, "description": "Test-only set."}}})
	registered := append(definitions(), constraintengine.FactDefinition{ID: setFact, Component: lokiComponent, Type: constraintengine.FactSet})
	for name, defs := range map[string][]constraintengine.FactDefinition{"unregistered set fact": definitions(), "registered set fact": registered} {
		if _, err := loadRaw(registryRaw, withSetRule, defs); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: a set rule loaded into the community corpus: %v", name, err)
		}
	}
}
