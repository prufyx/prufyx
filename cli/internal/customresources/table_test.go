// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// reservedRecordPins holds, per record, the sha256 of the Go rendering (%#v)
// of a record of the list as it was reviewed. It protects what is there: an
// edit or a removal of a pinned record fails the test. It does not bound the
// list: a record added by an owner-signed onboarding batch is not in the map
// and needs no code change, because the batch's signature covers the table
// bytes (the knowledge gate refuses a record that is not born with its new
// owner row). The properties of every record, pinned or not, are checked by
// TestReservedGroupsAreOwnedByTheirRepository.
var reservedRecordPins = map[string]string{
	"cluster.x-k8s.io":            "b4cbef92c90e67b245babd328d7b954f009564a88ea6cc0c45d932e66eb38035",
	"clusterctl.cluster.x-k8s.io": "f51c3bd659e3d6196246137e3b461592f082d5c89f8b73d70c7e9a6b779055e8",
	"gateway.networking.k8s.io":   "c61ad38bbc72700bb679af4b564c539d7313e99bf2c81d1dce13231831d034fc",
	"gateway.networking.x-k8s.io": "5bd00372ea374f3c7f887064800baa7a106cf5e2580dd27deac299e6a2c88ad5",
	"kueue.x-k8s.io":              "24c69edeed01c0e704a368caf499a34f8fb6b89c93627ea11aa935c9b3f2841d",
	"runtime.cluster.x-k8s.io":    "9ed91e90660a9229946ad5b21a8046884886eef80d695bf0ad5c17e23823637a",
}

// checkReservedPins returns one message per pinned record that is missing
// from records or differs from its reviewed rendering.
func checkReservedPins(records []ReservedGroup, pins map[string]string) []string {
	have := map[string]string{}
	for _, r := range records {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%#v", r)))
		have[r.Name] = hex.EncodeToString(sum[:])
	}
	var out []string
	for name, want := range pins {
		got, ok := have[name]
		switch {
		case !ok:
			out = append(out, name+": pinned record is removed")
		case got != want:
			out = append(out, name+": pinned record changed")
		}
	}
	return out
}

func TestReservedGroupsKeepTheirReviewedRecords(t *testing.T) {
	records := ReservedGroups()
	if msgs := checkReservedPins(records, reservedRecordPins); len(msgs) != 0 {
		t.Fatalf("%v: a record is changed only by a reviewed change that updates its pin", msgs)
	}
	// Negative: an edit of an existing record, and its removal, are caught.
	for i := range records {
		edited := ReservedGroups()
		edited[i].Reason += " (edited)"
		if msgs := checkReservedPins(edited, reservedRecordPins); len(msgs) == 0 && reservedRecordPins[edited[i].Name] != "" {
			t.Errorf("edit of %s not caught", edited[i].Name)
		}
		removed := append(ReservedGroups()[:i:i], ReservedGroups()[i+1:]...)
		if msgs := checkReservedPins(removed, reservedRecordPins); len(msgs) == 0 && reservedRecordPins[records[i].Name] != "" {
			t.Errorf("removal of %s not caught", records[i].Name)
		}
	}
	// A record added later (not pinned) is accepted by the pin check.
	added := append(ReservedGroups(), ReservedGroup{Name: "new.synthetic.x-k8s.io", Owner: "x", Repository: "https://github.com/o/x", Reason: "r"})
	if msgs := checkReservedPins(added, reservedRecordPins); len(msgs) != 0 {
		t.Errorf("added record refused: %v", msgs)
	}
	// Every pinned record is still in the table.
	for name := range reservedRecordPins {
		found := false
		for _, r := range records {
			found = found || r.Name == name
		}
		if !found {
			t.Errorf("pin %s has no record", name)
		}
	}
}

// table.json has one spelling: the canonical encoding of what it decodes to.
func TestTableFileIsCanonical(t *testing.T) {
	want, err := encodeTable(table, reserved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tableJSON, want) {
		t.Fatal("table.json is not in canonical form (two-space indent, fields in schema order, final newline)")
	}
}

func TestLoadTableRefusesBadDocuments(t *testing.T) {
	mutate := func(f func(d map[string]any)) []byte {
		var d map[string]any
		if err := json.Unmarshal(tableJSON, &d); err != nil {
			t.Fatal(err)
		}
		f(d)
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	project := func(d map[string]any, slug string) map[string]any {
		for _, p := range d["projects"].([]any) {
			if p.(map[string]any)["slug"] == slug {
				return p.(map[string]any)
			}
		}
		t.Fatalf("no project %s", slug)
		return nil
	}
	group := func(d map[string]any, slug string) map[string]any {
		return project(d, slug)["groups"].([]any)[0].(map[string]any)
	}
	if _, _, err := LoadTable(mutate(func(map[string]any) {})); err != nil {
		t.Fatalf("round trip refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"wrong schema", mutate(func(d map[string]any) { d["schema"] = "prufyx.io/custom-resource-table/v0" }), "schema"},
		{"unknown field", mutate(func(d map[string]any) { project(d, "antrea")["kinds"] = []any{} }), "unknown field"},
		{"empty kinds", mutate(func(d map[string]any) { group(d, "antrea")["kinds"] = []any{} }), "does not validate"},
		{"bad kind", mutate(func(d map[string]any) { group(d, "antrea")["kinds"] = []any{"Bad kind"} }), "does not validate"},
		{"unsorted kinds", mutate(func(d map[string]any) { group(d, "antrea")["kinds"] = []any{"Beta", "Alpha"} }), "does not validate"},
		{"duplicate kinds", mutate(func(d map[string]any) { group(d, "antrea")["kinds"] = []any{"Alpha", "Alpha"} }), "does not validate"},
		{"kinds of a reserved group", mutate(func(d map[string]any) { group(d, "kueue")["kinds"] = []any{"Workload"} }), "does not validate"},
		{"trailing data", append(append([]byte(nil), tableJSON...), []byte("{}")...), "trailing data"},
		{"no projects", mutate(func(d map[string]any) { d["projects"] = []any{} }), "no projects"},
		{"cncf with upstream", mutate(func(d map[string]any) {
			project(d, "antrea")["upstream"] = project(d, "cluster-api")["upstream"]
		}), "upstream"},
		{"community without upstream", mutate(func(d map[string]any) { delete(project(d, "cluster-api"), "upstream") }), "upstream"},
		{"unpinned source", mutate(func(d map[string]any) {
			project(d, "antrea")["groups"].([]any)[0].(map[string]any)["source"] = "https://github.com/antrea-io/antrea/blob/main/x.yaml"
		}), "does not validate"},
		{"reserved record without owner listing", mutate(func(d map[string]any) {
			r := d["reserved"].([]any)
			d["reserved"] = append(r, map[string]any{"name": "zz.x-k8s.io", "owner": "kueue", "repository": "https://github.com/kubernetes-sigs/kueue", "reason": "a record its owner does not list"})
		}), "does not validate"},
	} {
		if _, _, err := LoadTable(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// A listing with kinds survives the strict loader and the canonical encoder
// byte for byte, a listing without kinds encodes without the member, and the
// strict loader reads kinds back non-nil.
func TestTableKindsRoundTrip(t *testing.T) {
	src := func(slug string) string {
		return "https://github.com/x/" + slug + "/blob/0123456789abcdef0123456789abcdef01234567/crds/" + slug + ".yaml"
	}
	projects := []Project{
		{Slug: "a", Catalog: CatalogCNCF, FactProject: "a", Component: "pkg:github/x/a", Groups: []Group{{Name: "shared.example.io", Source: src("a"), Kinds: []string{"Alpha", "Beta"}}, {Name: "whole.example.io", Source: src("a")}}},
		{Slug: "b", Catalog: CatalogCNCF, FactProject: "b", Component: "pkg:github/x/b", Groups: []Group{{Name: "shared.example.io", Source: src("b"), Kinds: []string{"Gamma"}}}},
	}
	raw, err := CanonicalTable(projects, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), `"kinds"`); n != 2 {
		t.Fatalf("%d kinds members in\n%s", n, raw)
	}
	loaded, _, err := LoadTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalTable(loaded, nil)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("round trip differs: %v", err)
	}
	if loaded[0].Groups[1].Kinds != nil || len(loaded[0].Groups[0].Kinds) != 2 {
		t.Fatalf("kinds read back as %v / %v", loaded[0].Groups[0].Kinds, loaded[0].Groups[1].Kinds)
	}
}
