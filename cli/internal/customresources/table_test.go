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

// reservedPin is the sha256 of the Go rendering (%#v) of ReservedGroups().
// A reserved group is recorded by a person, one reviewed change per group,
// and that change updates this pin. The project rows are not pinned: rows
// are added as data (the knowledge gate checks each added row with this
// package's loader), so a pin over them would move with every addition.
const reservedPin = "9bc2428bad6065e83b4bb4c6255aa8452283467a7f82ca11721890f96c08170c"

func TestReservedGroupsMatchPin(t *testing.T) {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%#v", ReservedGroups())))
	if got := hex.EncodeToString(sum[:]); got != reservedPin {
		t.Fatalf("reserved groups rendering sha256 %s, pinned %s: update the pin only together with a reviewed reserved-group record", got, reservedPin)
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
