// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// variantPack returns the shipped pack with its first entry rewritten by
// edit, which receives the entry's members as raw JSON text.
func variantPack(t *testing.T, edit func(members map[string]string) string) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(doc["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(entries[0], &members); err != nil {
		t.Fatal(err)
	}
	text := map[string]string{}
	for k, v := range members {
		text[k] = string(v)
	}
	entries[0] = json.RawMessage(edit(text))
	joined := make([][]byte, len(entries))
	for i, e := range entries {
		joined[i] = e
	}
	doc["entries"] = json.RawMessage("[" + string(bytes.Join(joined, []byte(","))) + "]")
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPackRefusesCaseVariantMembers: struct decoding matches member names
// without regard to case and keeps the last, so an entry holding "rule"
// and "Rule" (or a repeated member) has two readings. Admission refuses it
// at every depth.
func TestPackRefusesCaseVariantMembers(t *testing.T) {
	landscape, _ := packagedFiles.ReadFile("data/landscape-projects.json")
	priority, _ := packagedFiles.ReadFile("data/priority-portfolio.json")
	shipped, _ := packagedFiles.ReadFile("data/rules.json")
	if _, err := CheckPackFiles(landscape, priority, shipped); err != nil {
		t.Fatalf("the shipped pack is refused: %v", err)
	}
	object := func(m map[string]string, extra string) string {
		return `{"project":` + m["project"] + `,"description":` + m["description"] + `,"requiredFacts":` + m["requiredFacts"] + `,` + extra + `}`
	}
	for name, edit := range map[string]func(map[string]string) string{
		"rule and Rule": func(m map[string]string) string {
			return object(m, `"rule":`+m["rule"]+`,"Rule":`+m["rule"])
		},
		"repeated rule": func(m map[string]string) string {
			return object(m, `"rule":`+m["rule"]+`,"rule":`+m["rule"])
		},
		"Description": func(m map[string]string) string {
			return object(m, `"rule":`+m["rule"]+`,"Description":`+m["description"])
		},
		"fact ID": func(m map[string]string) string {
			facts := strings.Replace(m["requiredFacts"], `"id":`, `"ID":"x","id":`, 1)
			return `{"project":` + m["project"] + `,"description":` + m["description"] + `,"requiredFacts":` + facts + `,"rule":` + m["rule"] + `}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			pack := variantPack(t, edit)
			if _, err := CheckPackFiles(landscape, priority, pack); err == nil {
				t.Fatal("a pack with a case-variant or repeated member was admitted")
			}
			if _, _, err := AdmittedPackView(pack); err == nil {
				t.Fatal("AdmittedPackView accepted the pack")
			}
		})
	}
}

// TestAdmittedPackView: the view holds every top-level member but entries,
// and one re-encoded entry per pack entry.
func TestAdmittedPackView(t *testing.T) {
	shipped, _ := packagedFiles.ReadFile("data/rules.json")
	members, entries, err := AdmittedPackView(shipped)
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := json.Unmarshal(shipped, &pack); err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(pack.Entries) || members["entries"] != nil || members["schema"] == nil || members["revision"] == nil {
		t.Fatalf("view: %d entries, members %v", len(entries), members)
	}
	again, err := AdmittedEntry(entries[0])
	if err != nil || !bytes.Equal(again, entries[0]) {
		t.Fatalf("AdmittedEntry is not stable: %v", err)
	}
}

// The external-bundle scanner folds member names exactly as struct
// decoding matches them: "ſtate" (long s) is "state".
func TestExternalScanFoldsLikeStructDecoding(t *testing.T) {
	for _, doc := range []string{`{"state":"a","State":"b"}`, "{\"state\":\"a\",\"ſtate\":\"b\"}", "{\"kind\":\"a\",\"Kind\":\"b\"}"} {
		if scanExternalJSON([]byte(doc)) == nil {
			t.Fatalf("%s accepted", doc)
		}
	}
	if err := scanExternalJSON([]byte(`{"state":"a","stats":"b"}`)); err != nil {
		t.Fatalf("distinct names refused: %v", err)
	}
}
