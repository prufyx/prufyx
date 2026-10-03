// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"fmt"
	"reflect"
	"testing"
)

// TestSourceLine: every document and List item records the 1-based line of
// its own apiVersion key, 0 when it has none; the other provenance fields and
// the digest do not depend on it.
func TestSourceLine(t *testing.T) {
	raw := "# leading comment\n" +
		"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n" +
		"---\n" +
		"kind: Pod\nmetadata: {name: b}\napiVersion: v1\n" +
		"---\n" +
		"apiVersion: v1\nkind: List\nitems:\n" +
		"- apiVersion: batch/v1\n  kind: CronJob\n" +
		"- kind: Job\n  apiVersion: batch/v1\n" +
		"---\n" +
		"apiVersion: apps/v1\nkind: DeploymentList\nitems:\n- metadata: {name: web}\n"
	w, err := Decode("a.yaml", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range w.Documents {
		got = append(got, fmt.Sprintf("%d/%d:%d", d.Source.Document, d.Source.Item, d.Source.Line))
	}
	want := []string{"0/-1:2", "1/-1:8", "2/0:13", "2/1:16", "3/0:0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	again, err := Decode("a.yaml", []byte(raw))
	if err != nil || again.Documents[0].Source.Digest != w.Documents[0].Source.Digest {
		t.Fatal("digest changed between identical decodes")
	}

	json, err := Decode("b.json", []byte(`{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"Pod"}]}`))
	if err != nil || len(json.Documents) != 1 || json.Documents[0].Source.Line != 1 {
		t.Fatalf("json line: %+v %v", json.Documents, err)
	}
}
