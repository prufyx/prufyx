// SPDX-License-Identifier: AGPL-3.0-only

package intake

import "testing"

func TestDecodeDocumentsRejectsUnsupportedYAML(t *testing.T) {
	for name, raw := range map[string]string{
		"alias":          "a: &x 1\nb: *x\n",
		"merge key":      "a: {x: 1}\nb:\n  <<: {x: 2}\n",
		"custom tag":     "a: !secret x\n",
		"non-string key": "1: x\n",
		"duplicate key":  "a: 1\na: 2\n",
		"binary":         "a: !!binary aGVsbG8=\n",
	} {
		if _, err := DecodeDocuments([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	documents, err := DecodeDocuments([]byte("---\n---\na: true\nb: [1, \"x\", null]\n---\n{\"c\": false}\n"))
	if err != nil || len(documents) != 2 {
		t.Fatalf("documents=%v err=%v", documents, err)
	}
	first := documents[0].(map[string]any)
	if first["a"] != true || len(first["b"].([]any)) != 3 || documents[1].(map[string]any)["c"] != false {
		t.Fatalf("decoded %#v", documents)
	}
}
