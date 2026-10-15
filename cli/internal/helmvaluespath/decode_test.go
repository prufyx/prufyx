// SPDX-License-Identifier: AGPL-3.0-only

package helmvaluespath

import (
	"slices"
	"testing"
)

func TestDecodeYAML(t *testing.T) {
	for _, bad := range []string{
		"a: &x 1\nb: *x\n",
		"<<: {a: 1}\n",
		"a: 1\na: 2\n",
		"1: x\n",
		"on: x\n",
		"yes: x\n",
		"~: x\n",
		"a: !custom x\n",
		"a: 1\n---\nb: 2\n",
		"[unclosed\n",
		"\"\": x\n",
		"\"a\\0b\": x\n",
		"a: {\"\\x00\": 1}\n",
	} {
		if _, _, err := DecodeYAML([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"", "---\n", "\"on\": x\n", "a: yes\n", "a: [1, {b: null}]\n", "\"a.b\": 1\n", "\"a b\": {_c: 1}\n"} {
		if _, _, err := DecodeYAML([]byte(good)); err != nil {
			t.Errorf("refused %q: %v", good, err)
		}
	}
	root, _, err := DecodeYAML([]byte("a: 1\nkubeVersion: x\n"))
	if err != nil || MappingLine(root, "kubeVersion") != 2 || MappingLine(root, "b") != 0 {
		t.Fatalf("mapping line: %v", err)
	}
}

func TestValuePaths(t *testing.T) {
	_, v, err := DecodeYAML([]byte("a: {b: 1, c: null, d: [1, {e: 2}]}\n\"x.y\": {z: 1}\nnn: null\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range ValuePaths(v) {
		got = append(got, DisplayPath(p))
		if _, ok := ValueAt(v, p); !ok {
			t.Fatalf("%v does not read back", p)
		}
	}
	if want := []string{"a", "a.b", "a.d", "x.y", "x.y.z"}; !slices.Equal(got, want) {
		t.Fatalf("paths %v, want %v", got, want)
	}
	if m, _ := Member([]string{"x.y", "z"}); m != "k..x_2Ey..z" {
		t.Fatalf("member %q", m)
	}
	if _, ok := ValueAt(v, []string{"a", "c"}); !ok {
		t.Fatal("null value does not exist")
	}
	if _, ok := ValueAt(v, []string{"a", "b", "c"}); ok {
		t.Fatal("path through a scalar exists")
	}
	if DisplayPath(nil) != "(root)" {
		t.Fatal("root")
	}
}
