// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestUnifiedDiffGolden(t *testing.T) {
	long := "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: a\n  labels:\n    one: x\n    two: x\n    three: x\n" +
		"    four: x\n    five: x\n    six: x\n    seven: x\n    eight: x\nspec:\n  schedule: \"* * * * *\"\n---\n" +
		"apiVersion: batch/v1beta1 # second\nkind: CronJob\nmetadata: {name: b, labels: {one: x}}\n"
	cases := []struct {
		name     string
		src      string
		requests []Request
	}{
		{name: "separate-hunks", src: long, requests: []Request{setRequest("value", "batch/v1beta1", "batch/v1", "apiVersion")}},
		{name: "merged-hunk", src: long, requests: []Request{
			setRequest("value", "x", "y", "metadata", "labels", "one"),
			setRequest("value", "x", "y", "metadata", "labels", "seven"),
			setRequest("key", "", "Two", "metadata", "labels", "two"),
		}},
		{name: "two-edits-one-line", src: long, requests: []Request{
			setRequest("key", "", "nom", "metadata", "name"),
			setRequest("value", "b", "'bee'", "metadata", "name"),
		}},
		{name: "no-final-newline", src: "a: 1\nb: 2\nc: 3", requests: []Request{setRequest("value", "3", "4", "c")}},
		{name: "crlf", src: "a: 1\r\nb: 2\r\nc: 3\r\n", requests: []Request{setRequest("value", "2", "\"two\"", "b")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := Plan("manifests/cron.yaml", []byte(tc.src), tc.requests, Options{})
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			golden := filepath.Join("testdata", "diff", tc.name+".golden")
			if *update {
				if err := os.WriteFile(golden, []byte(plan.Diff), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Diff != string(want) {
				t.Fatalf("diff differs from %s:\n%s", golden, plan.Diff)
			}
			// The same plan renders the same bytes every time.
			again, _ := Plan("manifests/cron.yaml", []byte(tc.src), tc.requests, Options{})
			if again.Diff != plan.Diff {
				t.Fatal("diff is not deterministic")
			}
		})
	}
	t.Run("no edits", func(t *testing.T) {
		diff, err := UnifiedDiff("x.yaml", []byte("a: b\n"), nil)
		if err != nil || diff != "" {
			t.Fatalf("%q %v", diff, err)
		}
	})
	t.Run("invalid edits", func(t *testing.T) {
		for _, edits := range [][]Edit{
			{{StartByte: 3, EndByte: 9, Replacement: "x"}},
			{{StartByte: 3, EndByte: 3, Replacement: "x"}},
			{{StartByte: 0, EndByte: 2, Replacement: "x"}, {StartByte: 1, EndByte: 2, Replacement: "y"}},
			{{StartByte: 3, EndByte: 5, Replacement: "x"}},
			{{StartByte: 3, EndByte: 4, Replacement: "x\ny"}},
		} {
			if _, err := UnifiedDiff("x.yaml", []byte("a: b\n"), edits); ReasonOf(err) != ReasonInvalidEdit {
				t.Fatalf("%v: got %v", edits, err)
			}
		}
	})
}
