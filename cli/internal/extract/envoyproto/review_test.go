// SPDX-License-Identifier: AGPL-3.0-only

package envoyproto

import (
	"strings"
	"testing"
)

// cmpFiles compares two trees given as full file maps.
func cmpFiles(t *testing.T, older, newer map[string]string) Comparison {
	t.Helper()
	o := mustScan(t, older)
	n, err := Scan(tree(newer), repo, commitB)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compare(o, n)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func noMechanical(t *testing.T, c Comparison) {
	t.Helper()
	for _, x := range c.Candidates {
		if x.Status == StatusMechanical {
			t.Fatalf("mechanical where the removal is not proven: %+v", x)
		}
	}
}

const (
	oldM  = "message M { string keep = 1; string f = 2 [deprecated = true]; }\n"
	pair1 = "reserved 2; reserved \"f\";"
)

func TestMovesAreNeverMechanical(t *testing.T) {
	v2 := func(body string) map[string]string {
		return map[string]string{Root + "/api/v2/m.proto": "package envoy.api.v2;\n" + body}
	}
	v3 := func(body string) map[string]string {
		return map[string]string{Root + "/api/v3/m.proto": "package envoy.api.v3;\n" + body}
	}
	reserved := "message M { string keep = 1; " + pair1 + " }\n"
	t.Run("package move, same field", func(t *testing.T) {
		c := cmpFiles(t, v2(oldM), v3(reserved))
		noMechanical(t, c)
		if len(c.Candidates) != 1 || c.Candidates[0].Member != "envoy.api.v2.M.f" {
			t.Fatal(c.Candidates)
		}
	})
	t.Run("same package, other file", func(t *testing.T) {
		older := map[string]string{Root + "/x/a.proto": "package envoy.q;\n" + oldM}
		newer := map[string]string{Root + "/y/b.proto": "package envoy.q;\nmessage M { string keep = 1; " + pair1 + " }\n"}
		c := cmpFiles(t, older, newer)
		// The symbol is the same message: a file move does not change the
		// proven removal.
		if statusOf(c, "envoy.q.M.f") != StatusMechanical {
			t.Fatal(c.Candidates)
		}
	})
	t.Run("message moved into another message", func(t *testing.T) {
		older := map[string]string{Root + "/a.proto": "package envoy.q;\n" + oldM}
		newer := map[string]string{Root + "/a.proto": "package envoy.q;\nmessage O { message M { " + pair1 + " } }\n"}
		noMechanical(t, cmpFiles(t, older, newer))
	})
	t.Run("field moved into a oneof", func(t *testing.T) {
		older := map[string]string{Root + "/a.proto": "package envoy.q;\n" + oldM}
		newer := map[string]string{Root + "/a.proto": "package envoy.q;\nmessage M { string keep = 1; oneof o { string f = 2; } }\n"}
		noMechanical(t, cmpFiles(t, older, newer))
	})
	t.Run("field renumbered", func(t *testing.T) {
		older := map[string]string{Root + "/a.proto": "package envoy.q;\n" + oldM}
		newer := map[string]string{Root + "/a.proto": "package envoy.q;\nmessage M { string keep = 1; reserved 2; string f = 8; }\n"}
		noMechanical(t, cmpFiles(t, older, newer))
	})
	t.Run("field in a nested oneof", func(t *testing.T) {
		src := "package envoy.q;\nmessage O { message M { oneof o { string f = 2 [deprecated = true]; string g = 3; } } }\n"
		gone := "package envoy.q;\nmessage O { message M { reserved 2; reserved \"f\"; oneof o { string g = 3; } } }\n"
		c := cmpFiles(t, map[string]string{Root + "/a.proto": src}, map[string]string{Root + "/a.proto": gone})
		if statusOf(c, "envoy.q.O.M.f") != StatusMechanical {
			t.Fatal(c.Candidates)
		}
		moved := "package envoy.q;\nmessage O { message M { reserved 2; oneof o { string f = 9; string g = 3; } } }\n"
		noMechanical(t, cmpFiles(t, map[string]string{Root + "/a.proto": src}, map[string]string{Root + "/a.proto": moved}))
	})
	t.Run("dotted lookalike names", func(t *testing.T) {
		// Member "a.b.c" could be message a.b field c or message a field b.c;
		// the scan's own names decide, never the encoded text.
		older := map[string]string{Root + "/a.proto": "package a;\nmessage b { string c = 2 [deprecated = true]; }\n"}
		newer := map[string]string{Root + "/a.proto": "package a;\nmessage b { reserved 2; reserved \"c\"; }\nmessage x {}\n"}
		c := cmpFiles(t, older, newer)
		if statusOf(c, "a.b.c") != StatusMechanical {
			t.Fatal(c.Candidates)
		}
	})
}

func TestSwappedPairIsNotMechanical(t *testing.T) {
	older := map[string]string{Root + "/a.proto": "package envoy.q;\n" + oldM}
	newer := map[string]string{Root + "/a.proto": "package envoy.q;\nmessage M { string keep = 1; " + pair1 + " }\n"}
	// The real removal (older, newer) is mechanical ...
	if statusOf(cmpFiles(t, older, newer), "envoy.q.M.f") != StatusMechanical {
		t.Fatal("the real removal pair is not proven")
	}
	// ... and the swapped arguments give nothing mechanical.
	noMechanical(t, cmpFiles(t, newer, older))
}

func TestParserRefusesContradictoryReservations(t *testing.T) {
	cases := map[string]string{
		"number in own range":     "message M { reserved 1 to 5; string a = 3; }\n",
		"number reserved after":   "message M { string a = 3; reserved 3; }\n",
		"name reserved":           "message M { string a = 1; reserved \"a\"; }\n",
		"name reserved before":    "message M { reserved \"a\"; string a = 1; }\n",
		"number in max range":     "message M { reserved 10 to max; string a = 11; }\n",
		"nested":                  "message O { message M { reserved \"a\"; string a = 1; } }\n",
		"oneof field reserved":    "message M { reserved 4; oneof o { string a = 4; } }\n",
		"number zero":             "message M { string a = 0; }\n",
		"implementation range lo": "message M { string a = 19000; }\n",
		"implementation range hi": "message M { string a = 19999; }\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustScan(t, one(hdr+body))
			if r.Attestable() {
				t.Fatal("accepted")
			}
		})
	}
	for name, body := range map[string]string{
		"just below": "message M { string a = 18999; }\n",
		"just above": "message M { string a = 20000; }\n",
		"one":        "message M { string a = 1; }\n",
	} {
		if r := mustScan(t, one(hdr+body)); !r.Attestable() {
			t.Fatalf("%s: %v", name, r.Ledger)
		}
	}
}

func TestPackageAfterDeclarationFails(t *testing.T) {
	for name, body := range map[string]string{
		"after message": "message M {}\npackage b;\n",
		"after enum":    "enum E { Z = 0; }\npackage b;\n",
		"after service": "service S {}\npackage b;\n",
	} {
		r := mustScan(t, one("syntax = \"proto3\";\n"+body))
		if r.Attestable() {
			t.Fatalf("%s accepted", name)
		}
	}
	if r := mustScan(t, one("syntax = \"proto3\";\nimport \"x.proto\";\noption a = 1;\npackage b;\nmessage M {}\n")); !r.Attestable() {
		t.Fatal(r.Ledger)
	}
}

func TestBlockCommentCannotUnhide(t *testing.T) {
	for name, src := range map[string]string{
		"block between":      "// [#not-implemented-hide:]\n/* note */\nstring f = 1 [deprecated = true];\n",
		"multiline block":    "// [#not-implemented-hide:]\n/* note\n more */\nstring f = 1 [deprecated = true];\n",
		"marker inside":      "/* [#not-implemented-hide:] */\nstring f = 1 [deprecated = true];\n",
		"block then comment": "// [#not-implemented-hide:]\n/* a */\n// text\nstring f = 1 [deprecated = true];\n",
	} {
		r := mustScan(t, one(hdr+"message M {\n"+src+"}\n"))
		if len(r.Candidates) != 0 || !r.Attestable() || r.Hidden != 1 {
			t.Fatalf("%s: %v hidden=%d", name, r.Candidates, r.Hidden)
		}
	}
	// A plain block comment without the marker still hides nothing.
	r := mustScan(t, one(hdr+"message M {\n/* note */\nstring f = 1 [deprecated = true];\n}\n"))
	if len(r.Candidates) != 1 {
		t.Fatal(r.Candidates)
	}
}

func TestPathologicalInputs(t *testing.T) {
	deep := strings.Repeat("{", 200000)
	cases := map[string]string{
		"very long line":        "message M { string a = 1 [json_name = \"" + strings.Repeat("x", 900000) + "\"]; }\n",
		"deep braces extend":    "extend M " + deep + "\n",
		"deep braces statement": "option x = " + deep + ";\n",
		"deep brackets option":  "message M { string a = 1 [x = " + strings.Repeat("[", 100000) + "]; }\n",
		"deep parens":           "message M { string a = 1 [" + strings.Repeat("(", 100000) + "]; }\n",
		"escaped quotes":        "message M { string a = 1 [(x.y) = \"a\\\"b [deprecated = true]\"]; }\n",
		"single quotes":         "message M { string a = 1 [(x.y) = 'a\\'b [deprecated = true]']; }\n",
		"non-ascii string":      "message M { string a = 1 [json_name = \"é中 [deprecated = true]\"]; }\n// é deprecated = true\n",
		"non-ascii outside":     "message é {}\n",
		"many commas":           "message M { reserved " + strings.Repeat("1,", 100000) + "1; }\n",
		"deep nesting":          strings.Repeat("message M { ", 5000) + strings.Repeat("}", 5000) + "\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustScan(t, one(hdr+body))
			for _, c := range r.Candidates {
				if c.Status != StatusDraft {
					t.Fatal("mechanical from a single scan")
				}
			}
			if name == "escaped quotes" || name == "single quotes" {
				if !r.Attestable() || len(r.Candidates) != 0 {
					t.Fatalf("%v %v", r.Ledger, r.Candidates)
				}
			}
			if name == "non-ascii string" && (!r.Attestable() || len(r.Candidates) != 0) {
				t.Fatalf("%v %v", r.Ledger, r.Candidates)
			}
			if name == "non-ascii outside" && r.Attestable() {
				t.Fatal("accepted")
			}
		})
	}
}

func FuzzScan(f *testing.F) {
	seeds := []string{
		hdr + "message M { string a = 1 [deprecated = true]; reserved 2; reserved \"b\"; oneof o { string c = 3; } map<string,string> m = 4; }\n",
		hdr + "// [#not-implemented-hide:]\n/* x */ enum E { A = 0 [deprecated = true]; }\n",
		"message M {", "[deprecated = true]", "\"", "/*", "reserved 1 to", "option deprecated = true;",
		"message M { string a = 1 [(envoy.annotations.deprecated_at_minor_version) = \"3.0\"]; }",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 1<<16 {
			return
		}
		m := tree(one(src))
		r, err := Scan(m, repo, commitA)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range r.Candidates {
			if c.Status != StatusDraft || c.Proof != "" {
				t.Fatalf("%+v", c)
			}
		}
		// A scan compared with itself under another commit proves nothing.
		n, _ := Scan(tree(one(src)), repo, commitB)
		cmp, err := Compare(r, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cmp.Candidates {
			if c.Status == StatusMechanical {
				t.Fatalf("%+v", c)
			}
		}
	})
}
