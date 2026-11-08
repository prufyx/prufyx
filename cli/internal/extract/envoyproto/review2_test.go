// SPDX-License-Identifier: AGPL-3.0-only

package envoyproto

import "testing"

const oldJSON = "message M { string keep = 1; string foo_bar = 2 [deprecated = true]; }\n"

func jsonPair(t *testing.T, oldSrc, newBody string) Comparison {
	t.Helper()
	return cmpFiles(t,
		map[string]string{Root + "/a.proto": "package envoy.q;\n" + oldSrc},
		map[string]string{Root + "/a.proto": "package envoy.q;\n" + newBody})
}

func TestJSONNamesBlockMechanical(t *testing.T) {
	const member = "envoy.q.M.foo_bar"
	res := "reserved 2; reserved \"foo_bar\"; "
	cases := []struct {
		name, old, new, want string
	}{
		{"true removal", oldJSON, "message M { string keep = 1; " + res + "}\n", StatusMechanical},
		{"unrelated json_name", oldJSON, "message M { " + res + "string other = 5 [json_name = \"other2\"]; }\n", StatusMechanical},
		{"rename keeps proto name as json_name", oldJSON, "message M { " + res + "string other = 5 [json_name = \"foo_bar\"]; }\n", StatusDraft},
		{"rename keeps camel json_name", oldJSON, "message M { " + res + "string other = 5 [json_name = \"fooBar\"]; }\n", StatusDraft},
		{"foo_bar to fooBar", oldJSON, "message M { " + res + "string fooBar = 6; }\n", StatusDraft},
		{"double underscore same camel", oldJSON, "message M { " + res + "string foo__bar = 6; }\n", StatusDraft},
		{"hidden field keeps accepting", oldJSON, "message M { " + res + "\n// [#not-implemented-hide:]\nstring fooBar = 6; }\n", StatusDraft},
		{"explicit old json_name taken by field", "message M { string a_b = 2 [deprecated = true, json_name = \"zed\"]; }\n",
			"message M { reserved 2; reserved \"a_b\"; string zed = 3; }\n", StatusDraft},
		{"explicit old json_name taken by json_name", "message M { string a_b = 2 [deprecated = true, json_name = \"zed\"]; }\n",
			"message M { reserved 2; reserved \"a_b\"; string c = 3 [json_name = \"zed\"]; }\n", StatusDraft},
		{"old explicit json_name, camel of name free", "message M { string a_b = 2 [deprecated = true, json_name = \"zed\"]; }\n",
			"message M { reserved 2; reserved \"a_b\"; }\n", StatusMechanical},
		{"in oneof", oldJSON, "message M { " + res + "oneof o { string fooBar = 6; } }\n", StatusDraft},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmp := jsonPair(t, c.old, c.new)
			member := member
			if c.old != oldJSON {
				member = "envoy.q.M.a_b"
			}
			if got := statusOf(cmp, member); got != c.want {
				t.Fatalf("got %s want %s (%v)", got, c.want, cmp.Ledger)
			}
		})
	}
}

func TestJSONNameOptionFailsClosed(t *testing.T) {
	for name, body := range map[string]string{
		"not a string": "message M { string a = 1 [json_name = foo]; }\n",
		"escape":       "message M { string a = 1 [json_name = \"a\\x41\"]; }\n",
		"two strings":  "message M { string a = 1 [json_name = \"a\" \"b\"]; }\n",
		"empty":        "message M { string a = 1 [json_name = \"\"]; }\n",
	} {
		if r := mustScan(t, one(hdr+body)); r.Attestable() {
			t.Fatalf("%s accepted", name)
		}
	}
	if r := mustScan(t, one(hdr+"message M { string a = 1 [json_name = \"aB\"]; }\n")); !r.Attestable() {
		t.Fatal(r.Ledger)
	}
}

func TestMissingPackageIsWithheld(t *testing.T) {
	for name, src := range map[string]string{
		"no package":         "syntax = \"proto3\";\nmessage M { string a = 1 [deprecated = true]; }\n",
		"empty file":         "",
		"only comments":      "// nothing\n",
		"package in comment": "// package a;\nmessage M {}\n",
	} {
		r := mustScan(t, one(src))
		if r.Attestable() || r.Ledger[0].Code != ReasonPackage {
			t.Fatalf("%s: %v", name, r.Ledger)
		}
	}
}

func TestNumberSyntax(t *testing.T) {
	for name, lit := range map[string]string{"binary": "0b1", "octal 0o": "0o7", "underscore": "1_0", "bad octal": "08", "float": "1.5", "hex float": "0x1p3"} {
		if r := mustScan(t, one(hdr+"message M { string a = "+lit+"; }\n")); r.Attestable() {
			t.Fatalf("%s accepted", name)
		}
	}
	for name, lit := range map[string]string{"decimal": "7", "hex": "0x10", "octal": "010"} {
		if r := mustScan(t, one(hdr+"message M { string a = "+lit+" [deprecated = true]; }\n")); !r.Attestable() || len(r.Candidates) != 1 {
			t.Fatalf("%s: %v", name, r.Ledger)
		}
	}
	r := mustScan(t, one(hdr+"message M { string a = 010 [deprecated = true]; }\n"))
	if r.Candidates[0].Number != 8 {
		t.Fatalf("octal 010 read as %d", r.Candidates[0].Number)
	}
}
