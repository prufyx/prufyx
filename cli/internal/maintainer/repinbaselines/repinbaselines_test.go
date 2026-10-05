// SPDX-License-Identifier: AGPL-3.0-only

package repinbaselines

import (
	"encoding/json"
	"strings"
	"testing"
)

func goodEntry() Entry {
	return Entry{
		Approval: "pr-15", Commit: strings.Repeat("a", 40), DecidedAt: "2026-10-05T10:00:00Z",
		Reason: "the project publishes v1.x as its stable line", Repository: "example/proj", Tag: "v1.3.0",
	}
}

func fileOf(entries ...Entry) []byte {
	raw, _ := File{Schema: Schema, Entries: entries}.Marshal()
	return raw
}

func TestParseAcceptsAWellFormedFile(t *testing.T) {
	b := goodEntry()
	b.Repository = "zeta/last"
	f, err := Parse(fileOf(goodEntry(), b))
	if err != nil || len(f.Entries) != 2 {
		t.Fatalf("%v %+v", err, f)
	}
	if e, ok := f.Lookup("EXAMPLE/Proj"); !ok || e.Tag != "v1.3.0" {
		t.Fatalf("lookup is case-insensitive: %+v %v", e, ok)
	}
	if _, ok := f.Lookup("example/none"); ok {
		t.Fatal("unknown repository")
	}
	if _, err := Parse([]byte(`{"schema":"` + Schema + `","entries":[]}`)); err != nil {
		t.Fatalf("empty file: %v", err)
	}
	if f, err := ParseOptional(nil); err != nil || len(f.Entries) != 0 {
		t.Fatalf("absent file is empty: %v", err)
	}
}

func TestParseRefusals(t *testing.T) {
	mut := func(f func(*Entry)) []byte {
		e := goodEntry()
		f(&e)
		return fileOf(e)
	}
	bad := map[string][]byte{
		"wrong schema":        []byte(`{"schema":"x","entries":[]}`),
		"unknown member":      []byte(`{"schema":"` + Schema + `","entries":[],"extra":1}`),
		"duplicate member":    []byte(`{"schema":"` + Schema + `","schema":"` + Schema + `","entries":[]}`),
		"trailing data":       []byte(`{"schema":"` + Schema + `","entries":[]} {}`),
		"unknown entry field": []byte(`{"schema":"` + Schema + `","entries":[{"approval":"a","commit":"` + strings.Repeat("a", 40) + `","decidedAt":"2026-10-05T10:00:00Z","reason":"r","repository":"a/b","tag":"v1","x":1}]}`),
		"missing field":       []byte(`{"schema":"` + Schema + `","entries":[{"repository":"a/b"}]}`),
		"not owner/repo":      mut(func(e *Entry) { e.Repository = "proj" }),
		"three parts":         mut(func(e *Entry) { e.Repository = "a/b/c" }),
		"dot repo":            mut(func(e *Entry) { e.Repository = "a/.." }),
		"double hyphen owner": mut(func(e *Entry) { e.Repository = "a--b/c" }),
		"tag with slash":      mut(func(e *Entry) { e.Tag = "release/1.0" }),
		"tag dotdot":          mut(func(e *Entry) { e.Tag = "v1..2" }),
		"tag empty":           mut(func(e *Entry) { e.Tag = "" }),
		"short commit":        mut(func(e *Entry) { e.Commit = "abc123" }),
		"upper commit":        mut(func(e *Entry) { e.Commit = strings.Repeat("A", 40) }),
		"bad time":            mut(func(e *Entry) { e.DecidedAt = "2026-10-05 10:00:00" }),
		"offset time":         mut(func(e *Entry) { e.DecidedAt = "2026-10-05T10:00:00+02:00" }),
		"empty reason":        mut(func(e *Entry) { e.Reason = "  " }),
		"padded reason":       mut(func(e *Entry) { e.Reason = " because" }),
		"control in reason":   mut(func(e *Entry) { e.Reason = "a\tb" }),
		"long reason":         mut(func(e *Entry) { e.Reason = strings.Repeat("x", 501) }),
		"bad approval":        mut(func(e *Entry) { e.Approval = "pr 15" }),
		"repository twice":    fileOf(goodEntry(), func() Entry { e := goodEntry(); e.Repository = "Example/PROJ"; return e }()),
		"unsorted":            fileOf(func() Entry { e := goodEntry(); e.Repository = "zeta/last"; return e }(), goodEntry()),
		"too large":           append([]byte(`{"schema":"`+Schema+`","entries":[]}`), make([]byte, MaxBytes)...),
	}
	for name, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCanonicalDigestBindsEveryField(t *testing.T) {
	base := goodEntry()
	if !strings.HasSuffix(string(base.Canonical()), "}\n") || !strings.Contains(string(base.Canonical()), "\n  \"approval\"") {
		t.Fatalf("canonical form: %q", base.Canonical())
	}
	var back map[string]string
	if err := json.Unmarshal(base.Canonical(), &back); err != nil || len(back) != 6 {
		t.Fatalf("%v %v", err, back)
	}
	seen := map[string]bool{base.Digest(): true}
	for name, f := range map[string]func(*Entry){
		"approval":   func(e *Entry) { e.Approval = "pr-16" },
		"commit":     func(e *Entry) { e.Commit = strings.Repeat("b", 40) },
		"decidedAt":  func(e *Entry) { e.DecidedAt = "2026-10-06T10:00:00Z" },
		"reason":     func(e *Entry) { e.Reason = "another" },
		"repository": func(e *Entry) { e.Repository = "example/other" },
		"tag":        func(e *Entry) { e.Tag = "v1.4.0" },
	} {
		e := goodEntry()
		f(&e)
		if seen[e.Digest()] {
			t.Errorf("%s does not change the digest", name)
		}
		seen[e.Digest()] = true
	}
}

func TestApprovalID(t *testing.T) {
	id, err := ApprovalID("Cloud-Custodian/cloud-custodian")
	if err != nil || id != "cloud-custodian--cloud-custodian" {
		t.Fatalf("%q %v", id, err)
	}
	if _, err := ApprovalID("nope"); err == nil {
		t.Fatal("not owner/repo")
	}
}
