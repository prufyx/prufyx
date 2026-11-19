// SPDX-License-Identifier: AGPL-3.0-only

package hopstop

import (
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func rec() Record {
	return Record{
		Schema: Schema, Project: "synthetic-proj", Family: lineattest.FamilyCustomResourceVersions,
		FromLine: "1.2", ToLine: "1.3", Code: "scan-unclean", Reasons: []string{"scan-unclean"},
		ToolCommit:  strings.Repeat("a", 40),
		FactsDigest: "sha256:" + strings.Repeat("b", 64),
	}
}

func TestValidRecordAndRoundTrip(t *testing.T) {
	r := rec()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r2 := rec()
	r2.FromLine, r2.ToLine, r2.Code = "1.1", "1.2", "family-stop:parked"
	raw, err := Marshal([]Record{r, r2})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil || len(got) != 2 || got[0].FromLine != "1.1" {
		t.Fatalf("%v %v", got, err)
	}
	empty, err := Parse([]byte("[]"))
	if err != nil || len(empty) != 0 {
		t.Fatal(err)
	}
}

func TestRefusesUnknownCodesAndShapes(t *testing.T) {
	mut := map[string]func(*Record){
		"unknown code":          func(r *Record) { r.Code = "network-flaky" },
		"free text code":        func(r *Record) { r.Code = "scan was not clean, see PR" },
		"empty code":            func(r *Record) { r.Code = "" },
		"transient release":     func(r *Record) { r.Code = "release-pending" },
		"transient derive":      func(r *Record) { r.Code = "derive-failed" },
		"unknown family stop":   func(r *Record) { r.Code = "family-stop:other" },
		"bare family stop":      func(r *Record) { r.Code = "family-stop:" },
		"free text reason":      func(r *Record) { r.Reasons = []string{"hand note"} },
		"transient reason":      func(r *Record) { r.Reasons = []string{"derive-failed"} },
		"unsorted reasons":      func(r *Record) { r.Reasons = []string{"scan-unclean", "declared-incomplete"} },
		"too many reasons":      func(r *Record) { r.Reasons = make([]string, MaxReasons+1) },
		"wrong schema":          func(r *Record) { r.Schema = "prufyx.io/hop-stop/v2" },
		"unknown family":        func(r *Record) { r.Family = "not.a.family" },
		"line not major.minor":  func(r *Record) { r.FromLine = "1.2.3" },
		"from not before to":    func(r *Record) { r.FromLine = "1.3" },
		"short commit":          func(r *Record) { r.ToolCommit = "abc" },
		"digest without prefix": func(r *Record) { r.FactsDigest = strings.Repeat("b", 64) },
		"project not a slug":    func(r *Record) { r.Project = "Has Space" },
	}
	for name, m := range mut {
		r := rec()
		m(&r)
		if err := r.Validate(); err == nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	r := rec()
	good, err := Marshal([]Record{r})
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"unknown member":   strings.Replace(string(good), `"code":`, `"note": "x", "code":`, 1),
		"case variant":     strings.Replace(string(good), `"code":`, `"Code": "scan-unclean", "code":`, 1),
		"object not array": `{}`,
		"trailing data":    string(good) + `[]`,
		"unknown code":     strings.Replace(string(good), `"code": "scan-unclean"`, `"code": "made-up"`, 1),
	}
	for name, raw := range bad {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	dup := []Record{r, r}
	if err := Admit(dup); err == nil {
		t.Fatal("duplicate hop accepted")
	}
	r2 := rec()
	r2.FromLine, r2.ToLine = "1.1", "1.2"
	if err := Admit([]Record{r, r2}); err == nil {
		t.Fatal("unsorted section accepted")
	}
	if _, err := Marshal([]Record{{Schema: Schema}}); err == nil {
		t.Fatal("marshal of an invalid record")
	}
}

func TestFinalAndTransientAreDisjoint(t *testing.T) {
	for _, c := range append(append([]string{}, finalCodes...), "family-stop:parked") {
		if !Final(c) || Transient(c) {
			t.Fatalf("%s", c)
		}
	}
	for _, c := range transientCodes {
		if Final(c) || !Transient(c) {
			t.Fatalf("%s", c)
		}
	}
}
