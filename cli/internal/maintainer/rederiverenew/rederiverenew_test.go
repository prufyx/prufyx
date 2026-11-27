// SPDX-License-Identifier: AGPL-3.0-only

package rederiverenew

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

const ciliumID = "crd.version-removal.cilium"

var (
	now = time.Date(2026, 12, 20, 12, 0, 0, 0, time.UTC)
	at  = now.Add(-time.Hour)
)

func stamp(t time.Time) string { return t.Format("2006-01-02T15:04:05Z") }

type doc = map[string]any

func obj(v any, keys ...string) doc {
	m := v.(doc)
	for _, k := range keys {
		m = m[k].(doc)
	}
	return m
}

func ruleEv(e any) doc { return obj(e, "rule", "evidence") }
func attEv(a any) doc  { return obj(a, "evidence") }

func setTimes(ev doc, derived, until time.Time) {
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = stamp(derived), stamp(derived), stamp(until)
}

// fixture is a small pack cut from the shipped one: the cilium mechanical
// rule and two of its line attestations, all ending 20 days after at.
func fixture(t *testing.T) doc {
	t.Helper()
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var full doc
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatal(err)
	}
	var entries, atts []any
	for _, e := range full["entries"].([]any) {
		ev := ruleEv(e)
		if x, ok := ev["extractor"].(doc); ok && x["id"] == ciliumID && len(entries) < 1 {
			entries = append(entries, e)
		}
	}
	for _, a := range full["lineAttestations"].([]any) {
		if x, ok := attEv(a)["extractor"].(doc); ok && x["id"] == ciliumID && len(atts) < 2 {
			atts = append(atts, a)
		}
	}
	if len(entries) != 1 || len(atts) != 2 {
		t.Fatalf("the shipped pack no longer holds the fixture records (%d rules, %d attestations)", len(entries), len(atts))
	}
	old := at.Add(-70 * 24 * time.Hour)
	for _, e := range entries {
		ruleEv(e)["state"] = "active"
		setTimes(ruleEv(e), old, at.Add(20*24*time.Hour))
	}
	for _, a := range atts {
		setTimes(attEv(a), old, at.Add(20*24*time.Hour))
	}
	full["entries"], full["lineAttestations"] = entries, atts
	delete(full, "pathPolicies")
	delete(full, "servedAPIs")
	return full
}

func clone(t *testing.T, d doc) doc {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var out doc
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func render(t *testing.T, d doc) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		t.Fatal(err)
	}
	p, err := extractpack.ParsePack(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func repoOf(id string) (string, bool) { return "github.com/cilium/cilium", id == ciliumID }

func planFor(t *testing.T, base []byte) Plan {
	t.Helper()
	p, err := MakePlan(base, stamp(at), now, 45, repoOf)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Extractors) != 1 || len(p.Extractors[0].Records) != 3 {
		t.Fatalf("plan %+v", p)
	}
	return p
}

// renewAll is what a derivation at at with the planned lease applies.
func renewAll(d doc, lease int) {
	until := at.Add(time.Duration(lease) * 24 * time.Hour)
	for _, e := range d["entries"].([]any) {
		setTimes(ruleEv(e), at, until)
	}
	for _, a := range d["lineAttestations"].([]any) {
		setTimes(attEv(a), at, until)
	}
}

func rebuild(ev doc) {
	ev["extractor"].(doc)["version"] = "99.0.0"
	ev["sources"].([]any)[0].(doc)["contentDigest"] = "sha256:" + strings.Repeat("a", 64)
}

func TestAssembleCarriesOnlyRenewals(t *testing.T) {
	t.Parallel()
	d := fixture(t)
	base := render(t, d)
	plan := planFor(t, base)
	applied := clone(t, d)
	renewAll(applied, plan.Extractors[0].LeaseDays)
	out, res, err := Assemble(base, render(t, applied), plan, now, 45)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renewed) != 3 || len(res.NotRenewed) != 0 || res.LeftOut != 0 || !bytes.Equal(out, render(t, applied)) {
		t.Fatalf("result %+v", res)
	}

	// A new build may move the extractor and the sources.
	newBuild := clone(t, applied)
	rebuild(ruleEv(newBuild["entries"].([]any)[0]))
	if _, _, err := Assemble(base, render(t, newBuild), plan, now, 45); err != nil {
		t.Fatalf("new build: %v", err)
	}

	// A record the derivation did not touch stays as it was; a new record
	// is not carried.
	partial := clone(t, applied)
	partial["lineAttestations"].([]any)[1] = clone(t, d)["lineAttestations"].([]any)[1]
	extra := clone(t, applied)["lineAttestations"].([]any)[0].(doc)
	extra["line"] = "99.1"
	partial["lineAttestations"] = append(partial["lineAttestations"].([]any), extra)
	out, res, err = Assemble(base, render(t, partial), plan, now, 45)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renewed) != 2 || len(res.NotRenewed) != 1 || res.LeftOut != 1 || bytes.Contains(out, []byte(`"99.1"`)) {
		t.Fatalf("result %+v", res)
	}
}

func TestAssembleRefuses(t *testing.T) {
	t.Parallel()
	type edit func(applied doc, plan *Plan)
	rule := func(f func(ev doc)) edit {
		return func(a doc, _ *Plan) { f(ruleEv(a["entries"].([]any)[0])) }
	}
	att := func(f func(a doc)) edit {
		return func(a doc, _ *Plan) { f(a["lineAttestations"].([]any)[0].(doc)) }
	}
	for name, c := range map[string]struct {
		edit edit
		want string
	}{
		"moved tag: same build, other source digest": {rule(func(ev doc) {
			ev["sources"].([]any)[0].(doc)["contentDigest"] = "sha256:" + strings.Repeat("a", 64)
		}), "changes more"},
		"moved tag: attestation source revision": {att(func(a doc) {
			attEv(a)["sources"].([]any)[0].(doc)["revision"] = strings.Repeat("b", 40)
		}), "changes more"},
		"range changed": {att(func(a doc) { a["releases"].(doc)["to"].([]any)[0].(doc)["version"] = "99.0.0" }), "changes more"},
		"range changed on a new build": {att(func(a doc) {
			rebuild(attEv(a))
			a["releases"].(doc)["to"].([]any)[0].(doc)["commit"] = strings.Repeat("c", 40)
		}), "changes more"},
		"rule subject changed": {func(a doc, _ *Plan) { obj(a["entries"].([]any)[0], "rule", "subject")["to"] = "99.0.0" }, "changes more"},
		"lease member added":   {rule(func(ev doc) { ev["lease"] = "pinned" }), "changes more"},
		"completeness changed": {att(func(a doc) { a["completeness"] = "PARTIAL" }), ""},
		"other extractor": {rule(func(ev doc) {
			ev["extractor"].(doc)["id"] = "crd.version-removal.other"
		}), "another extractor"},
		"reviewed basis": {rule(func(ev doc) { ev["basis"] = "reviewed" }), "mechanical"},
		"withdrawn":      {rule(func(ev doc) { ev["state"] = "withdrawn" }), "mechanical"},
		"no source":      {rule(func(ev doc) { rebuild(ev); ev["sources"] = []any{} }), "cites no source"},
		"future derivation time": {rule(func(ev doc) {
			setTimes(ev, at.Add(48*time.Hour), at.Add(80*24*time.Hour))
		}), "planned derivation time"},
		"reviewedAt differs": {rule(func(ev doc) { ev["reviewedAt"] = stamp(at.Add(time.Second)) }), "planned derivation time"},
		"over 90 days":       {rule(func(ev doc) { ev["validUntil"] = stamp(at.Add(90*24*time.Hour + time.Second)) }), "at most 90 days"},
		"no duration":        {rule(func(ev doc) { ev["validUntil"] = stamp(at) }), "over 0"},
		"another lease":      {rule(func(ev doc) { ev["validUntil"] = stamp(at.Add(89*24*time.Hour + time.Hour)) }), "not the planned"},
		"record gone":        {func(a doc, _ *Plan) { a["lineAttestations"] = a["lineAttestations"].([]any)[1:] }, "missing from the applied pack"},
		"planned record not due": {func(_ doc, p *Plan) { p.Extractors[0].Records[0] = "rule other" }, "not due"},
		"planned record twice": {func(_ doc, p *Plan) {
			p.Extractors[0].Records[1] = p.Extractors[0].Records[0]
		}, "planned twice"},
		"plan leaves a due record out": {func(_ doc, p *Plan) { p.Extractors[0].Records = p.Extractors[0].Records[:2] }, "not the due records"},
		"extractor planned twice":      {func(_ doc, p *Plan) { p.Extractors = append(p.Extractors, p.Extractors[0]) }, "not usable"},
		"plan of another family":       {func(_ doc, p *Plan) { p.Extractors[0].ID = "k8s.served-api-removal" }, "not usable"},
		"plan lease over 90":           {func(_ doc, p *Plan) { p.Extractors[0].LeaseDays = 91 }, "not usable"},
		"future plan time":             {func(_ doc, p *Plan) { p.DerivedAt = stamp(now.Add(time.Hour)) }, "in the future"},
		"plan time over 24 hours old":  {func(_ doc, p *Plan) { p.DerivedAt = stamp(now.Add(-25 * time.Hour)) }, "24 hours old"},
		"empty plan":                   {func(_ doc, p *Plan) { p.Extractors = nil }, "empty"},
		"plan schema":                  {func(_ doc, p *Plan) { p.Schema = "x" }, "schema"},
	} {
		t.Run(name, func(t *testing.T) {
			d := fixture(t)
			base := render(t, d)
			plan := planFor(t, base)
			applied := clone(t, d)
			renewAll(applied, plan.Extractors[0].LeaseDays)
			c.edit(applied, &plan)
			out, _, err := Assemble(base, render(t, applied), plan, now, 45)
			if !errors.Is(err, ErrRefused) || out != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
}

func TestAssembleRefusesTheWholePack(t *testing.T) {
	t.Parallel()
	d := fixture(t)
	base := render(t, d)
	plan := planFor(t, base)
	applied := clone(t, d)
	renewAll(applied, plan.Extractors[0].LeaseDays)
	head := render(t, applied)
	if _, _, err := Assemble(base, base, plan, now, 45); err == nil || !strings.Contains(err.Error(), "no planned record was renewed") {
		t.Fatalf("nothing renewed: %v", err)
	}
	if _, _, err := Assemble(base, head, plan, now, 2); err == nil || !strings.Contains(err.Error(), "over the cap") {
		t.Fatalf("cap: %v", err)
	}
	for _, max := range []int{0, 46} {
		if _, _, err := Assemble(base, head, plan, now, max); err == nil {
			t.Fatalf("cap %d admitted", max)
		}
	}
	if _, _, err := Assemble(append([]byte(" "), base...), head, plan, now, 45); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("base rendering: %v", err)
	}
}

func TestPlanSelectsOnlyDueMechanicalRecords(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		edit func(d doc)
		want int
	}{
		"all due":            {func(d doc) {}, 3},
		"45 days is due":     {func(d doc) { ruleEv(d["entries"].([]any)[0])["validUntil"] = stamp(at.Add(DueWindow)) }, 3},
		"not yet due":        {func(d doc) { ruleEv(d["entries"].([]any)[0])["validUntil"] = stamp(at.Add(DueWindow + time.Second)) }, 2},
		"withdrawn rule":     {func(d doc) { ruleEv(d["entries"].([]any)[0])["state"] = "withdrawn" }, 2},
		"reviewed rule":      {func(d doc) { ruleEv(d["entries"].([]any)[0])["basis"] = "reviewed" }, 2},
		"kubernetes":         {func(d doc) { obj(d["entries"].([]any)[0], "rule", "subject")["component"] = kubernetesComponent }, 2},
		"changelog family":   {func(d doc) { ruleEv(d["entries"].([]any)[0])["extractor"].(doc)["id"] = "changelog.listed.x" }, 2},
		"kubernetes family":  {func(d doc) { ruleEv(d["entries"].([]any)[0])["extractor"].(doc)["id"] = "k8s.served-api-removal" }, 2},
		"unreadable validUntil": {func(d doc) { ruleEv(d["entries"].([]any)[0])["validUntil"] = "soon" }, 2},
	} {
		d := fixture(t)
		c.edit(d)
		// The attestation loader may refuse an edited pack; rules are edited.
		p, err := MakePlan(render(t, d), stamp(at), now, 45, repoOf)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := 0
		for _, x := range p.Extractors {
			got += len(x.Records)
			if x.LeaseDays < 76 || x.LeaseDays > 90 {
				t.Fatalf("%s: lease %d", name, x.LeaseDays)
			}
		}
		if got != c.want {
			t.Fatalf("%s: %d records, want %d", name, got, c.want)
		}
	}
	base := render(t, fixture(t))
	p, err := MakePlan(base, stamp(at), now, 2, repoOf)
	if err != nil || len(p.Extractors) != 0 || len(p.Deferred) != 1 {
		t.Fatalf("over the cap: %+v %v", p, err)
	}
	for name, c := range map[string]struct {
		at   string
		max  int
		repo func(string) (string, bool)
	}{
		"future":       {stamp(now.Add(time.Hour)), 45, repoOf},
		"old":          {stamp(now.Add(-25 * time.Hour)), 45, repoOf},
		"offset time":  {"2026-12-20T11:00:00+00:00", 45, repoOf},
		"cap over 45":  {stamp(at), 46, repoOf},
		"negative cap": {stamp(at), -1, repoOf},
		"unregistered": {stamp(at), 45, func(string) (string, bool) { return "", false }},
	} {
		if _, err := MakePlan(base, c.at, now, c.max, c.repo); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestCompareRequiresByteIdenticalRuns(t *testing.T) {
	t.Parallel()
	write := func(t *testing.T, dir, name, content string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pair := func(t *testing.T) (string, string) {
		a, b := t.TempDir(), t.TempDir()
		for _, d := range []string{a, b} {
			write(t, d, "manifest.json", "{}\n")
			write(t, d, "sub/candidates.json", "[]\n")
		}
		return a, b
	}
	a, b := pair(t)
	if d, err := Compare(a, b); err != nil || !digestRE.MatchString(d) {
		t.Fatalf("%q %v", d, err)
	}
	for name, edit := range map[string]func(t *testing.T, a, b string){
		"flipped byte":     func(t *testing.T, a, b string) { write(t, b, "sub/candidates.json", "{]\n") },
		"extra in second":  func(t *testing.T, a, b string) { write(t, b, "more.json", "x") },
		"extra in first":   func(t *testing.T, a, b string) { write(t, a, "more.json", "x") },
		"renamed":          func(t *testing.T, a, b string) { write(t, a, "x.json", "x"); write(t, b, "y.json", "x") },
		"symlink": func(t *testing.T, a, b string) {
			for _, d := range []string{a, b} {
				if err := os.Symlink("manifest.json", filepath.Join(d, "link")); err != nil {
					t.Fatal(err)
				}
			}
		},
		"missing directory": func(t *testing.T, a, b string) {
			if err := os.RemoveAll(b); err != nil {
				t.Fatal(err)
			}
		},
		"both empty": func(t *testing.T, a, b string) {
			for _, d := range []string{a, b} {
				for _, n := range []string{"manifest.json", "sub"} {
					if err := os.RemoveAll(filepath.Join(d, n)); err != nil {
						t.Fatal(err)
					}
				}
			}
		},
	} {
		a, b := pair(t)
		edit(t, a, b)
		if _, err := Compare(a, b); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestOriginIsRequiredInFull(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("1", 64)
	run := Run{ID: "7", Attempt: "1", Commit: strings.Repeat("a", 40), WorkflowSHA: strings.Repeat("b", 40)}
	plan := Plan{DerivedAt: stamp(at), Extractors: []Extractor{{ID: ciliumID, LeaseDays: 80}}}
	res := Result{Renewed: []Renewal{{Record: "rule x", Extractor: ciliumID, Version: "1.0.0", CodeDigest: digest}}}
	outputs := map[string]string{ciliumID: digest}
	block, err := Origin(run, plan, res, outputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Origin-Run: 7\n", "Origin-Attempt: 1\n", "Origin-Commit: ", "Origin-Workflow: ", "Origin-Derived-At: " + stamp(at), "Origin-Records: 1 sha256:", "Origin-Extractor: " + ciliumID} {
		if !strings.Contains(block, want) {
			t.Fatalf("origin lacks %q:\n%s", want, block)
		}
	}
	for name, edit := range map[string]func(r *Run, res *Result, o map[string]string){
		"run id":      func(r *Run, _ *Result, _ map[string]string) { r.ID = "" },
		"attempt":     func(r *Run, _ *Result, _ map[string]string) { r.Attempt = "0" },
		"commit":      func(r *Run, _ *Result, _ map[string]string) { r.Commit = "main" },
		"workflow":    func(r *Run, _ *Result, _ map[string]string) { r.WorkflowSHA = "" },
		"no records":  func(_ *Run, res *Result, _ map[string]string) { res.Renewed = nil },
		"no output":   func(_ *Run, _ *Result, o map[string]string) { delete(o, ciliumID) },
		"code digest": func(_ *Run, res *Result, _ map[string]string) { res.Renewed = []Renewal{{Record: "rule x", Extractor: ciliumID, Version: "1"}} },
	} {
		r, rs, o := run, res, map[string]string{ciliumID: digest}
		edit(&r, &rs, o)
		if _, err := Origin(r, plan, rs, o); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
