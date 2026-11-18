// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// A group of a reserved namespace is emitted whole (no kinds), in the form
// table validation accepts; an ordinary group keeps its kinds.
func TestTableRowReservedGroupIsWhole(t *testing.T) {
	src := ipSource(func(_ string, m *memTree) {
		m.files["api/config/crd/kueue.x-k8s.io_workloads.yaml"] = ipDocs(ipCRD(roGroup, "Workload"))
	})
	i := ipInput(src, ipRules(t, `[`+ipEntry+`]`))
	i.Slug, i.Name, i.Repo = roSlug, "Kueue", "github.com/"+roRepo
	res := mustGenerate(t, i)
	var row struct {
		Slug   string
		Groups []map[string]any
	}
	if err := json.Unmarshal(res.TableRow, &row); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, g := range row.Groups {
		name := g["name"].(string)
		_, hasKinds := g["kinds"]
		seen[name] = true
		if name == roGroup && hasKinds {
			t.Errorf("reserved group row lists kinds: %v", g)
		}
		if name != roGroup && !hasKinds {
			t.Errorf("ordinary group %s lost its kinds", name)
		}
	}
	if !seen[roGroup] || !seen["widgets.example.test"] {
		t.Fatalf("groups missing: %v", seen)
	}
	// The report still names the kinds.
	for _, g := range res.Report.Groups {
		if g.Name == roGroup && len(g.Kinds) != 1 {
			t.Errorf("report lost the kinds: %+v", g)
		}
	}
	// The emitted row passes the real table validation next to its record.
	var rowDoc map[string]any
	_ = json.Unmarshal(res.TableRow, &rowDoc)
	// The documentation-domain fixture group is refused by validation on its
	// own account; keep only the reserved group.
	var only []any
	for _, g := range rowDoc["groups"].([]any) {
		if g.(map[string]any)["name"] == roGroup {
			only = append(only, g)
		}
	}
	rowDoc["groups"] = only
	doc := map[string]any{
		"schema":   customresources.TableSchema,
		"projects": []any{rowDoc},
		"reserved": []any{map[string]any{"name": roGroup, "owner": roSlug, "repository": "https://github.com/" + roRepo, "reason": "the group is defined by this project's own definitions"}},
	}
	raw, _ := json.Marshal(doc)
	if _, _, err := customresources.LoadTable(raw); err != nil {
		t.Fatalf("generated row refused by table validation: %v", err)
	}
	// Control: the same row with kinds on the reserved group is refused.
	bad := bytes.Replace(raw, []byte(`"name":"`+roGroup+`"`), []byte(`"kinds":["Workload"],"name":"`+roGroup+`"`), 1)
	if _, _, err := customresources.LoadTable(bad); err == nil {
		t.Fatal("control: a reserved group with kinds must be refused")
	}
}

func omRules(t *testing.T, absent ...string) *Rules { return optRules(t, absent...) }

// The target marks exactly the optional entry the reading proved absent at a
// window tag; mandatory entries carry no mark.
func TestOptionalMarkEmittedWhereProvenAbsent(t *testing.T) {
	repo := optRepo(t, nil)
	res := mustGenerate(t, optInput(GitSource{Dir: repo}, omRules(t, firstFive...)))
	for _, half := range [][]byte{res.A, res.B} {
		if !bytes.Contains(half, []byte(`{"path": "`+optPath+`", "optional": true}`)) {
			t.Fatalf("optional mark missing:\n%s", half)
		}
		if !bytes.Contains(half, []byte(`{"path": "api/config/crd/alpha.yaml"}`)) || strings.Count(string(half), `"optional"`) != 1 {
			t.Fatalf("mandatory entry marked or missing:\n%s", half)
		}
	}
	canon, err := Canonical(res.A)
	if err != nil || !bytes.Equal(canon, res.A) {
		t.Fatalf("emitted target is not canonical: %v", err)
	}
}

// An optional entry present at every tag is never marked: nothing proves it
// absent anywhere.
func TestOptionalMarkNotEmittedWhenPresentEverywhere(t *testing.T) {
	repo := optRepo(t, func(tag string, s *optSpec) {
		s.files[optPath] = ipCRD("widgets.example.test", "Operator")
	})
	// absentTags must name a tag of the run, but present-listed is a stop:
	// the pinned evidence is wrong, so the run fails and no target exists.
	_, err := Generate(optInput(GitSource{Dir: repo}, omRules(t, optTags[0])))
	wantStop(t, err, StopOptionalPresentListed)
}

// A path present at the older tags and removed at the newest is never
// turned into an optional path: the newest tag must read it.
func TestOptionalMarkNeverHidesARemoval(t *testing.T) {
	repo := optRepo(t, func(tag string, s *optSpec) {
		if tag != optTags[len(optTags)-1] {
			s.files[optPath] = ipCRD("widgets.example.test", "Operator")
		} else {
			delete(s.files, optPath)
		}
	})
	res, err := Generate(optInput(GitSource{Dir: repo}, omRules(t, optTags[5])))
	if res != nil {
		t.Fatalf("a removed path produced a target:\n%s", res.A)
	}
	wantStop(t, err, StopOptionalAbsentNewest)
}

// The optionalMark decision itself: only a listed entry verified absent at a
// window tag is marked.
func TestOptionalMarkDecision(t *testing.T) {
	rules := omRules(t, firstFive...)
	read := &tagResult{optStatus: map[string]string{optPath: "read"}}
	absent := &tagResult{optStatus: map[string]string{optPath: "verified-absent"}}
	if optionalMark(rules, []*tagResult{read, read}, optPath) {
		t.Error("marked without any proven absence")
	}
	if !optionalMark(rules, []*tagResult{absent, read}, optPath) {
		t.Error("not marked despite proven absence")
	}
	if optionalMark(rules, []*tagResult{absent, read}, "api/config/crd/") {
		t.Error("a mandatory entry was marked")
	}
	if optionalMark(nil, []*tagResult{absent}, optPath) {
		t.Error("marked without rules")
	}
}
