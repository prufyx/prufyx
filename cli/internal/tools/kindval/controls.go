// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// controlsJSON is the reviewed controls file: claims whose outcome is known
// (control "true": confirmed; "false": refuted), each value cited to an
// upstream file at a commit in the pull request that added it.
//
//go:embed controls.json
var controlsJSON []byte

// controlsFile is prufyx.io/kind-val-controls/v1.
type controlsFile struct {
	Schema   string         `json:"schema"`
	Controls []controlEntry `json:"controls"`
}

// controlEntry is one reviewed control: an ordinary claim plus its expected
// outcome and, for the Kubernetes kinds, the lines it applies to.
type controlEntry struct {
	Claim
	// Lines expands the entry for every line of the matrix in range: a
	// k8s-served-api entry gets the line as its subject, a k8s-removal entry
	// the hop from the line one minor below. Without Lines the entry names
	// its own line(s) and is used only when the matrix has them.
	Lines *lineRange `json:"lines,omitempty"`
}

// lineRange is an inclusive range of release lines; an empty bound is open.
type lineRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

func (r lineRange) has(line string) bool {
	return (r.From == "" || !lineLess(line, r.From)) && (r.To == "" || !lineLess(r.To, line))
}

// controlKinds are the claim kinds a control may have.
var controlKinds = map[string]bool{KindServedAPI: true, KindK8sRemoval: true, KindCRDVersion: true, KindCRDRemoval: true, KindCRDPair: true, KindCRDField: true}

// loadControls decodes and checks the embedded controls file.
func loadControls() ([]controlEntry, error) {
	var f controlsFile
	dec := json.NewDecoder(strings.NewReader(string(controlsJSON)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("controls.json: %w", err)
	}
	if f.Schema != ControlsSchema {
		return nil, fmt.Errorf("controls.json: schema %q is not %s", f.Schema, ControlsSchema)
	}
	ids := map[string]bool{}
	for _, e := range f.Controls {
		switch {
		case !strings.HasPrefix(e.ID, "control.") || ids[e.ID]:
			return nil, fmt.Errorf("controls.json: id %q is not control.-prefixed or is repeated", e.ID)
		case !controlKinds[e.Kind]:
			return nil, fmt.Errorf("controls.json: %s: kind %q cannot be a control", e.ID, e.Kind)
		case e.Control != ControlTrue && e.Control != ControlFalse:
			return nil, fmt.Errorf("controls.json: %s: control must be \"true\" or \"false\"", e.ID)
		case e.Lines != nil && e.Kind != KindServedAPI && e.Kind != KindK8sRemoval:
			return nil, fmt.Errorf("controls.json: %s: only Kubernetes controls take lines", e.ID)
		case e.Lines != nil && (e.Subject.Line != "" || len(e.Subject.From)+len(e.Subject.To) > 0):
			return nil, fmt.Errorf("controls.json: %s: an entry with lines names no line of its own", e.ID)
		}
		ids[e.ID] = true
	}
	return f.Controls, nil
}

// mustControls is the embedded controls; a broken file is a build defect
// that the tests catch.
func mustControls() []controlEntry {
	entries, err := loadControls()
	if err != nil {
		panic(err)
	}
	return entries
}

// controlKindsWithEntries is the set of kinds the controls file covers.
func controlKindsWithEntries() map[string]bool {
	out := map[string]bool{}
	for _, e := range mustControls() {
		out[e.Kind] = true
	}
	return out
}

// ExpandControls is the control claims of a run of the given matrix for the
// given claim kinds, in id order: every entry of those kinds whose lines
// the matrix has.
func ExpandControls(entries []controlEntry, lines []string, kinds map[string]bool) []Claim {
	lines = uniqueLines(lines)
	have := map[string]bool{}
	for _, l := range lines {
		have[l] = true
	}
	sorted := append([]string(nil), lines...)
	sortLines(sorted)
	var out []Claim
	for _, e := range entries {
		if !kinds[e.Kind] {
			continue
		}
		c := e.Claim
		switch {
		case e.Lines != nil && e.Kind == KindServedAPI:
			for _, l := range sorted {
				if e.Lines.has(l) {
					cc := c
					cc.ID, cc.Subject.Line = c.ID+"."+l, l
					out = append(out, cc)
				}
			}
		case e.Lines != nil && e.Kind == KindK8sRemoval:
			for _, l := range sorted {
				prev := previousLine(l)
				if e.Lines.has(l) && have[prev] {
					cc := c
					cc.ID = c.ID + "." + prev + "-to-" + l
					cc.Subject.From, cc.Subject.To = rawString(prev), rawString(l)
					out = append(out, cc)
				}
			}
		case e.Kind == KindServedAPI:
			if have[c.Subject.Line] {
				out = append(out, c)
			}
		case e.Kind == KindK8sRemoval:
			from, err1 := lineSubject(c.Subject.From)
			to, err2 := lineSubject(c.Subject.To)
			if err1 == nil && err2 == nil && have[from] && have[to] {
				out = append(out, c)
			}
		default:
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// claimKinds is the set of kinds whose controls a run of the claims needs:
// the kinds of the claims that are not controls, and k8s-served-api as well
// when there is a k8s-removal claim (a removal is decided on the served
// APIs of both its lines).
func claimKinds(claims []Claim) map[string]bool {
	out := map[string]bool{}
	for _, c := range claims {
		if c.Control == "" {
			out[c.Kind] = true
		}
	}
	if out[KindK8sRemoval] {
		out[KindServedAPI] = true
	}
	return out
}

// uniqueLines is the lines in order, each once.
func uniqueLines(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// checkControls requires the controls of a v2 claims file to be exactly the
// reviewed controls expanded for its lines and the kinds of its claims:
// none missing, none added, none changed. A caller cannot invent, edit or
// drop a control.
func (c Claims) checkControls() error {
	if len(c.Lines) == 0 {
		return errors.New("a v2 claims file names its lines")
	}
	for _, l := range c.Lines {
		if _, _, ok := minorOf(l); !ok || strings.Count(l, ".") != 1 {
			return fmt.Errorf("line %q is not major.minor", l)
		}
	}
	if len(uniqueLines(c.Lines)) != len(c.Lines) {
		return errors.New("a line is named twice")
	}
	entries, err := loadControls()
	if err != nil {
		return err
	}
	want := map[string]string{}
	for _, ctl := range ExpandControls(entries, c.Lines, claimKinds(c.Claims)) {
		b, _ := json.Marshal(ctl)
		want[ctl.ID] = string(b)
	}
	got := 0
	for _, cl := range c.Claims {
		if cl.Control == "" {
			continue
		}
		got++
		b, _ := json.Marshal(cl)
		if want[cl.ID] != string(b) {
			return fmt.Errorf("control %s is not a reviewed control of this run's lines and kinds", cl.ID)
		}
	}
	if got != len(want) {
		var missing []string
		for id := range want {
			found := false
			for _, cl := range c.Claims {
				found = found || (cl.Control != "" && cl.ID == id)
			}
			if !found {
				missing = append(missing, id)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("the reviewed controls %s are missing", strings.Join(missing, ", "))
	}
	return nil
}
