// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/k8sremovals"
)

// apiPair renders "group/version Kind" ("version Kind" for the core group).
func apiPair(group, version, kind string) string {
	if group == "" {
		return version + " " + kind
	}
	return group + "/" + version + " " + kind
}

// member renders "group/version/Kind", the custom-resource set member form.
func member(group, version, kind string) string { return group + "/" + version + "/" + kind }

// minorOf parses "major.minor" (a patch suffix is ignored); ok is false for
// anything else.
func minorOf(line string) (major, minor int, ok bool) {
	parts := strings.Split(line, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	m, err1 := strconv.Atoi(parts[0])
	n, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || m < 0 || n < 0 {
		return 0, 0, false
	}
	return m, n, true
}

// lineOf is the "major.minor" line of a version.
func lineOf(version string) string {
	m, n, ok := minorOf(version)
	if !ok {
		return version
	}
	return fmt.Sprintf("%d.%d", m, n)
}

// lineLess orders lines numerically.
func lineLess(a, b string) bool {
	am, an, _ := minorOf(a)
	bm, bn, _ := minorOf(b)
	return am < bm || am == bm && an < bn
}

// previousLine is the line one minor below.
func previousLine(line string) string {
	m, n, ok := minorOf(line)
	if !ok || n == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d", m, n-1)
}

// sortLines sorts lines numerically.
func sortLines(lines []string) {
	sort.SliceStable(lines, func(i, j int) bool { return lineLess(lines[i], lines[j]) })
}

func rawString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

func rawObject(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// servedAPIClaim builds a k8s-served-api claim.
func servedAPIClaim(line, group, version, kind, expect, source string) Claim {
	api := apiPair(group, version, kind)
	id := fmt.Sprintf("k8s.%s.%s.%s", line, strings.ReplaceAll(strings.ReplaceAll(api, "/", "_"), " ", "_"), expect)
	return Claim{ID: id, Kind: KindServedAPI, Subject: Subject{Line: line, Group: group, Version: version, Kind: kind}, Expect: expect, Evidence: rawObject(map[string]string{"source": source})}
}

// KubernetesClaims derives the checkable claims of the removal table for
// the given cluster lines. For a removal that takes effect at line L
// (kinds K of group G stop being served at version V):
//
//   - every line >= L does not serve G/V K (Kubernetes never serves a
//     removed version again);
//   - line L-1 serves G/V K (the rule's own from range: what L-1 served);
//   - line L serves every version the table names as still served there;
//   - when both L-1 and L are in the matrix, a k8s-removal claim for the
//     hop L-1 -> L: both servers agree and the scan blocks.
//
// Nothing is claimed about a removed version on lines below L-1: the table
// does not record when a version was introduced.
func KubernetesClaims(lines []string) []Claim {
	have := make(map[string]bool, len(lines))
	for _, line := range lines {
		have[line] = true
	}
	var out []Claim
	add := func(c Claim) {
		if have[c.Subject.Line] {
			out = append(out, c)
		}
	}
	type removal struct {
		line, group, version, source string
		kinds, served                []string
	}
	var removals []removal
	table := k8sremovals.ByTargetMinor()
	for line, list := range table {
		for _, r := range list {
			removals = append(removals, removal{line: line, group: r.Group, version: r.Removed, source: "k8sremovals:" + r.Fact, kinds: r.Kinds, served: r.Served})
		}
	}
	// The 1.32 flow-control removal is handled outside the table.
	for _, rv := range k8sremovals.RemovedVersions() {
		if _, inTable := table[rv.Line]; inTable {
			continue
		}
		removals = append(removals, removal{line: rv.Line, group: rv.Group, version: rv.Version, source: "k8sremovals:RemovedVersions:" + rv.Line, kinds: rv.Kinds})
	}
	for _, r := range removals {
		prev := previousLine(r.line)
		for _, kind := range r.kinds {
			for _, line := range lines {
				if !lineLess(line, r.line) {
					add(servedAPIClaim(line, r.group, r.version, kind, ExpectNotServed, r.source))
				}
			}
			add(servedAPIClaim(prev, r.group, r.version, kind, ExpectServed, r.source+":from"))
			for _, served := range r.served {
				add(servedAPIClaim(r.line, r.group, served, kind, ExpectServed, r.source+":served"))
			}
			if have[prev] && have[r.line] {
				api := apiPair(r.group, r.version, kind)
				id := fmt.Sprintf("k8s.%s-to-%s.%s.removal", prev, r.line, strings.ReplaceAll(strings.ReplaceAll(api, "/", "_"), " ", "_"))
				out = append(out, Claim{ID: id, Kind: KindK8sRemoval, Subject: Subject{From: rawString(prev), To: rawString(r.line), Group: r.group, Version: r.version, Kind: kind}, Evidence: rawObject(map[string]string{"source": r.source})})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	dedup := out[:0]
	for i, c := range out {
		if i > 0 && out[i-1].ID == c.ID {
			continue
		}
		dedup = append(dedup, c)
	}
	return dedup
}

// knownRemovals is every "group/version Kind" the removal table names,
// keyed by the line it stops being served.
func knownRemovals() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, rv := range k8sremovals.AdmissionRemovedVersions() {
		if out[rv.Line] == nil {
			out[rv.Line] = map[string]bool{}
		}
		for _, kind := range rv.Kinds {
			out[rv.Line][apiPair(rv.Group, rv.Version, kind)] = true
		}
	}
	return out
}

// lineSubject reads a k8s-removal from/to member: a "major.minor" string.
func lineSubject(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("not a release line: %s", string(raw))
	}
	if _, _, ok := minorOf(s); !ok || strings.Count(s, ".") != 1 {
		return "", fmt.Errorf("%q is not major.minor", s)
	}
	return s, nil
}

// releaseSubject reads a crd-removal or crd-pair from/to member.
func releaseSubject(raw json.RawMessage) (CRDRelease, error) {
	var r CRDRelease
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("not a release: %v", err)
	}
	return r, r.validate()
}

func (r CRDRelease) validate() error {
	if r.Tag == "" || len(r.Commit) != 40 || strings.Trim(r.Commit, "0123456789abcdef") != "" || len(r.Files) == 0 {
		return fmt.Errorf("release %q needs a tag, a full lowercase hex commit and files", r.Tag)
	}
	return nil
}

// CRDPair is a pair of consecutive releases of one project to install in
// turn: the grouping of every crd-removal and crd-pair claim with the same
// project and releases. crd-version claims attach to a release of a pair.
type CRDPair struct {
	ID      string
	Project string
	Repo    string
	From    CRDRelease
	To      CRDRelease
	// Fields are the crd-field claims decided on this pair.
	Fields []Claim
}

func pairID(project, fromTag, toTag string) string { return project + "." + fromTag + "-to-" + toTag }

// Validate checks the claims document: known kinds, unique ids, complete
// subjects, and one commit and file list per project release.
func (c Claims) Validate() error {
	v2 := c.Schema == ClaimsSchemaV2
	if c.Schema != ClaimsSchema && !v2 {
		return fmt.Errorf("schema %q is neither %s nor %s", c.Schema, ClaimsSchema, ClaimsSchemaV2)
	}
	if !v2 && len(c.Lines) > 0 {
		return fmt.Errorf("lines are a %s member", ClaimsSchemaV2)
	}
	ids := map[string]bool{}
	releases := map[string]CRDRelease{}
	release := func(project string, r CRDRelease) error {
		key := project + "@" + r.Tag
		if prev, ok := releases[key]; ok && (prev.Commit != r.Commit || strings.Join(prev.Files, "\n") != strings.Join(r.Files, "\n")) {
			return fmt.Errorf("release %s %s has two different commits or file lists", project, r.Tag)
		}
		releases[key] = r
		return nil
	}
	for i, cl := range c.Claims {
		if cl.ID == "" || ids[cl.ID] {
			return fmt.Errorf("claim %d: id %q is empty or repeated", i, cl.ID)
		}
		ids[cl.ID] = true
		switch {
		case cl.Control != "" && !v2:
			return fmt.Errorf("claim %s: control is a %s member", cl.ID, ClaimsSchemaV2)
		case cl.Control != "" && cl.Control != ControlTrue && cl.Control != ControlFalse:
			return fmt.Errorf("claim %s: control must be \"true\" or \"false\"", cl.ID)
		case v2 && (cl.Control != "") != strings.HasPrefix(cl.ID, "control."):
			return fmt.Errorf("claim %s: only a control has an id starting with control.", cl.ID)
		}
		s := cl.Subject
		var err error
		switch cl.Kind {
		case KindServedAPI:
			if _, _, ok := minorOf(s.Line); !ok || s.Version == "" || s.Kind == "" || (cl.Expect != ExpectServed && cl.Expect != ExpectNotServed) {
				err = errors.New("needs line, version, kind and expect served|not_served")
			}
		case KindK8sRemoval:
			if s.Version == "" || s.Kind == "" {
				err = errors.New("needs version and kind")
			} else if _, err = lineSubject(s.From); err == nil {
				_, err = lineSubject(s.To)
			}
		case KindCRDVersion:
			if s.Project == "" || s.Repo == "" || s.Release == nil || s.CRD == "" || s.Group == "" || s.Version == "" || s.Kind == "" || s.Served == nil || s.Storage == nil {
				err = errors.New("needs project, repo, release, crd, group, version, kind, served and storage")
			} else if err = s.Release.validate(); err == nil {
				err = release(s.Project, *s.Release)
			}
		case KindCRDRemoval, KindCRDPair:
			if s.Project == "" || s.Repo == "" || (cl.Kind == KindCRDRemoval && (s.Group == "" || s.Version == "" || s.Kind == "")) {
				err = errors.New("needs project, repo, from and to (and group, version, kind for a removal)")
			} else {
				var from, to CRDRelease
				if from, err = releaseSubject(s.From); err == nil {
					if to, err = releaseSubject(s.To); err == nil {
						if err = release(s.Project, from); err == nil {
							err = release(s.Project, to)
						}
					}
				}
			}
		case KindCRDField:
			err = validateField(s)
			if err == nil {
				from, _ := releaseSubject(s.From)
				to, _ := releaseSubject(s.To)
				if err = release(s.Project, from); err == nil {
					err = release(s.Project, to)
				}
			}
		case KindAddonRule:
		default:
			err = fmt.Errorf("unknown kind %q", cl.Kind)
		}
		if err != nil {
			return fmt.Errorf("claim %s (%s): %v", cl.ID, cl.Kind, err)
		}
	}
	if v2 {
		return c.checkControls()
	}
	return nil
}

// validateField checks the subject of a crd-field claim. The value is
// checked when the claim is run: a change that needs one and has none is
// undetermined (value-missing), not an invalid file.
func validateField(s Subject) error {
	if s.Project == "" || s.Repo == "" || s.CRD == "" || s.Group == "" || s.Version == "" || s.Kind == "" || s.Path == "" || !fieldChanges[s.Change] {
		return errors.New("needs project, repo, from, to, crd, group, version, kind, path and a change of field-removed|field-required-added|field-type-changed|enum-value-removed|validation-tightened")
	}
	if s.CRD != strings.ToLower(s.CRD) || !strings.HasSuffix(s.CRD, "."+s.Group) {
		return fmt.Errorf("crd %q is not <plural>.%s", s.CRD, s.Group)
	}
	switch strings.Split(s.Path, ".")[0] {
	case "apiVersion", "kind", "metadata":
		return fmt.Errorf("path %q is not a schema field of the custom resource", s.Path)
	}
	for _, seg := range strings.Split(s.Path, ".") {
		if seg == "" || strings.ContainsAny(seg, "[]") {
			return fmt.Errorf("path %q is not dot-separated property names", s.Path)
		}
	}
	if len(s.Value) > 0 && !json.Valid(s.Value) {
		return fmt.Errorf("value is not JSON")
	}
	if _, err := releaseSubject(s.From); err != nil {
		return err
	}
	_, err := releaseSubject(s.To)
	return err
}

// Pairs lists the release pairs the claims need installed, by project and
// tags, in id order. The crd-field claims of a pair ride along, in id order.
func (c Claims) Pairs() []CRDPair {
	byID := map[string]CRDPair{}
	for _, cl := range c.Claims {
		if cl.Kind != KindCRDRemoval && cl.Kind != KindCRDPair && cl.Kind != KindCRDField {
			continue
		}
		from, _ := releaseSubject(cl.Subject.From)
		to, _ := releaseSubject(cl.Subject.To)
		id := pairID(cl.Subject.Project, from.Tag, to.Tag)
		p := byID[id]
		p.ID, p.Project, p.Repo, p.From, p.To = id, cl.Subject.Project, cl.Subject.Repo, from, to
		if cl.Kind == KindCRDField {
			p.Fields = append(p.Fields, cl)
		}
		byID[id] = p
	}
	out := make([]CRDPair, 0, len(byID))
	for _, p := range byID {
		sort.SliceStable(p.Fields, func(i, j int) bool { return p.Fields[i].ID < p.Fields[j].ID })
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CRDSingle is a release that crd-version claims name and no pair covers:
// it is installed on its own, from the commit and files the claims cite.
type CRDSingle struct {
	ID      string
	Project string
	Repo    string
	Release CRDRelease
}

func singleID(project, tag string) string { return project + "." + tag }

// Singles lists the releases named by crd-version claims that are neither
// the from nor the to release of any pair the claims need, by id order.
func (c Claims) Singles() []CRDSingle {
	covered := map[string]bool{}
	for _, p := range c.Pairs() {
		covered[singleID(p.Project, p.From.Tag)] = true
		covered[singleID(p.Project, p.To.Tag)] = true
	}
	byID := map[string]CRDSingle{}
	for _, cl := range c.Claims {
		s := cl.Subject
		if cl.Kind != KindCRDVersion || s.Release == nil {
			continue
		}
		id := singleID(s.Project, s.Release.Tag)
		if !covered[id] {
			byID[id] = CRDSingle{ID: id, Project: s.Project, Repo: s.Repo, Release: *s.Release}
		}
	}
	out := make([]CRDSingle, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
