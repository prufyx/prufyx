// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Typed stop codes. Each has a next action; none is ever downgraded to a
// guess.
const (
	StopBadInput              = "bad-input"
	StopTagGrammar            = "tag-grammar"
	StopTagLineDuplicate      = "tag-line-duplicate"
	StopTagPrefixMixed        = "tag-prefix-mixed"
	StopTagPrefixUnsupported  = "tag-prefix-unsupported"
	StopTagUnreadable         = "tag-unreadable"
	StopTreeUnreadable        = "tree-unreadable"
	StopSymlinkEscapes        = "symlink-escapes-tree"
	StopUnreadableShape       = "unreadable-shape"
	StopDocsOnlyCRDSource     = "docs-only-crd-source"
	StopUnpinnedExclusion     = "unpinned-exclusion"
	StopExclusionOwnedGroup   = "exclusion-owned-group"
	StopFixtureHiddenOwnedCRD = "fixture-hidden-owned-crd"
	StopRuleMatchesNothing    = "rule-matches-nothing"
	StopDuplicateCRD          = "duplicate-crd"
	StopReservedGroup         = "reserved-group"
	StopGroupOwnedElsewhere   = "group-owned-elsewhere"
	StopNoCRDSource           = "no-crd-source"
	StopWindowTooShort        = "window-too-short"
	StopCommunityUpstream     = "community-upstream-missing"
	StopForeignCopyUnpinned   = "foreign-copy-unpinned"
	StopWindowShortened       = "window-shortened"
	StopInstallPathNothing    = "install-path-matches-nothing"
)

var nextAction = map[string]string{
	StopBadInput:              "fix the command line; every required option is listed in the usage text",
	StopTagGrammar:            "pass final release tags of the form <prefix>X.Y.Z, each once",
	StopTagLineDuplicate:      "pass one final tag per release line",
	StopTagPrefixMixed:        "pass tags of one prefix family",
	StopTagPrefixUnsupported:  "the extractor accepts no prefix, v, knative-v or a chart prefix; a new prefix needs an extractor change",
	StopTagUnreadable:         "make the tag available in the local checkout (fetch outside this command)",
	StopTreeUnreadable:        "repair or re-clone the local checkout",
	StopSymlinkEscapes:        "a link that leaves the tree cannot be read; review the link and either drop the tag window or pin a rule after review",
	StopUnreadableShape:       "the file is not a plain definition (template, patch or no spec.versions); narrow the window past it or ask for an extractor change",
	StopDocsOnlyCRDSource:     "the only definitions sit under a documentation directory; add a reviewed installSurface rule naming the file, or choose another source",
	StopUnpinnedExclusion:     "a definition file outside the install paths needs a reviewed exclusion rule (exact-file or fixture-dir) with pinned evidence",
	StopExclusionOwnedGroup:   "the excluded file defines a group the target reads; narrow the rule or review the file as install surface",
	StopFixtureHiddenOwnedCRD: "a fixture defines an owned CRD the target does not read; review it as install surface or remove the rule",
	StopRuleMatchesNothing:    "the rule names a path no tag of the window carries; drop or correct the rule",
	StopDuplicateCRD:          "two files define the same group and kind; pin which one is the source",
	StopReservedGroup:         "a Kubernetes-reserved group needs a reviewed ownership record before a target may list it",
	StopGroupOwnedElsewhere:   "another table project lists the group; use a kinds-only row after review",
	StopNoCRDSource:           "no install path holds a definition; give an installSurface rule or choose another source",
	StopWindowTooShort:        "fewer than two tags read the same files; widen the tag set or fix the unreadable tag",
	StopForeignCopyUnpinned:   "a definition file of another project's group sits outside the default-excluded directories (documentation or fixtures); add a reviewed pinned exclusion rule for the exact file or fixture directory",
	StopWindowShortened:       "older tags were withheld and --strict-window forbids a shorter window; fix the withheld tags or drop the flag after review",
	StopInstallPathNothing:    "an installPaths entry holds no definition file at this tag; correct the entry, or narrow the window past the tag",
	StopCommunityUpstream:     "a community-catalog row needs the upstream block (name, repository, license, licenseSource) in the rules file",
}

// Stop is a typed stop: the generator will not guess.
type Stop struct {
	Code    string `json:"code"`
	Subject string `json:"subject,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Next    string `json:"next"`
}

func stop(code, subject, detail string) Stop {
	n, ok := nextAction[code]
	if !ok {
		n = "review the finding"
	}
	return Stop{Code: code, Subject: subject, Detail: detail, Next: n}
}

func sortStops(s []Stop) []Stop {
	out := append([]Stop(nil), s...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// StopError carries the typed stops of a run.
type StopError struct{ Stops []Stop }

func (e *StopError) Error() string {
	var b strings.Builder
	for _, s := range e.Stops {
		fmt.Fprintf(&b, "STOP %s %s: %s; next: %s\n", s.Code, s.Subject, s.Detail, s.Next)
	}
	return strings.TrimRight(b.String(), "\n")
}

// Rule ids of the generator.
const (
	RuleIncludeInstallDir      = "include-install-dir"
	RuleIncludeSymlinkResolved = "include-symlink-resolved"
	RuleIncludePinnedSurface   = "include-pinned-surface"
	RuleIncludeInstallPath     = "include-install-path"
	RuleNonInstallCopy         = "non-install-copy"
	RuleExcludePinnedFile      = "exclude-pinned-file"
	RuleExcludePinnedFixtures  = "exclude-pinned-fixtures"
	RuleFixtureDrop            = "fixture-drop"
	RuleForeignCopy            = "foreign-copy"
	RuleGroupKinds             = "group-kinds"
	RuleTagPrefix              = "tag-prefix"
	RuleMinFrom                = "min-from"
)

// Decision is one line of the rule report.
type Decision struct {
	Rule    string `json:"rule"`
	Subject string `json:"subject"`
	Detail  string `json:"detail,omitempty"`
}

// DroppedTag is a tag withheld from the window.
type DroppedTag struct {
	Tag    string `json:"tag"`
	Reason string `json:"reason"`
}

// TagFact names a window tag and its commit.
type TagFact struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

// GroupFact is one group of the table row.
type GroupFact struct {
	Name  string   `json:"name"`
	Kinds []string `json:"kinds"`
}

// ReportSchema identifies the report document.
const ReportSchema = "prufyx.io/target-draft-report/v1"

// Report names the rule behind every decision.
type Report struct {
	Schema      string       `json:"schema"`
	Slug        string       `json:"slug"`
	TagPrefix   string       `json:"tagPrefix"`
	MinFrom     string       `json:"minFrom"`
	Tags        []TagFact    `json:"tags"`
	Dropped     []DroppedTag `json:"droppedTags"`
	Warnings    []string     `json:"warnings"`
	Decisions   []Decision   `json:"decisions"`
	Groups      []GroupFact  `json:"groups"`
	CRDCount    int          `json:"crdCount"`
	FactsDigest string       `json:"factsDigest"`
	// NonInstallCopies are the definition files outside the pinned
	// installPaths at the newest tag; present only when installPaths is used.
	NonInstallCopyCount int              `json:"nonInstallCopyCount,omitempty"`
	NonInstallCopies    []NonInstallCopy `json:"nonInstallCopies,omitempty"`
}

// NonInstallCopy is a definition file the target does not read because it is
// outside the pinned installPaths. It is reported, never dropped silently.
type NonInstallCopy struct {
	Path       string   `json:"path"`
	Groups     []string `json:"groups"`
	Unreadable string   `json:"unreadable,omitempty"`
}

type pathOut struct {
	Path string `json:"path"`
}

type exclOut struct {
	Path     string `json:"path"`
	Repo     string `json:"repo"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence"`
}

type targetBody struct {
	Project     string    `json:"project"`
	Catalog     string    `json:"catalog,omitempty"`
	Name        string    `json:"name"`
	Repo        string    `json:"repo"`
	Component   string    `json:"component"`
	FactProject string    `json:"factProject"`
	TagPrefixes []string  `json:"tagPrefixes"`
	MinFrom     string    `json:"minFrom"`
	Attest      bool      `json:"attest,omitempty"`
	Paths       []pathOut `json:"paths"`
	Exclude     []exclOut `json:"exclude"`
}

type targetDoc struct {
	Schema string     `json:"schema"`
	Target targetBody `json:"target"`
}

type rowGroup struct {
	Name   string   `json:"name"`
	Source string   `json:"source"`
	Kinds  []string `json:"kinds"`
}

type rowDoc struct {
	Slug        string     `json:"slug"`
	Catalog     string     `json:"catalog"`
	Upstream    *Upstream  `json:"upstream,omitempty"`
	FactProject string     `json:"factProject"`
	Component   string     `json:"component"`
	Groups      []rowGroup `json:"groups"`
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Canonical re-encodes a target file in the generator's format so that two
// files that differ only in whitespace compare equal. Unknown fields are an
// error.
func Canonical(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d targetDoc
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	if d.Target.TagPrefixes == nil {
		d.Target.TagPrefixes = []string{}
	}
	if d.Target.Paths == nil {
		d.Target.Paths = []pathOut{}
	}
	if d.Target.Exclude == nil {
		d.Target.Exclude = []exclOut{}
	}
	return marshalTarget(d)
}

func jstr(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(b.String(), "\n")
}

func jlist(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = jstr(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// marshalTarget writes a target file in the exact on-disk format of the
// shipped target-*.json files: two-space indented keys, the tag prefix list
// on one line, and one compact object per line for paths and exclusions. The
// shipped files are embedded into the extractor and covered by its code
// digest, so digest equality needs byte equality with this format.
func marshalTarget(d targetDoc) ([]byte, error) {
	t := d.Target
	var b strings.Builder
	b.WriteString("{\n  \"schema\": " + jstr(d.Schema) + ",\n  \"target\": {\n")
	line := func(k, v string) { b.WriteString("    \"" + k + "\": " + v + ",\n") }
	line("project", jstr(t.Project))
	if t.Catalog != "" {
		line("catalog", jstr(t.Catalog))
	}
	line("name", jstr(t.Name))
	line("repo", jstr(t.Repo))
	line("component", jstr(t.Component))
	line("factProject", jstr(t.FactProject))
	line("tagPrefixes", jlist(t.TagPrefixes))
	line("minFrom", jstr(t.MinFrom))
	if t.Attest {
		line("attest", "true")
	}
	var objs []string
	for _, p := range t.Paths {
		objs = append(objs, "{\"path\": "+jstr(p.Path)+"}")
	}
	b.WriteString("    \"paths\": " + objList(objs) + ",\n")
	objs = nil
	for _, e := range t.Exclude {
		objs = append(objs, "{\"path\": "+jstr(e.Path)+", \"repo\": "+jstr(e.Repo)+", \"reason\": "+jstr(e.Reason)+", \"evidence\": "+jstr(e.Evidence)+"}")
	}
	b.WriteString("    \"exclude\": " + objList(objs) + "\n  }\n}\n")
	return []byte(b.String()), nil
}

func objList(objs []string) string {
	if len(objs) == 0 {
		return "[]"
	}
	return "[\n      " + strings.Join(objs, ",\n      ") + "\n    ]"
}

func build(in Input, catalog, component, fact, ownerRepo, prefix, minFrom string, rules *Rules, window []*tagResult, dropped []DroppedTag, newest *tagResult) (*Result, error) {
	ordered := orderPaths(newest.included)
	body := targetBody{Project: in.Slug, Name: in.Name, Repo: in.Repo, Component: component, FactProject: fact,
		TagPrefixes: []string{prefix}, MinFrom: minFrom, Paths: []pathOut{}, Exclude: []exclOut{}}
	if catalog == "community" {
		body.Catalog = "community"
	}
	for _, i := range ordered {
		body.Paths = append(body.Paths, pathOut{Path: i.Path})
	}
	a, err := marshalTarget(targetDoc{Schema: "prufyx.io/crd-version-target/v1", Target: body})
	if err != nil {
		return nil, err
	}
	bb := body
	bb.Attest = true
	var excls []exclOut
	for _, e := range rules.Exclusions {
		excls = append(excls, exclOut{Path: e.Path, Repo: in.Repo, Reason: e.Reason, Evidence: e.Evidence})
	}
	sort.Slice(excls, func(i, j int) bool { return excls[i].Path < excls[j].Path })
	if excls != nil {
		bb.Exclude = excls
	}
	b, err := marshalTarget(targetDoc{Schema: "prufyx.io/crd-version-target/v1", Target: bb})
	if err != nil {
		return nil, err
	}

	// Group kind lists: the union of the kinds read at the newest tag.
	kinds := map[string]map[string]bool{}
	source := map[string]string{}
	for _, i := range ordered {
		for _, c := range i.CRDs {
			if kinds[c.Group] == nil {
				kinds[c.Group] = map[string]bool{}
				source[c.Group] = i.Path
			}
			kinds[c.Group][c.Kind] = true
		}
	}
	var gnames []string
	for g := range kinds {
		gnames = append(gnames, g)
	}
	sort.Strings(gnames)
	row := rowDoc{Slug: in.Slug, Catalog: catalog, FactProject: fact, Component: component}
	if catalog == "community" {
		row.Upstream = rules.Upstream
	}
	var gfacts []GroupFact
	crdCount := 0
	for _, g := range gnames {
		var ks []string
		for k := range kinds[g] {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		crdCount += len(ks)
		row.Groups = append(row.Groups, rowGroup{Name: g, Source: blobURL(ownerRepo, newest.commit, source[g]), Kinds: ks})
		gfacts = append(gfacts, GroupFact{Name: g, Kinds: ks})
	}
	rowRaw, err := marshal(row)
	if err != nil {
		return nil, err
	}

	// Report.
	rep := Report{Schema: ReportSchema, Slug: in.Slug, TagPrefix: prefix, MinFrom: minFrom, Groups: gfacts, CRDCount: crdCount, Dropped: dropped}
	if rep.Dropped == nil {
		rep.Dropped = []DroppedTag{}
	}
	rep.Warnings = []string{}
	if len(dropped) > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("WARNING window-shrunk: %d older tag(s) withheld, so minFrom is %s; see droppedTags", len(dropped), minFrom))
	}
	seen := map[Decision]bool{}
	add := func(d Decision) {
		if !seen[d] {
			seen[d] = true
			rep.Decisions = append(rep.Decisions, d)
		}
	}
	for _, r := range window {
		rep.Tags = append(rep.Tags, TagFact{Tag: r.tag, Commit: r.commit})
		for _, d := range r.decisions {
			add(d)
		}
	}
	add(Decision{Rule: RuleTagPrefix, Subject: strconvQuote(prefix), Detail: "every window tag is <prefix>X.Y.Z"})
	add(Decision{Rule: RuleMinFrom, Subject: minFrom, Detail: fmt.Sprintf("oldest line whose tag reads the same %d files as the newest; %d older tag(s) withheld", len(ordered), len(dropped))})
	for _, g := range gfacts {
		add(Decision{Rule: RuleGroupKinds, Subject: g.Name, Detail: strings.Join(g.Kinds, ",")})
	}
	sort.Slice(rep.Decisions, func(i, j int) bool {
		x, y := rep.Decisions[i], rep.Decisions[j]
		if x.Rule != y.Rule {
			return x.Rule < y.Rule
		}
		if x.Subject != y.Subject {
			return x.Subject < y.Subject
		}
		return x.Detail < y.Detail
	})
	rep.FactsDigest = digestFacts(window)

	if len(newest.copies) > 0 {
		rep.NonInstallCopies = newest.copies
		rep.NonInstallCopyCount = len(newest.copies)
	}
	log := changelogText(in.Name, crdCount, gnames, prefix, minFrom, ordered, excls, window)
	if n := len(newest.copies); n > 0 {
		log = strings.Replace(log, "The paths were derived", fmt.Sprintf("%d further definition file(s) outside the declared install paths are reported as non-install copies and are not read. The paths were derived", n), 1)
	}
	return &Result{A: a, B: b, TableRow: rowRaw, Changelog: []byte(log), Report: rep}, nil
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

func changelogText(name string, crds int, groups []string, prefix, minFrom string, ordered []*inclusion, excls []exclOut, window []*tagResult) string {
	regular, linked := 0, 0
	for _, i := range ordered {
		if i.LinkKind {
			linked++
		} else {
			regular++
		}
	}
	var tags []string
	for _, r := range window {
		tags = append(tags, r.tag)
	}
	var b strings.Builder
	b.WriteString("### Added\n\n")
	fmt.Fprintf(&b, "- A CRD extractor target for %s (%d CRDs in %d groups: %s) from the %s line onward, tag family `%s`, with line attestation enabled. ", name, crds, len(groups), strings.Join(groups, ", "), minFrom, prefix)
	fmt.Fprintf(&b, "%d definition files are read from their install paths", regular)
	if linked > 0 {
		fmt.Fprintf(&b, "; %d more are listed as explicit paths because the tree reaches them through symbolic links into a vendored or test-like directory", linked)
	}
	b.WriteString(". ")
	if len(excls) == 0 {
		b.WriteString("No exclusion is needed. ")
	} else {
		var ps []string
		for _, e := range excls {
			ps = append(ps, "`"+e.Path+"`")
		}
		fmt.Fprintf(&b, "%d pinned exclusion(s) are recorded with reviewed evidence: %s. ", len(excls), strings.Join(ps, ", "))
	}
	fmt.Fprintf(&b, "The paths were derived from the source tree at the release tags %s. Attested pairs appear only after release derivation and a data change.\n", strings.Join(tags, ", "))
	return b.String()
}
