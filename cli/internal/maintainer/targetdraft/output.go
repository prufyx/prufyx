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
	StopPathFilterNothing     = "path-filter-matches-nothing"
	StopFilterHidesOwned      = "filter-hides-owned-group"
	StopFilterHidesUnowned    = "filter-hides-unowned-group"
	StopPathFilterCount       = "path-filter-count-mismatch"
	StopRepoNotCanonical      = "repo-not-canonical"
	StopComponentNotCanonical = "component-not-canonical"
	StopUpstreamNotCanonical  = "upstream-not-canonical"
	StopDirMixed              = "dir-mixed"
	StopDirIncomplete         = "dir-incomplete"
	StopDirSubdir             = "dir-subdir"
	StopDirMatchNondefault    = "dir-match-nondefault"
	StopDirSetDiffers         = "dir-set-differs"
	StopDirUnsupported        = "dir-collapse-unsupported"
	StopMultiPrefixAmbiguous  = "multi-prefix-ambiguous"
	StopMultiPrefixShort      = "multi-prefix-window-short"
	StopMultiPrefixGroups     = "multi-prefix-groups-differ"

	StopDuplicateCRDDiffers        = "duplicate-crd-differs"
	StopDuplicateCRDNoCommonSource = "duplicate-crd-no-common-source"
	StopDuplicateCRDUnresolvable   = "duplicate-crd-unresolvable"

	StopInstallPathAmbiguous   = "install-path-ambiguous"
	StopInstallPathHidesCRD    = "install-path-hides-crd"
	StopInstallPathCopyDiffers = "install-path-copy-differs"
)

var nextAction = map[string]string{
	StopBadInput:                   "fix the command line; every required option is listed in the usage text",
	StopTagGrammar:                 "pass final release tags of the form <prefix>X.Y.Z, each once",
	StopTagLineDuplicate:           "pass one final tag per release line",
	StopTagPrefixMixed:             "pass tags of one prefix family",
	StopTagPrefixUnsupported:       "the extractor accepts no prefix, v, knative-v or a chart prefix; a new prefix needs an extractor change",
	StopTagUnreadable:              "make the tag available in the local checkout (fetch outside this command)",
	StopTreeUnreadable:             "repair or re-clone the local checkout",
	StopSymlinkEscapes:             "a link that leaves the tree cannot be read; review the link and either drop the tag window or pin a rule after review",
	StopUnreadableShape:            "the file is not a plain definition (template, patch or no spec.versions); narrow the window past it or ask for an extractor change",
	StopDocsOnlyCRDSource:          "the only definitions sit under a documentation directory; add a reviewed installSurface rule naming the file, or choose another source",
	StopUnpinnedExclusion:          "a definition file outside the install paths needs a reviewed exclusion rule (exact-file or fixture-dir) with pinned evidence",
	StopExclusionOwnedGroup:        "the excluded file defines a group the target reads; narrow the rule or review the file as install surface",
	StopFixtureHiddenOwnedCRD:      "a fixture defines an owned CRD the target does not read; review it as install surface or remove the rule",
	StopRuleMatchesNothing:         "the rule names a path no tag of the window carries; drop or correct the rule",
	StopDuplicateCRD:               "two files define the same group and kind; pin which one is the source",
	StopReservedGroup:              "a Kubernetes-reserved group needs a reviewed ownership record before a target may list it",
	StopGroupOwnedElsewhere:        "another table project lists the group; use a kinds-only row after review",
	StopNoCRDSource:                "no install path holds a definition; give an installSurface rule or choose another source",
	StopWindowTooShort:             "fewer than two tags read the same files; widen the tag set or fix the unreadable tag",
	StopForeignCopyUnpinned:        "a definition file of another project's group sits outside the default-excluded directories (documentation or fixtures); add a reviewed pinned exclusion rule for the exact file or fixture directory",
	StopWindowShortened:            "older tags were withheld and --strict-window forbids a shorter window; fix the withheld tags or drop the flag after review",
	StopInstallPathNothing:         "an installPaths entry holds no definition file at this tag; correct the entry, or narrow the window past the tag",
	StopPathFilterNothing:          "a pathFilter entry matches no file under installPaths at this tag; correct the glob, or narrow the window past the tag",
	StopFilterHidesUnowned:         "a pathFilter entry matches a file whose group has no single known owner in the ownership index; add the group to the reviewed index or narrow the glob so the file stays install surface",
	StopPathFilterCount:            "a pathFilter entry matches a different number of files than its pinned expectFiles at this tag; re-review the files the glob matches and pin the exact count, or narrow the glob",
	StopFilterHidesOwned:           "a pathFilter entry matches a file that defines a group the target reads; narrow the glob or review the file as install surface",
	StopRepoNotCanonical:           "use the canonical lower-case form github.com/<owner>/<name> (no scheme, no .git suffix, no spaces, no capital letters)",
	StopComponentNotCanonical:      "use pkg:github/<owner>/<name> in lower case, matching the repository",
	StopUpstreamNotCanonical:       "a community row's upstream.repository must be https://github.com/<owner>/<name> of the repository, its licenseSource a /blob/<40-hex commit>/LICENSE or COPYING file under it with a valid license expression; a CNCF row takes no upstream block",
	StopDirMixed:                   "the directory holds a file the default match would read that is not an installed definition file; keep exact files or review the directory",
	StopDirIncomplete:              "a file of the directory matches the guard but not the match, or is a symbolic link the read would refuse; the loader would report an incomplete inventory, so keep exact files",
	StopDirSubdir:                  "a definition file sits in a subdirectory of the directory; recursion is not emitted, keep exact files",
	StopDirMatchNondefault:         "a definition file of the directory is outside the one default match; a custom pattern is never invented, keep exact files or review a hand-written entry",
	StopDirSetDiffers:              "the directory would read another set of files than the exact install files at some window tag; keep exact files",
	StopDirUnsupported:             "directory collapse does not apply to this input (exclusions, optional or ranged installPaths, pathFilter, range-check tags, links, root or test-like files); drop --collapse-directories",
	StopMultiPrefixAmbiguous:       "the tags do not form exactly two disjoint prefix lines with one switch-over; pass one prefix per run, or fix the tag list",
	StopMultiPrefixShort:           "a prefix has fewer than two tags in its window; widen that prefix's tags or run the other prefix alone",
	StopMultiPrefixGroups:          "the two prefixes read different API groups, so they are different release lines; run each prefix as its own target after review",
	StopCommunityUpstream:          "a community-catalog row needs the upstream block (name, repository, license, licenseSource) in the rules file",
	StopDuplicateCRDDiffers:        "the copies differ in their decoded spec at a tag; pin one source by a reviewed installPaths rule, or fix the tag window",
	StopDuplicateCRDNoCommonSource: "the chosen copy does not hold the definition at a tag where another copy does; pin the source by a reviewed installPaths rule or narrow the window",
	StopDuplicateCRDUnresolvable:   "the copies cannot be reduced to one source without losing a definition; pin the source by a reviewed installPaths rule",
	StopInstallPathAmbiguous:       "the install directory cannot be inferred unambiguously at every tag (no candidate, several directories, a different directory at some tag, or a file the directory would read that the rule does not rank); write a reviewed installPaths rule instead",
	StopInstallPathHidesCRD:        "a definition file outside the install paths defines a group and kind that no install path defines; widen the installPaths after review, or add a reviewed exclusion, so no real definition stays hidden",
	StopInstallPathCopyDiffers:     "a definition file outside the install paths repeats an installed definition with a different decoded spec; review which copy users install and pin it by a reviewed installPaths rule",
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
	RuleFilteredCopy           = "filtered-copy"
	RuleExcludePinnedFile      = "exclude-pinned-file"
	RuleExcludePinnedFixtures  = "exclude-pinned-fixtures"
	RuleFixtureDrop            = "fixture-drop"
	RuleForeignCopy            = "foreign-copy"
	RuleGroupKinds             = "group-kinds"
	RuleTagPrefix              = "tag-prefix"
	RuleMinFrom                = "min-from"
	RuleCollapseDirectory      = "collapse-directory"
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
	Schema    string `json:"schema"`
	Slug      string `json:"slug"`
	TagPrefix string `json:"tagPrefix"`
	// TagPrefixes and PrefixWindows are present only for a multi-prefix run
	// (internal multi-prefix option): the prefixes in tagPrefixes order and the proven
	// window of each. Neither is part of FactsDigest.
	TagPrefixes   []string       `json:"tagPrefixes,omitempty"`
	PrefixWindows []PrefixWindow `json:"prefixWindows,omitempty"`
	// PrefixKindDifferences is a warning, never a stop: group/kind pairs read
	// by only one of the two prefix windows.
	PrefixKindDifferences []string     `json:"prefixKindDifferences,omitempty"`
	MinFrom               string       `json:"minFrom"`
	Tags                  []TagFact    `json:"tags"`
	Dropped               []DroppedTag `json:"droppedTags"`
	Warnings              []string     `json:"warnings"`
	Decisions             []Decision   `json:"decisions"`
	Groups                []GroupFact  `json:"groups"`
	CRDCount              int          `json:"crdCount"`
	FactsDigest           string       `json:"factsDigest"`
	// NonInstallCopies are the definition files outside the pinned
	// installPaths at any window tag, one entry per distinct (path, groups,
	// unreadable) with the window tags it appears in; sorted. Present only
	// when installPaths is used.
	NonInstallCopyCount int              `json:"nonInstallCopyCount,omitempty"`
	NonInstallCopies    []NonInstallCopy `json:"nonInstallCopies,omitempty"`
	// OptionalPaths lists, per window tag and optional installPaths entry,
	// whether the file was read or its absence verified. Present only when
	// an optional entry is used; part of FactsDigest then.
	OptionalPaths []OptionalFact `json:"optionalPaths,omitempty"`
	// RangedPaths lists, per window tag, the ranged installPaths entry
	// selected for each role (role, then path); RangeCheckedTags are the
	// extra tags the boundary check read, sorted. Present only when ranged
	// entries are used; part of FactsDigest then.
	RangedPaths      []RangedFact `json:"rangedPaths,omitempty"`
	RangeCheckedTags []string     `json:"rangeCheckedTags,omitempty"`
	// FilteredCopies are the files under installPaths removed from the install
	// surface by a pathFilter entry, one per distinct (path, groups), with the
	// window tags; sorted. Present only when pathFilter is used.
	FilteredCopyCount int            `json:"filteredCopyCount,omitempty"`
	FilteredCopies    []FilteredCopy `json:"filteredCopies,omitempty"`
	// InferredInstallPaths is the install directory chosen by rule R2 and the
	// ranking evidence of every tag. Present only when inference ran (internal);
	// part of FactsDigest then.
	InferredInstallPaths *InferredInstallPaths `json:"inferredInstallPaths,omitempty"`
	// PatchFragments lists, per window tag, the kustomize patch fragments set
	// aside as non-install, non-definition files. Present only with
	// a fragment; part of FactsDigest then.
	PatchFragments []PatchFragmentFact `json:"patchFragments,omitempty"`
	// Representation is "directory" when install files were written as
	// directory entries; absent (exact files) otherwise. Directories lists
	// each directory entry with the file names it reads, identical at every
	// window tag. Neither is part of FactsDigest: a directory entry is a
	// representation of the same file set.
	Representation string          `json:"representation,omitempty"`
	Directories    []DirectoryFact `json:"directories,omitempty"`
}

// PatchFragmentFact is the patch fragments set aside at one window tag.
type PatchFragmentFact struct {
	Tag   string   `json:"tag"`
	Paths []string `json:"paths"`
}

// DirectoryFact is one directory entry of the target.
type DirectoryFact struct {
	Dir   string   `json:"dir"`
	Files []string `json:"files"`
}

// FilteredCopy is a definition file under installPaths that a pathFilter entry
// removed from the install surface. It is reported, never dropped silently.
type FilteredCopy struct {
	Path   string   `json:"path"`
	Glob   string   `json:"glob"`
	Groups []string `json:"groups"`
	Tags   []string `json:"tags,omitempty"`
}

// unionFiltered merges the per-tag filtered copies of the window.
func unionFiltered(window []*tagResult) []FilteredCopy {
	idx := map[string]int{}
	var out []FilteredCopy
	for _, r := range window {
		for _, c := range r.filtered {
			k := c.Path + "\x00" + c.Glob + "\x00" + strings.Join(c.Groups, ",")
			i, ok := idx[k]
			if !ok {
				idx[k] = len(out)
				i = len(out)
				out = append(out, FilteredCopy{Path: c.Path, Glob: c.Glob, Groups: c.Groups})
			}
			out[i].Tags = append(out[i].Tags, r.tag)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.Path != y.Path {
			return x.Path < y.Path
		}
		if x.Glob != y.Glob {
			return x.Glob < y.Glob
		}
		return strings.Join(x.Groups, ",") < strings.Join(y.Groups, ",")
	})
	return out
}

// NonInstallCopy is a definition file the target does not read because it is
// outside the pinned installPaths. It is reported, never dropped silently.
type NonInstallCopy struct {
	Path       string   `json:"path"`
	Groups     []string `json:"groups"`
	Unreadable string   `json:"unreadable,omitempty"`
	// Tags are the window tags that carry this copy, in window order. Filled
	// when the report is built.
	Tags []string `json:"tags,omitempty"`
}

// unionCopies merges the per-tag copies of the window into one sorted list.
func unionCopies(window []*tagResult) []NonInstallCopy {
	idx := map[string]int{}
	var out []NonInstallCopy
	for _, r := range window {
		for _, c := range r.copies {
			k := c.Path + "\x00" + strings.Join(c.Groups, ",") + "\x00" + c.Unreadable
			i, ok := idx[k]
			if !ok {
				idx[k] = len(out)
				i = len(out)
				out = append(out, NonInstallCopy{Path: c.Path, Groups: c.Groups, Unreadable: c.Unreadable})
			}
			out[i].Tags = append(out[i].Tags, r.tag)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.Path != y.Path {
			return x.Path < y.Path
		}
		if gx, gy := strings.Join(x.Groups, ","), strings.Join(y.Groups, ","); gx != gy {
			return gx < gy
		}
		return x.Unreadable < y.Unreadable
	})
	return out
}

// pathOut is one paths entry: an exact file, or (Directory) a directory read
// with the one default match and guard.
type pathOut struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory,omitempty"`
	Match     string `json:"match,omitempty"`
	Guard     string `json:"guard,omitempty"`
}

// key names an entry for comparison: an exact file by its path (unchanged),
// a directory entry by path, match and guard.
func (p pathOut) key() string {
	if !p.Directory {
		return p.Path
	}
	return p.Path + " [directory match=" + p.Match + " guard=" + p.Guard + "]"
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
		switch {
		case p.Directory && (p.Match == "" || p.Guard == ""):
			return nil, fmt.Errorf("directory entry %q needs match and guard", p.Path)
		case !p.Directory && (p.Match != "" || p.Guard != ""):
			return nil, fmt.Errorf("file entry %q takes no match or guard", p.Path)
		case p.Directory:
			objs = append(objs, "{\"path\": "+jstr(p.Path)+", \"directory\": true, \"match\": "+jstr(p.Match)+", \"guard\": "+jstr(p.Guard)+"}")
		default:
			objs = append(objs, "{\"path\": "+jstr(p.Path)+"}")
		}
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

func build(in Input, catalog, component, fact, ownerRepo, prefix string, prefixes []string, prefixWindows []PrefixWindow, minFrom string, rules *Rules, window []*tagResult, dropped []DroppedTag, newest, citation *tagResult, union map[string]*inclusion, dirs []collapsedDir) (*Result, error) {
	ordered := orderPaths(newest.included)
	// With ranged entries the target lists the union of the paths read at the
	// window tags (the moved directory appears with both locations); groups
	// and kinds still come from the newest tag.
	pathsOrdered := ordered
	if union != nil {
		pathsOrdered = orderPaths(union)
	}
	body := targetBody{Project: in.Slug, Name: in.Name, Repo: in.Repo, Component: component, FactProject: fact,
		TagPrefixes: tagPrefixList(prefix, prefixes), MinFrom: minFrom, Paths: []pathOut{}, Exclude: []exclOut{}}
	if catalog == "community" {
		body.Catalog = "community"
	}
	if dirs != nil {
		for _, d := range dirs {
			body.Paths = append(body.Paths, pathOut{Path: d.Dir, Directory: true, Match: DefaultDirMatch, Guard: DefaultDirGuard})
		}
	} else {
		for _, i := range pathsOrdered {
			body.Paths = append(body.Paths, pathOut{Path: i.Path})
		}
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
	if citation == nil {
		citation = newest
	}
	for _, i := range orderPaths(citation.included) {
		for _, c := range i.CRDs {
			if _, ok := source[c.Group]; !ok {
				source[c.Group] = i.Path
			}
		}
	}
	for _, i := range ordered {
		for _, c := range i.CRDs {
			if kinds[c.Group] == nil {
				kinds[c.Group] = map[string]bool{}
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
		row.Groups = append(row.Groups, rowGroup{Name: g, Source: blobURL(ownerRepo, citation.commit, source[g]), Kinds: ks})
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
	if prefixes != nil {
		rep.TagPrefixes = append([]string(nil), prefixes...)
		rep.PrefixWindows = prefixWindows
		rep.PrefixKindDifferences = kindDifferences(prefixWindows)
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
	if prefixes == nil {
		add(Decision{Rule: RuleTagPrefix, Subject: strconvQuote(prefix), Detail: "every window tag is <prefix>X.Y.Z"})
	} else {
		for _, pw := range prefixWindows {
			add(Decision{Rule: RuleTagPrefix, Subject: strconvQuote(pw.Prefix), Detail: "its own window tags are <prefix>X.Y.Z: " + strings.Join(pw.Tags, ",") + "; the prefix lines are listed side by side, never merged"})
		}
	}
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
	if dirs != nil {
		rep.Representation = "directory"
		for _, d := range dirs {
			rep.Directories = append(rep.Directories, DirectoryFact{Dir: d.Dir, Files: d.Files})
			add(Decision{Rule: RuleCollapseDirectory, Subject: d.Dir, Detail: fmt.Sprintf("%d file(s) read by the default match at every window tag: %s", len(d.Files), strings.Join(d.Files, ","))})
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
	}

	for _, r := range window {
		if len(r.fragments) > 0 {
			rep.PatchFragments = append(rep.PatchFragments, PatchFragmentFact{Tag: r.tag, Paths: append([]string(nil), r.fragments...)})
		}
	}
	copies := unionCopies(window)
	if len(copies) > 0 {
		rep.NonInstallCopies = copies
		rep.NonInstallCopyCount = len(copies)
	}
	filtered := unionFiltered(window)
	if len(filtered) > 0 {
		rep.FilteredCopies = filtered
		rep.FilteredCopyCount = len(filtered)
	}
	family := prefix
	if prefixes != nil {
		family = strings.Join(prefixes, "` and `")
	}
	log := changelogText(in.Name, crdCount, gnames, family, minFrom, pathsOrdered, excls, window, len(copies), len(filtered))
	return &Result{A: a, B: b, TableRow: rowRaw, Changelog: []byte(log), Report: rep}, nil
}

// tagPrefixList is the target's tagPrefixes list: the one prefix, or the
// prefixes of a multi-prefix run.
func tagPrefixList(prefix string, prefixes []string) []string {
	if prefixes != nil {
		return append([]string(nil), prefixes...)
	}
	return []string{prefix}
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

func changelogText(name string, crds int, groups []string, prefix, minFrom string, ordered []*inclusion, excls []exclOut, window []*tagResult, copies, filtered int) string {
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
	if copies > 0 {
		fmt.Fprintf(&b, "%d further definition file(s) outside the declared install paths are reported as non-install copies and are not read. ", copies)
	}
	if filtered > 0 {
		fmt.Fprintf(&b, "%d definition file(s) inside the declared install paths are removed by a reviewed path filter, reported as filtered copies and not read. ", filtered)
	}
	fmt.Fprintf(&b, "The paths were derived from the source tree at the release tags %s. Attested pairs appear only after release derivation and a data change.\n", strings.Join(tags, ", "))
	return b.String()
}
