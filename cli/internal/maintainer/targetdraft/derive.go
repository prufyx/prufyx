// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// Derive mode (opt-in, Input.DeriveRules): the generator's rules inputs are
// COMPUTED from tree facts at the tags of the run by fixed literal rules, never
// written by judgment. Every value in the derived rules is built from a fixed
// text plus computed values (tag, path, blob id, group list); upstream text
// (file names, group names, file contents) is data: it is validated against a
// strict allow-list before it can appear in any text, and anything outside the
// list is the typed stop derive-unclean-text. A fact the rules cannot decide
// is a typed stop and nothing is written.
//
// What is derived:
//   - installPaths: rule R2 (infer.go, unchanged) first; rule R3 when R2 has no
//     candidate at a tag: the single directory that holds every non-skipped
//     definition file, that no skipped segment disqualifies, and that a
//     literal same-tag reference from OUTSIDE the directory installs (see
//     treeref.go), with every definition file of the directory covered;
//   - exclusions: only a computed foreign-carrier exclusion, per file, and only
//     with a positive proof of foreignness at every tag the file appears
//     in (see foreignProof); each lists tag, path and blob id per tag;
//   - owner-record PROPOSALS (never records) for reserved and shared groups
//     defined under the install directory, and for a scope that needs the
//     owner (scope-needs-owner, which overrides every install-path rule);
//   - NO absentTags, optional entries or ranged entries: an older tag that does
//     not hold the install directory's definitions is withheld by the window
//     logic (reported in droppedTags, window-shortened under --strict-window),
//     never read as proof that definitions were absent.
//
// Derived rules are the committed rules.json; verify-pr re-runs this mode from
// the facts bundle and byte-compares (verify.go). The module is pure: all
// reads go through the Tree of each tag.

// deriveVersion names the derivation; it is part of every idempotence key.
const deriveVersion = "derive/v1"

// Stop codes of derive mode.
const (
	// StopScopeNeedsOwner: more than one candidate scope (directories with
	// disjoint group sets, or component-prefixed tags). An owner decides.
	StopScopeNeedsOwner = "scope-needs-owner"
	// StopInstallPathUnreferenced: rule R3 found one directory but no literal
	// same-tag reference from outside installs every definition file of it.
	StopInstallPathUnreferenced = "install-path-unreferenced"
	// StopDeriveUncleanText: upstream text outside the allow-list would have
	// reached a derived text.
	StopDeriveUncleanText = "derive-unclean-text"
)

func init() {
	nextAction[StopScopeNeedsOwner] = "more than one candidate scope exists (directories whose groups are disjoint, or component-prefixed tags); the owner decides which scope the target covers and writes the rules by hand; the proposal file lists the candidates"
	nextAction[StopInstallPathUnreferenced] = "the only non-skipped definition directory is not named by a literal reference from outside it (a kustomization resources or bases entry, or a chart crds directory) covering every definition file; write a reviewed installPaths rule or change the tag set"
	nextAction[StopDeriveUncleanText] = "a path or group name outside the plain allow-list would reach a derived text; it is never escaped or guessed; write the rules by hand after review"
}

var (
	// derivePathRE is the allow-list of repository paths that may reach a
	// derived text.
	derivePathRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+@=,/-]{0,498}$`)
	// deriveGroupRE is the allow-list of API group names.
	deriveGroupRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,250}[a-z0-9])?$`)
	// deriveModuleRE is the allow-list of Go module paths.
	deriveModuleRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~/-]{0,198}$`)
)

func derivePathOK(p string) bool {
	if !derivePathRE.MatchString(p) || strings.Contains(p, "//") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Fixed texts of every derived entry; never read from repository content.
const (
	deriveInstallReason     = "derived: install directory chosen from tree facts"
	deriveInstallEvidenceR2 = "derived: rule R2 chose this directory at every tag that holds definitions"
	deriveInstallEvidenceR3 = "derived: rule R3 chose this directory: the only non-skipped definition directory, installed by a literal same-tag reference from outside it at every tag that holds definitions"
	deriveExclusionReason   = "derived: non-install carrier of groups not defined by the install paths; foreign origin proven"
)

// ProposalsSchema names the owner-proposal document.
const ProposalsSchema = "prufyx.io/target-derive-proposals/v1"

// ProposalFile is one defining file at one tag.
type ProposalFile struct {
	Tag  string `json:"tag"`
	Path string `json:"path"`
	Blob string `json:"blob"`
}

// ScopeCandidate is one enumerated candidate scope: a directory, its groups
// and its definition files at every tag.
type ScopeCandidate struct {
	Dir    string         `json:"dir"`
	Groups []string       `json:"groups"`
	Files  []ProposalFile `json:"files"`
}

// Proposal kinds.
const (
	ProposalReservedGroup = "reserved-group"
	ProposalSharedGroup   = "shared-group"
	ProposalScope         = "scope-needs-owner"
)

// OwnerProposal is a computed PROPOSAL for an owner record. The job never adds
// a record; the owner signs or refuses. Status is always "proposed".
type OwnerProposal struct {
	Kind                string           `json:"kind"`
	Status              string           `json:"status"`
	Group               string           `json:"group,omitempty"`
	Slug                string           `json:"slug"`
	Repo                string           `json:"repo"`
	DefiningFilesAtTags []ProposalFile   `json:"definingFilesAtTags,omitempty"`
	InstallPathOrCopy   string           `json:"installPathOrCopy,omitempty"`
	CarrierOf           string           `json:"carrierOf,omitempty"`
	TagPrefix           string           `json:"tagPrefix,omitempty"`
	Candidates          []ScopeCandidate `json:"candidates,omitempty"`
}

// LooseningItem is one computed exclusion with its evidence. Every exclusion
// loosens what the install paths read; the signed packet lists them first.
type LooseningItem struct {
	Path     string `json:"path"`
	Evidence string `json:"evidence"`
}

// ProposalsDoc is the file written by --emit-proposals.
type ProposalsDoc struct {
	Schema      string          `json:"schema"`
	Slug        string          `json:"slug"`
	Repo        string          `json:"repo"`
	Stopped     bool            `json:"stopped"`
	Loosening   []LooseningItem `json:"loosening"`
	Proposals   []OwnerProposal `json:"proposals"`
	RulesDigest string          `json:"rulesDigest,omitempty"`
}

// DeriveTagFact is the install directory evidence of one tag.
type DeriveTagFact struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
	Dir    string `json:"dir,omitempty"`
	Rule   string `json:"rule"` // R2, R3 or none
}

// DerivedRulesReport is the report block of a derive run; part of the facts
// digest.
type DerivedRulesReport struct {
	Version      string          `json:"version"`
	TablesDigest string          `json:"tablesDigest"`
	Key          string          `json:"key"`
	RulesDigest  string          `json:"rulesDigest"`
	InstallPath  string          `json:"installPath"`
	Rule         string          `json:"rule"`
	Tags         []DeriveTagFact `json:"tags"`
	Loosening    []LooseningItem `json:"loosening"`
}

// deriveEnv is the ownership knowledge the derivation reads.
type deriveEnv struct {
	index  customresources.Index
	tables string // digest of the ownership table and reserved records
}

// deriveEnvFn builds the environment; tests replace it.
var deriveEnvFn = func() deriveEnv {
	raw, err := customresources.CanonicalTable(customresources.Projects(), customresources.ReservedGroups())
	d := "unreadable"
	if err == nil {
		d = sumHex(raw)
	}
	return deriveEnv{index: customresources.DefaultIndex(), tables: d}
}

// deriveTablesDigest digests every table and text the derivation decides by:
// the skipped-segment tables, the file-name tables and the fixed texts. They
// are constants of this code, so tool_commit covers them too; hashing them
// here makes a table edit change every idempotence key on its own.
func deriveTablesDigest() string {
	var parts []string
	var exact []string
	for s := range inferSkipExact {
		exact = append(exact, s)
	}
	sort.Strings(exact)
	parts = append(parts, "skip:"+strings.Join(exact, ","), "skip-prefix:bundle")
	var tl []string
	for s := range testLikeSegments {
		tl = append(tl, s)
	}
	sort.Strings(tl)
	parts = append(parts, "testlike:"+strings.Join(tl, ","))
	parts = append(parts, deriveVersion, deriveInstallReason, deriveInstallEvidenceR2, deriveInstallEvidenceR3, deriveExclusionReason,
		RefKustomizeResource, RefKustomizeBase, RefChartCRDs, inferNoCandidate)
	return sumHex([]byte(strings.Join(parts, "\n")))
}

// deriveKey is the idempotence key of a run: the derivation (code tables and
// texts), the ownership table, the slug and repository, the strict-window
// flag and the tag list with the commit id of EVERY tag read (a force-moved
// tag changes it). Equal key means equal input: no run is needed.
func deriveKey(env deriveEnv, slug, repo string, strict bool, tags []parsedTag, commits []string) string {
	parts := []string{deriveVersion, deriveTablesDigest(), env.tables, slug, repo, fmt.Sprint(strict)}
	for i, t := range tags {
		parts = append(parts, t.Tag+"="+commits[i])
	}
	return sumHex([]byte(strings.Join(parts, "\n")))
}

// DeriveKey returns the idempotence key of a derive run without scanning: it
// only opens each tag to read its commit id.
func DeriveKey(in Input) (string, error) {
	tags, _, stops := parseTags(in.Tags)
	if len(stops) > 0 {
		return "", &StopError{Stops: stops}
	}
	if in.Source == nil {
		return "", &StopError{Stops: []Stop{stop(StopBadInput, "", "a source is required")}}
	}
	commits := make([]string, len(tags))
	for i, t := range tags {
		_, c, err := in.Source.Open(t.Tag)
		if err != nil {
			return "", &StopError{Stops: []Stop{stop(StopTagUnreadable, t.Tag, err.Error())}}
		}
		commits[i] = c
	}
	return deriveKey(deriveEnvFn(), in.Slug, in.Repo, in.StrictWindow, tags, commits), nil
}

// deriveTags is what one derivation reads: the tags of the run and, per tag,
// the tree, the scan and the commit.
type deriveTags struct {
	slug, ownerRepo string
	tags            []parsedTag
	trees           []Tree
	scans           [][]*finding
	commits         []string
	scanStops       [][]Stop
	env             deriveEnv
	strict          bool
}

// derivedOut is the successful result of a derivation.
type derivedOut struct {
	Rules       *Rules
	RulesJSON   []byte
	Report      *DerivedRulesReport
	Proposals   []OwnerProposal
	Loosening   []LooseningItem
	installRule string
}

func unclean(subject string) string { return safeField(clipText(subject)) }

func clipText(s string) string {
	if len(s) > 120 {
		return strings.ToValidUTF8(s[:120], "") + "..."
	}
	return s
}

// nonSkippedDefs lists the readable definition files of a tag that no
// skipped segment disqualifies.
func nonSkippedDefs(fs []*finding) []*finding {
	var out []*finding
	for _, f := range fs {
		if f.Unreadable == "" && len(f.CRDs) > 0 && !inferSkippedPath(f.Path) {
			out = append(out, f)
		}
	}
	return out
}

func (d *deriveTags) blob(i int, p string) (string, error) {
	b, err := d.trees[i].Read(p)
	if err != nil {
		return "", err
	}
	return gitBlobSHA(b), nil
}

// scopeCandidates enumerates the candidate directories of the given tags with
// their groups and definition files (path and blob id per tag).
func (d *deriveTags) scopeCandidates(idx []int) ([]ScopeCandidate, []Stop) {
	byDir := map[string]*ScopeCandidate{}
	groups := map[string]map[string]bool{}
	for _, i := range idx {
		for _, f := range nonSkippedDefs(d.scans[i]) {
			dir := path.Dir(f.Path) + "/"
			if !derivePathOK(f.Path) {
				return nil, []Stop{stop(StopDeriveUncleanText, unclean(f.Path), "path")}
			}
			c := byDir[dir]
			if c == nil {
				c = &ScopeCandidate{Dir: dir}
				byDir[dir] = c
				groups[dir] = map[string]bool{}
			}
			for _, g := range groupSet(f.CRDs) {
				if !deriveGroupRE.MatchString(g) {
					return nil, []Stop{stop(StopDeriveUncleanText, unclean(f.Path), "group name")}
				}
				groups[dir][g] = true
			}
			b, err := d.blob(i, f.Path)
			if err != nil {
				return nil, []Stop{stop(StopTreeUnreadable, f.Path, err.Error())}
			}
			c.Files = append(c.Files, ProposalFile{Tag: d.tags[i].Tag, Path: f.Path, Blob: b})
		}
	}
	var out []ScopeCandidate
	for dir, c := range byDir {
		for g := range groups[dir] {
			c.Groups = append(c.Groups, g)
		}
		sort.Strings(c.Groups)
		sort.Slice(c.Files, func(a, b int) bool {
			if c.Files[a].Tag != c.Files[b].Tag {
				return c.Files[a].Tag < c.Files[b].Tag
			}
			return c.Files[a].Path < c.Files[b].Path
		})
		out = append(out, *c)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Dir < out[b].Dir })
	return out, nil
}

// scopeTrigger is the deterministic scope-needs-owner trigger of one tag: two
// candidate directories with disjoint group sets.
func scopeTrigger(fs []*finding) bool {
	sets := map[string]map[string]bool{}
	for _, f := range nonSkippedDefs(fs) {
		dir := path.Dir(f.Path)
		if sets[dir] == nil {
			sets[dir] = map[string]bool{}
		}
		for _, c := range f.CRDs {
			sets[dir][c.Group] = true
		}
	}
	var dirs []string
	for dir := range sets {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for a := 0; a < len(dirs); a++ {
		for b := a + 1; b < len(dirs); b++ {
			disjoint := true
			for g := range sets[dirs[a]] {
				if sets[dirs[b]][g] {
					disjoint = false
					break
				}
			}
			if disjoint {
				return true
			}
		}
	}
	return false
}

// tagDerivation is the install directory result of one tag.
type tagDerivation struct {
	dir  string
	rule string // R2, R3, none
}

// deriveTag applies R2 and then R3 to one tag. rule none means the tag holds
// no non-skipped definition at all (the window logic withholds it).
func (d *deriveTags) deriveTag(i int) (tagDerivation, []Stop) {
	tag := d.tags[i].Tag
	fs := d.scans[i]
	if dir, _, _, st := inferOne(tag, fs); st == nil {
		return tagDerivation{dir: dir, rule: "R2"}, nil
	} else if len(st) != 1 || st[0].Detail != inferNoCandidate {
		return tagDerivation{}, st
	}
	// Rule R3.
	for _, f := range fs {
		if f.Unreadable != "" && !inferMayStayUnread(f) {
			return tagDerivation{}, ambiguous(f.Path, "unreadable file outside skipped directories; rule R3 never guesses around it")
		}
	}
	defs := nonSkippedDefs(fs)
	if len(defs) == 0 {
		return tagDerivation{rule: "none"}, nil
	}
	dirs := map[string]bool{}
	for _, f := range defs {
		dirs[path.Dir(f.Path)+"/"] = true
	}
	if len(dirs) != 1 {
		var ds []string
		for k := range dirs {
			ds = append(ds, k)
		}
		sort.Strings(ds)
		return tagDerivation{}, ambiguous(tag, "rule R3: the definitions sit in "+fmt.Sprint(len(ds))+" directories without a ranking")
	}
	var dir string
	for k := range dirs {
		dir = k
	}
	if dir == "./" {
		return tagDerivation{}, ambiguous(tag, "rule R3: a definition file at the repository root")
	}
	for _, f := range fs {
		if strings.HasPrefix(f.Path, dir) && path.Dir(f.Path)+"/" != dir {
			return tagDerivation{}, ambiguous(f.Path, "the directory "+dir+" would also read this file, which rule R3 does not accept")
		}
	}
	// C4: second evidence, a literal same-tag reference from outside the
	// directory, covering every definition file of it.
	entries, err := d.trees[i].Entries()
	if err != nil {
		return tagDerivation{}, []Stop{stop(StopTreeUnreadable, tag, err.Error())}
	}
	refs := ReadTreeRefs(entries, d.trees[i].Read)
	external := false
	for _, r := range refs {
		if !strings.HasPrefix(r.From, dir) && (r.To == dir || strings.HasPrefix(r.To, dir)) {
			external = true
			break
		}
	}
	cov := CoveredFiles(entries, refs)
	if !external {
		return tagDerivation{}, []Stop{stop(StopInstallPathUnreferenced, tag+" "+dir, "no reference from outside the directory names it")}
	}
	for _, f := range defs {
		if !cov[f.Path] {
			return tagDerivation{}, []Stop{stop(StopInstallPathUnreferenced, tag+" "+f.Path, "a definition file of the directory is not covered by a literal reference")}
		}
	}
	return tagDerivation{dir: dir, rule: "R3"}, nil
}

// foreignProof returns a positive proof that a definition file at a tag is a
// foreign carrier, or "". Two proofs exist:
//   - every definition of the file (group and kind) is listed by exactly one
//     OTHER project of the ownership table (owner-listed);
//   - the file sits below a vendor or third_party directory and its module
//     origin, from a vendor/modules.txt line or the nearest go.mod, is a
//     module path that is neither the repository nor below it (module).
//
// A group of a Kubernetes-reserved namespace is no exception: it needs one of
// the two proofs like any other.
func (d *deriveTags) foreignProof(i int, f *finding) string {
	var owners []string
	all := true
	for _, c := range f.CRDs {
		o, a := d.env.index.OwnerOf(c.Group, c.Kind)
		if a != customresources.Owned || o == d.slug || !slugRE.MatchString(o) {
			all = false
			break
		}
		owners = append(owners, o)
	}
	if all && len(owners) > 0 {
		sort.Strings(owners)
		uniq := owners[:0]
		for _, o := range owners {
			if len(uniq) == 0 || uniq[len(uniq)-1] != o {
				uniq = append(uniq, o)
			}
		}
		return "owner-listed " + strings.Join(uniq, ",")
	}
	if m := d.moduleOrigin(i, f.Path); m != "" {
		return "module " + m
	}
	return ""
}

// moduleOrigin returns the foreign module path of a file below a vendor or
// third_party directory, or "" when unproven or when the origin is the
// repository itself.
func (d *deriveTags) moduleOrigin(i int, p string) string {
	segs := strings.Split(p, "/")
	root := -1
	for k := 0; k < len(segs)-1; k++ {
		if s := strings.ToLower(segs[k]); s == "vendor" || s == "third_party" {
			root = k
		}
	}
	if root < 0 {
		return ""
	}
	repoMod := strings.ToLower("github.com/" + d.ownerRepo)
	tree := d.trees[i]
	foreign := func(m string) string {
		if !deriveModuleRE.MatchString(m) {
			return ""
		}
		l := strings.ToLower(m)
		if l == repoMod || strings.HasPrefix(l, repoMod+"/") {
			return ""
		}
		return m
	}
	// Nearest go.mod, from the file's directory up to the vendor directory.
	for k := len(segs) - 1; k > root; k-- {
		dir := strings.Join(segs[:k], "/")
		if b, err := tree.Read(dir + "/go.mod"); err == nil {
			if m := goModulePath(b); m != "" {
				return foreign(m)
			}
			return ""
		}
	}
	vroot := strings.Join(segs[:root+1], "/")
	rel := strings.Join(segs[root+1:], "/")
	if b, err := tree.Read(vroot + "/modules.txt"); err == nil {
		best := ""
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "# ") {
				continue
			}
			f := strings.Fields(line[2:])
			if len(f) < 2 {
				continue
			}
			if m := f[0]; (rel == m || strings.HasPrefix(rel, m+"/")) && len(m) > len(best) {
				best = m
			}
		}
		if best != "" {
			return foreign(best)
		}
	}
	return ""
}

// goModulePath returns the module path of a go.mod text, or "".
func goModulePath(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "module ") || strings.HasPrefix(l, "module\t") {
			m := strings.TrimSpace(l[len("module"):])
			if k := strings.Index(m, "//"); k >= 0 {
				m = strings.TrimSpace(m[:k])
			}
			return strings.Trim(m, "\"`")
		}
	}
	return ""
}

type carrierObs struct {
	tag, blob, proof, segment string
	groups                    []string
}

// skippedSegment names the first skipped segment of a path (for the evidence).
func skippedSegment(p string) string {
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		if inferSkipSegment(s) || testLikeSegments[strings.ToLower(s)] {
			return strings.ToLower(s)
		}
	}
	return ""
}

// derive runs the whole derivation.
func (d *deriveTags) derive() (*derivedOut, []OwnerProposal, []Stop) {
	n := len(d.tags)
	if n == 0 || n != len(d.trees) || n != len(d.scans) || n != len(d.commits) {
		return nil, nil, []Stop{stop(StopBadInput, "derive", "no tags to derive from")}
	}
	// A tag whose tree could not be read completely is never derived from.
	for i := range d.tags {
		if len(d.scanStops[i]) > 0 {
			return nil, nil, sortStops(d.scanStops[i])
		}
	}
	newest := n - 1
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	// C5: scope-needs-owner overrides every install-path rule.
	scope := d.tags[newest].Prefix != "" && d.tags[newest].Prefix != "v"
	for i := range d.tags {
		if scopeTrigger(d.scans[i]) {
			scope = true
		}
	}
	if scope {
		cands, st := d.scopeCandidates(all)
		if len(st) > 0 {
			return nil, nil, st
		}
		prop := OwnerProposal{Kind: ProposalScope, Status: "proposed", Slug: d.slug, Repo: "https://github.com/" + d.ownerRepo, Candidates: cands}
		if p := d.tags[newest].Prefix; p != "" && p != "v" && derivePathOK(p) {
			prop.TagPrefix = p
		}
		return nil, []OwnerProposal{prop}, []Stop{stop(StopScopeNeedsOwner, d.slug, "several candidate scopes or component-prefixed tags; the proposal lists them")}
	}
	// Install directory per tag.
	per := make([]tagDerivation, n)
	for i := range d.tags {
		td, st := d.deriveTag(i)
		if len(st) > 0 {
			return nil, nil, sortStops(st)
		}
		per[i] = td
	}
	if per[newest].dir == "" {
		return nil, nil, ambiguous(d.tags[newest].Tag, "no install directory at the newest tag")
	}
	dir := per[newest].dir
	for i := range per {
		if per[i].dir != "" && per[i].dir != dir {
			return nil, nil, ambiguous(d.tags[i].Tag, fmt.Sprintf("rule %s chooses %s here and %s at %s", per[i].rule, per[i].dir, dir, d.tags[newest].Tag))
		}
	}
	if !derivePathOK(strings.TrimSuffix(dir, "/")) {
		return nil, nil, []Stop{stop(StopDeriveUncleanText, unclean(dir), "install directory")}
	}
	rule := per[newest].rule
	evidence := deriveInstallEvidenceR2
	if rule == "R3" {
		evidence = deriveInstallEvidenceR3
	}

	// C2: computed foreign-carrier exclusions.
	underDir := func(p string) bool { return strings.HasPrefix(p, dir) }
	nonSkipped := map[string]bool{}
	for i := range d.tags {
		for _, f := range nonSkippedDefs(d.scans[i]) {
			for _, c := range f.CRDs {
				nonSkipped[c.Group] = true
			}
		}
	}
	obs := map[string][]carrierObs{}
	bad := map[string]bool{}
	for i := range d.tags {
		for _, f := range d.scans[i] {
			if underDir(f.Path) {
				continue
			}
			if f.Unreadable != "" {
				bad[f.Path] = true
				continue
			}
			if len(f.CRDs) == 0 {
				continue
			}
			o, ok := d.carrierQualifies(i, f, nonSkipped)
			if !ok {
				bad[f.Path] = true
				continue
			}
			obs[f.Path] = append(obs[f.Path], o)
		}
	}
	var paths []string
	for p := range obs {
		if !bad[p] {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var excl []ExclusionRule
	var loose []LooseningItem
	newestTag := d.tags[newest].Tag
	for _, p := range paths {
		list := obs[p]
		if list[len(list)-1].tag != newestTag {
			continue // only a carrier present at the newest tag gets a rule
		}
		var ev []string
		for _, o := range list {
			ev = append(ev, fmt.Sprintf("%s blob %s groups %s segment %s proof %s", o.tag, o.blob, strings.Join(o.groups, ","), o.segment, o.proof))
		}
		evidenceText := "derived: " + strings.Join(ev, "; ")
		excl = append(excl, ExclusionRule{Class: ClassExactFile, Path: p, Reason: deriveExclusionReason, Evidence: evidenceText})
		loose = append(loose, LooseningItem{Path: p, Evidence: evidenceText})
	}
	rules := &Rules{Schema: RulesSchema, InstallSurface: []SurfaceRule{}, Exclusions: excl,
		InstallPaths: []InstallPathRule{{Path: dir, Reason: deriveInstallReason, Evidence: evidence}}}
	if excl == nil {
		rules.Exclusions = []ExclusionRule{}
	}
	raw, err := canonicalJSON(rules)
	if err != nil {
		return nil, nil, []Stop{stop(StopBadInput, "derive", err.Error())}
	}
	if _, err := ParseRules(raw); err != nil {
		return nil, nil, []Stop{stop(StopBadInput, "derive", err.Error())}
	}

	props, st := d.ownerProposals(dir)
	if len(st) > 0 {
		return nil, nil, st
	}
	rep := &DerivedRulesReport{Version: deriveVersion, TablesDigest: deriveTablesDigest(), RulesDigest: sumHex(raw), InstallPath: dir, Rule: rule, Loosening: loose}
	if rep.Loosening == nil {
		rep.Loosening = []LooseningItem{}
	}
	rep.Key = deriveKey(d.env, d.slug, "github.com/"+d.ownerRepo, d.strict, d.tags, d.commits)
	for i, t := range d.tags {
		rep.Tags = append(rep.Tags, DeriveTagFact{Tag: t.Tag, Commit: d.commits[i], Dir: per[i].dir, Rule: per[i].rule})
	}
	sort.Slice(rep.Tags, func(a, b int) bool { return rep.Tags[a].Tag < rep.Tags[b].Tag })
	return &derivedOut{Rules: rules, RulesJSON: raw, Report: rep, Proposals: props, Loosening: loose, installRule: rule}, props, nil
}

// carrierQualifies applies the foreign-carrier conditions to one file at one
// tag: it sits below a skipped segment (and every link that reaches it does
// too), none of its groups appears in any non-skipped file of the run, every
// text that would be written is on the allow-list, and a positive proof of
// foreignness exists. Anything else is "not a carrier": no exclusion.
func (d *deriveTags) carrierQualifies(i int, f *finding, nonSkipped map[string]bool) (carrierObs, bool) {
	if !inferMayStayUnread(&finding{Path: f.Path, Reached: f.Reached}) {
		return carrierObs{}, false
	}
	if !derivePathOK(f.Path) {
		return carrierObs{}, false
	}
	var groups []string
	for _, c := range f.CRDs {
		if nonSkipped[c.Group] || !deriveGroupRE.MatchString(c.Group) {
			return carrierObs{}, false
		}
	}
	groups = groupSet(f.CRDs)
	proof := d.foreignProof(i, f)
	if proof == "" {
		return carrierObs{}, false
	}
	b, err := d.blob(i, f.Path)
	if err != nil {
		return carrierObs{}, false
	}
	return carrierObs{tag: d.tags[i].Tag, blob: b, proof: proof, segment: skippedSegment(f.Path), groups: groups}, true
}

// ownerProposals computes the owner-record proposals for the groups the
// install directory defines: a reserved group without this project's record,
// and a group that another project of the table lists. A carrier outside the
// install directory needs no record.
func (d *deriveTags) ownerProposals(dir string) ([]OwnerProposal, []Stop) {
	byGroup := map[string][]ProposalFile{}
	kindOf := map[string]string{}
	carrier := map[string]string{}
	for i := range d.tags {
		for _, f := range d.scans[i] {
			if !strings.HasPrefix(f.Path, dir) || f.Unreadable != "" {
				continue
			}
			for _, g := range groupSet(f.CRDs) {
				switch {
				case reservedStop(g, d.slug, d.ownerRepo):
					kindOf[g] = ProposalReservedGroup
				default:
					o, a := d.env.index.Owner(g)
					if a == customresources.Owned && o != d.slug {
						kindOf[g] = ProposalSharedGroup
						carrier[g] = o
					} else if a == customresources.Ambiguous {
						kindOf[g] = ProposalSharedGroup
					}
				}
				if kindOf[g] == "" {
					continue
				}
				if !deriveGroupRE.MatchString(g) || !derivePathOK(f.Path) {
					return nil, []Stop{stop(StopDeriveUncleanText, unclean(f.Path), "path or group name")}
				}
				b, err := d.blob(i, f.Path)
				if err != nil {
					return nil, []Stop{stop(StopTreeUnreadable, f.Path, err.Error())}
				}
				byGroup[g] = append(byGroup[g], ProposalFile{Tag: d.tags[i].Tag, Path: f.Path, Blob: b})
			}
		}
	}
	var groups []string
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	var out []OwnerProposal
	for _, g := range groups {
		files := byGroup[g]
		sort.Slice(files, func(a, b int) bool {
			if files[a].Tag != files[b].Tag {
				return files[a].Tag < files[b].Tag
			}
			return files[a].Path < files[b].Path
		})
		out = append(out, OwnerProposal{Kind: kindOf[g], Status: "proposed", Group: g, Slug: d.slug, Repo: "https://github.com/" + d.ownerRepo,
			DefiningFilesAtTags: files, InstallPathOrCopy: "install-path", CarrierOf: carrier[g]})
	}
	return out, nil
}

// annotateDerivedRules adds the derive block to the report, the facts digest
// and the changelog. Only derive runs call it, so every other digest is
// unchanged.
func annotateDerivedRules(res *Result, dr *derivedOut) {
	rep := *dr.Report
	lines := []string{"derived-rules\t" + rep.Version + "\t" + rep.TablesDigest + "\t" + rep.RulesDigest + "\t" + safeField(rep.InstallPath) + "\t" + rep.Rule}
	for _, t := range rep.Tags {
		lines = append(lines, safeField(t.Tag)+"\tderive-tag\t"+safeField(t.Dir)+"\t"+t.Rule)
	}
	for _, l := range rep.Loosening {
		lines = append(lines, "loosening\t"+safeField(l.Path)+"\t"+sumHex([]byte(l.Evidence)))
	}
	res.Report.DerivedRules = &rep
	res.Report.FactsDigest = sumHex([]byte(res.Report.FactsDigest + "\n" + strings.Join(lines, "\n") + "\n"))
	txt := "\nThe rules of this target were derived from tree facts, not written by hand: rule " + rep.Rule + " chose " + rep.InstallPath + "."
	if len(rep.Loosening) == 0 {
		txt += " No exclusion was derived."
	} else {
		txt += " Loosening: " + fmt.Sprint(len(rep.Loosening)) + " exclusion(s), each a non-install carrier with a proof of foreign origin at every tag it appears in:"
		for _, l := range rep.Loosening {
			txt += " " + l.Path + ";"
		}
	}
	res.Changelog = append(res.Changelog, []byte(txt+"\n")...)
	res.RulesJSON = dr.RulesJSON
}
