// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"context"
	"errors"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// CueVersion identifies the removal cue list and the hedge list below.
const CueVersion = "2"

// cueRE is the removal cue list: a cited list item must contain one.
var cueRE = regexp.MustCompile(`(?i)remov|dropp|delet|no longer|\bgone\b|purg`)

// hedgeRE finds a removal cue that is negated ("not removed"), in the
// future ("will be removed", "scheduled for removal") or undone
// ("reverted", "restored"). A cited item that holds one is never verified,
// whatever else it says.
var hedgeRE = regexp.MustCompile(`(?i)\b(not|never|no)\s+(be\s+|been\s+|being\s+|yet\s+)?(remov|dropp|delet|purg)|n't\s+(be\s+|been\s+)?(remov|dropp|delet|purg)|\b(will|would|shall|to|may|might|could|should)\s+(be\s+|eventually\s+be\s+)?(remov|dropp|delet|purg)|\b(scheduled|planned|slated|targeted)\s+for\s+(remov|delet)|\b(revert\w*|restor\w*|re-?added|reintroduc\w*)\b`)

// Verdicts.
const (
	VerdictVerified = "verified"
	VerdictLead     = "lead"
	VerdictDropped  = "dropped"
)

// Reasons, in the order the steps run.
const (
	ReasonSourceMismatch        = "source-mismatch"
	ReasonSourceRefused         = "source-refused"
	ReasonReleaseMismatch       = "release-mismatch"
	ReasonSourceUnbound         = "source-unbound"
	ReasonUnparsedSection       = "unparsed-section"
	ReasonKindNotAllowed        = "kind-not-allowed"
	ReasonNameInvalid           = "name-invalid"
	ReasonNoCitedCue            = "no-cited-cue"
	ReasonAmbiguousCitation     = "ambiguous-citation"
	ReasonHiddenContent         = "hidden-content"
	ReasonHedgedCue             = "hedged-cue"
	ReasonInventoryIncomplete   = "inventory-incomplete"
	ReasonNotInInventory        = "not-in-inventory"
	ReasonStillPresent          = "still-present"
	ReasonNoProvenance          = "no-provenance"
	ReasonProvenanceUnbounded   = "provenance-unbounded"
	ReasonProvenanceUnavailable = "provenance-unavailable"
)

// kindRule is what a claim kind needs: a name form and the inventories
// the name must be in (earlier release) and absent from (later release).
type kindRule struct {
	name        *regexp.Regexp
	present, to string
}

// allowedKinds are the only kinds that can verify, and only for
// Kubernetes: kinds without a complete mechanical inventory stay leads.
var allowedKinds = map[string]kindRule{
	"removed_feature_gate": {
		name:    regexp.MustCompile(`^[A-Z][A-Za-z0-9]{2,60}$`),
		present: InventoryFeatureGates, to: InventoryFeatureGateNames,
	},
	"removed_api_version": {
		name:    regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*/v[1-9][0-9]{0,2}((alpha|beta)[1-9][0-9]{0,2})?$`),
		present: InventoryServedAPIVersions, to: InventoryServedAPIVersions,
	},
}

// AllowedKinds lists the kinds that can verify.
func AllowedKinds() []string {
	out := make([]string, 0, len(allowedKinds))
	for k := range allowedKinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Inputs are what Verify reads besides the bundle.
type Inputs struct {
	Reader extract.PinnedReader
	Tags   extract.TagSource
	// History lists the commits of the release range; nil means none is
	// available (every claim that reaches provenance stays a lead).
	History History
	// Inventory serves the mechanical inventories.
	Inventory Inventories
	// HistoryLimit bounds the commit walk; 0 means DefaultHistoryLimit.
	HistoryLimit int
}

// ErrInputsIncomplete means Verify could not read an input it needs. No
// report is produced.
var ErrInputsIncomplete = errors.New("consensus inputs are incomplete")

// Citation is the list item a name was found in.
type Citation struct {
	Name string `json:"name"`
	// NormalisedLines and OriginalLines are inclusive 1-based ranges, in
	// the normalised section and in the source file.
	NormalisedLines [2]int `json:"normalisedLines"`
	OriginalLines   [2]int `json:"originalLines"`
	// Quote is the item's full normalised text.
	Quote string `json:"quote"`
	// Occurrences counts identical copies of the item in the section.
	Occurrences int `json:"occurrences"`
}

// InventoryRef names the inventories a claim was checked against.
type InventoryRef struct {
	FromDigest string `json:"fromDigest"`
	ToDigest   string `json:"toDigest"`
}

// PRProvenance is one pull request reference of a cited item and the
// commit of the release range whose subject carries it.
type PRProvenance struct {
	PR     int    `json:"pr"`
	Commit string `json:"commit"`
}

// ClaimResult is the verdict on one claim.
type ClaimResult struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Component  string         `json:"component,omitempty"`
	Names      []string       `json:"names"`
	Verdict    string         `json:"verdict"`
	Reason     string         `json:"reason,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	Citations  []Citation     `json:"citations"`
	Inventory  *InventoryRef  `json:"inventory,omitempty"`
	Provenance []PRProvenance `json:"provenance"`
}

// Summary counts verdicts.
type Summary struct {
	Verified int `json:"verified"`
	Lead     int `json:"lead"`
	Dropped  int `json:"dropped"`
}

// ReportRelease is a release as Verify resolved it.
type ReportRelease struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

// Report is the verifier's result.
type Report struct {
	Schema            string        `json:"schema"`
	NormaliserVersion string        `json:"normaliserVersion"`
	CueVersion        string        `json:"cueVersion"`
	HistoryLimit      int           `json:"historyLimit"`
	Source            Source        `json:"source"`
	FromRelease       ReportRelease `json:"fromRelease"`
	ToRelease         ReportRelease `json:"toRelease"`
	Claims            []ClaimResult `json:"claims"`
	Summary           Summary       `json:"summary"`
}

// AllVerified reports whether every claim verified.
func (r *Report) AllVerified() bool { return r.Summary.Verified == len(r.Claims) && len(r.Claims) > 0 }

// Canonical renders the report as canonical JSON.
func (r *Report) Canonical() ([]byte, error) { return extract.Canonical(r) }

// verdictError carries a step failure.
type verdictError struct {
	verdict, reason, detail string
}

func fail(verdict, reason, format string, a ...any) *verdictError {
	return &verdictError{verdict: verdict, reason: reason, detail: fmt.Sprintf(format, a...)}
}

// Verify checks every claim of a bundle. Steps run in order and the first
// failure decides the claim:
//
//  1. the source is pinned: the releases match the section rule and the
//     recorded tags, the release notes are read at the later release's tag
//     commit (or a descendant of it on its release branch), the file digest
//     matches the bytes read by commit, the normalised digest is recomputed
//     equal, and every line of the section is inside the line grammar;
//  2. the kind is allowed;
//  3. every name has the kind's form;
//  4. every name is cited by exactly one distinct list item that carries
//     a removal cue and no hidden content;
//  5. every name is in the complete inventory of the earlier release;
//  6. every name is absent from the complete inventory of the later one;
//  7. every cited item references pull requests of the same repository,
//     each in a commit subject of the release range.
//
// It returns an error wrapping ErrInputsIncomplete when an input cannot be
// read; the caller must then not use any result.
func Verify(ctx context.Context, b *Bundle, in Inputs) (*Report, error) {
	if b == nil {
		return nil, errors.New("no bundle")
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	limit := in.HistoryLimit
	if limit <= 0 {
		limit = DefaultHistoryLimit
	}
	rep := &Report{
		Schema: ReportSchema, NormaliserVersion: NormaliserVersion, CueVersion: CueVersion, HistoryLimit: limit,
		Source: b.Source, FromRelease: ReportRelease{Tag: b.FromRelease.Tag, Commit: b.FromRelease.Commit},
		ToRelease: ReportRelease{Tag: b.ToRelease.Tag},
		Claims:    []ClaimResult{},
	}
	v := &verifier{bundle: b, in: in, limit: limit, ctx: ctx}
	repo, _ := extract.ParseRepo(b.Source.Repo)
	v.repo = repo
	sourceFail, err := v.pinSource(rep)
	if err != nil {
		return nil, err
	}
	for _, c := range b.Claims {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res := ClaimResult{ID: c.ID, Kind: c.Kind, Component: c.Component, Names: append([]string{}, c.Names...), Citations: []Citation{}, Provenance: []PRProvenance{}}
		f := sourceFail
		if f == nil {
			f, err = v.claim(c, &res)
			if err != nil {
				return nil, err
			}
		}
		if f != nil {
			res.Verdict, res.Reason, res.Detail = f.verdict, f.reason, f.detail
		} else {
			res.Verdict = VerdictVerified
		}
		switch res.Verdict {
		case VerdictVerified:
			rep.Summary.Verified++
		case VerdictLead:
			rep.Summary.Lead++
		default:
			rep.Summary.Dropped++
		}
		rep.Claims = append(rep.Claims, res)
	}
	return rep, nil
}

type verifier struct {
	ctx      context.Context
	bundle   *Bundle
	in       Inputs
	limit    int
	repo     extract.RepoRef
	norm     Normalised
	items    []item
	toCommit string
	// cited memoises, per name, the items that cite it with a cue.
	cited map[string][]int
	// sections maps every normalised line to its heading section.
	sections []section

	history     map[int]string
	historyErr  *verdictError
	historyDone bool
}

// pinSource runs step 1. A failure applies to every claim.
func (v *verifier) pinSource(rep *Report) (*verdictError, error) {
	b := v.bundle
	s := b.Source
	if b.FromRelease.Repo != s.Repo {
		return fail(VerdictDropped, ReasonReleaseMismatch, "the releases and the source are of different repositories"), nil
	}
	if s.Section != b.ToRelease.Tag {
		return fail(VerdictDropped, ReasonReleaseMismatch, "the section %q is not the later release %q", s.Section, b.ToRelease.Tag), nil
	}
	spec := SectionSpec{Repo: s.Repo, Path: s.Path, Version: s.Section}
	if _, err := ruleFor(spec); err != nil {
		return fail(VerdictDropped, ReasonSourceRefused, "%v", err), nil
	}
	toMinor, okTo := KubernetesMinor(b.ToRelease.Tag)
	fromMinor, okFrom := KubernetesMinor(b.FromRelease.Tag)
	if !okTo || !okFrom || fromMinor+1 != toMinor {
		return fail(VerdictDropped, ReasonReleaseMismatch, "the earlier release must be the minor release just before %s", b.ToRelease.Tag), nil
	}
	if v.in.Tags == nil {
		return nil, fmt.Errorf("%w: no tag source", ErrInputsIncomplete)
	}
	tags, err := v.in.Tags.Tags(v.repo)
	if err != nil {
		return nil, fmt.Errorf("%w: tags of %s: %v", ErrInputsIncomplete, v.repo.Key, err)
	}
	var fromCommit, toCommit string
	lineTags := map[string]bool{}
	linePrefix := strings.TrimSuffix(b.ToRelease.Tag, "0")
	for _, t := range tags {
		switch t.Name {
		case b.FromRelease.Tag:
			fromCommit = t.Commit
		case b.ToRelease.Tag:
			toCommit = t.Commit
		}
		if rest, ok := strings.CutPrefix(t.Name, linePrefix); ok && patchRE.MatchString(rest) {
			lineTags[t.Commit] = true
		}
	}
	if fromCommit == "" || toCommit == "" {
		return nil, fmt.Errorf("%w: tag %s or %s is not recorded", ErrInputsIncomplete, b.FromRelease.Tag, b.ToRelease.Tag)
	}
	rep.ToRelease.Commit = toCommit
	v.toCommit = toCommit
	if fromCommit != b.FromRelease.Commit {
		return fail(VerdictDropped, ReasonReleaseMismatch, "tag %s points at %s, not %s", b.FromRelease.Tag, fromCommit, b.FromRelease.Commit), nil
	}
	if f, err := v.bindSource(toCommit, lineTags, toMinor); f != nil || err != nil {
		return f, err
	}
	if v.in.Reader == nil {
		return nil, fmt.Errorf("%w: no reader", ErrInputsIncomplete)
	}
	src, err := v.in.Reader.Read(v.repo, s.Commit, s.Path)
	if err != nil {
		if errors.Is(err, extract.ErrNotFound) {
			return fail(VerdictDropped, ReasonSourceMismatch, "%s does not exist at %s", s.Path, s.Commit), nil
		}
		return nil, fmt.Errorf("%w: %s at %s: %v", ErrInputsIncomplete, s.Path, s.Commit, err)
	}
	if FileDigest(src) != s.FileSHA256 {
		return fail(VerdictDropped, ReasonSourceMismatch, "the file digest does not match the bytes at the commit"), nil
	}
	if s.NormaliserVersion != NormaliserVersion {
		return fail(VerdictDropped, ReasonSourceMismatch, "normaliser version %q, this verifier is %q", s.NormaliserVersion, NormaliserVersion), nil
	}
	norm, err := Normalise(src, spec)
	if err != nil {
		return fail(VerdictDropped, ReasonSourceRefused, "%v", err), nil
	}
	if norm.Digest() != s.NormalisedSHA256 {
		return fail(VerdictDropped, ReasonSourceMismatch, "the normalised digest does not match"), nil
	}
	v.norm = norm
	v.sections = headingSections(norm)
	v.items = listItems(norm)
	v.cited = map[string][]int{}
	return nil, nil
}

// barrierBefore returns the first barrier of the release section at or
// before an original line.
func (v *verifier) barrierBefore(original int) *Problem {
	for i := range v.norm.Barriers {
		if v.norm.Barriers[i].Original <= original {
			return &v.norm.Barriers[i]
		}
	}
	return nil
}

// headingSections maps every line to the section it belongs to: the span
// from its nearest heading to the next heading of the same or a higher
// level. A section is unparsed when any line in that span (its child
// sections included) is outside the line grammar, or a construct was left
// open at its heading.
func headingSections(n Normalised) []section {
	level := func(t string) int {
		if m := sectionHeadingRE.FindStringSubmatch(t); m != nil {
			return len(m[1])
		}
		return 0
	}
	var heads []int
	for i, l := range n.Lines {
		if level(l.Text) > 0 {
			heads = append(heads, i)
		}
	}
	unparsed := map[int]bool{}
	firstProblem := map[int]string{}
	for _, h := range heads {
		lv := level(n.Lines[h].Text)
		for j := h; j < len(n.Lines); j++ {
			if j > h {
				if l := level(n.Lines[j].Text); l > 0 && l <= lv {
					break
				}
			}
			if p := n.Lines[j].Problem; p != "" && !unparsed[h] {
				unparsed[h] = true
				firstProblem[h] = fmt.Sprintf("line %d, %s", n.Lines[j].Original, p)
			}
		}
	}
	out := make([]section, len(n.Lines))
	cur := -1
	for i, l := range n.Lines {
		if level(l.Text) > 0 {
			cur = i
		}
		out[i] = section{heading: cur, unparsed: cur < 0 || unparsed[cur], problem: firstProblem[cur]}
	}
	return out
}

// section is the heading section a line belongs to.
type section struct {
	heading  int
	unparsed bool
	problem  string
}

var sectionHeadingRE = regexp.MustCompile(`^(#{2,6})( |$)`)

// patchRE is the patch part of a release tag of one minor line ("0",
// "1", ... after "v1.N.").
var patchRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})$`)

// bindSource requires the release notes to be read at the commit of a
// recorded release tag of the later release's minor line, or at a commit
// that descends from the later release's tag commit and is reachable from
// its release branch. Any other commit (one that exists only in a fork,
// say) is not the release's own text.
func (v *verifier) bindSource(toCommit string, lineTags map[string]bool, toMinor int) (*verdictError, error) {
	c := v.bundle.Source.Commit
	if c == toCommit || lineTags[c] {
		return nil, nil
	}
	if v.in.History == nil {
		return fail(VerdictDropped, ReasonSourceUnbound, "%s is not a release tag commit and no history is available to place it", c), nil
	}
	branch := fmt.Sprintf("release-1.%d", toMinor)
	ok, err := v.in.History.OnBranch(v.repo, toCommit, c, branch)
	switch {
	case errors.Is(err, ErrHistoryUnavailable):
		return fail(VerdictDropped, ReasonSourceUnbound, "%s is not a release tag commit and no history is available to place it", c), nil
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrInputsIncomplete, err)
	case !ok:
		return fail(VerdictDropped, ReasonSourceUnbound, "%s neither is a release tag commit nor descends from %s on %s", c, v.bundle.ToRelease.Tag, branch), nil
	}
	return nil, nil
}

// claim runs steps 2-7 for one claim.
func (v *verifier) claim(c Claim, res *ClaimResult) (*verdictError, error) {
	rule, ok := allowedKinds[c.Kind]
	if !ok || (c.Component != "" && c.Component != "kubernetes") || v.repo.Key != KubernetesRepo {
		return fail(VerdictLead, ReasonKindNotAllowed, "kind \"%s\" of component \"%s\" has no section rule and complete mechanical inventory", logSafe(c.Kind), logSafe(c.Component)), nil
	}
	seen := map[string]bool{}
	for _, n := range c.Names {
		if !rule.name.MatchString(n) {
			return fail(VerdictDropped, ReasonNameInvalid, "\"%s\" is not a %s name", logSafe(n), c.Kind), nil
		}
		if seen[n] {
			return fail(VerdictDropped, ReasonNameInvalid, "\"%s\" is named twice", n), nil
		}
		seen[n] = true
	}

	// Step 4: citation by code.
	cited := map[int]bool{}
	for _, n := range c.Names {
		for i, l := range v.norm.Lines {
			if sec := v.sections[i]; sec.unparsed && containsToken(html.UnescapeString(l.Text), n) {
				return fail(VerdictLead, ReasonUnparsedSection, "%s appears in a section outside the line grammar (%s)", n, sec.problem), nil
			}
		}
		withCue, seen := v.cited[n]
		if !seen {
			// Items of unparsed sections never get here: a name in any
			// unparsed section has already made the claim a lead.
			for i, it := range v.items {
				if containsToken(it.prose, n) && cueRE.MatchString(it.prose) {
					withCue = append(withCue, i)
				}
			}
			v.cited[n] = withCue
		}
		if len(withCue) == 0 {
			return fail(VerdictDropped, ReasonNoCitedCue, "%s is not in a list item of the section with a removal cue", n), nil
		}
		first := v.items[withCue[0]]
		for _, i := range withCue[1:] {
			if v.items[i].key != first.key {
				return fail(VerdictLead, ReasonAmbiguousCitation, "%s is cited by %d different list items", n, distinct(v.items, withCue)), nil
			}
		}
		for _, i := range withCue {
			if v.items[i].hidden {
				return fail(VerdictLead, ReasonHiddenContent, "the list item citing %s held hidden content (%s)", n, strings.Join(v.items[i].flags, ", ")), nil
			}
		}
		// The name anywhere else in the read subsections (another item
		// without a cue, a heading, a paragraph) is a statement the
		// verifier cannot weigh against the cited one.
		inCited := map[int]bool{}
		for _, i := range withCue {
			for k := v.items[i].start; k <= v.items[i].end; k++ {
				inCited[k] = true
			}
		}
		for k, l := range v.norm.Lines {
			if !inCited[k] && containsToken(proseOf(l.Text), n) {
				return fail(VerdictLead, ReasonAmbiguousCitation, "%s is also named on line %d, outside the cited item", n, l.Original), nil
			}
		}
		if !containsToken(rawProseOf(first.text), n) {
			return fail(VerdictLead, ReasonHiddenContent, "the list item citing %s spells it with character references", n), nil
		}
		if b := v.barrierBefore(v.norm.Lines[v.items[withCue[len(withCue)-1]].end].Original); b != nil {
			return fail(VerdictLead, ReasonUnparsedSection, "line %d of the release section (%s) can hide the item citing %s when rendered", b.Original, b.Reason, n), nil
		}
		if m := hedgeRE.FindString(first.prose); m != "" {
			return fail(VerdictLead, ReasonHedgedCue, "the list item citing %s says %q", n, m), nil
		}
		res.Citations = append(res.Citations, Citation{
			Name: n, NormalisedLines: [2]int{first.start + 1, first.end + 1},
			OriginalLines: [2]int{v.norm.Lines[first.start].Original, v.norm.Lines[first.end].Original},
			Quote:         first.text, Occurrences: len(withCue),
		})
		cited[withCue[0]] = true
	}

	// Steps 5 and 6: existence in the earlier release, absence from the
	// later one.
	from, err := v.in.Inventory.Inventory(v.ctx, rule.present, v.repo, v.bundle.FromRelease.Commit)
	if err != nil {
		if IsIncomplete(err) {
			return fail(VerdictLead, ReasonInventoryIncomplete, "%s at %s: %v", rule.present, v.bundle.FromRelease.Tag, err), nil
		}
		return nil, fmt.Errorf("%w: %v", ErrInputsIncomplete, err)
	}
	res.Inventory = &InventoryRef{FromDigest: from.Digest}
	for _, n := range c.Names {
		if !from.Names[n] {
			return fail(VerdictDropped, ReasonNotInInventory, "%s is not in the %s of %s", n, rule.present, v.bundle.FromRelease.Tag), nil
		}
	}
	to, err := v.in.Inventory.Inventory(v.ctx, rule.to, v.repo, v.toCommit)
	if err != nil {
		if IsIncomplete(err) {
			return fail(VerdictLead, ReasonInventoryIncomplete, "%s at %s: %v", rule.to, v.bundle.ToRelease.Tag, err), nil
		}
		return nil, fmt.Errorf("%w: %v", ErrInputsIncomplete, err)
	}
	res.Inventory.ToDigest = to.Digest
	for _, n := range c.Names {
		if to.Names[n] {
			return fail(VerdictDropped, ReasonStillPresent, "%s is still in the %s of %s", n, rule.to, v.bundle.ToRelease.Tag), nil
		}
	}

	// Step 7: provenance.
	idx := make([]int, 0, len(cited))
	for i := range cited {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	prs := map[int]bool{}
	for _, i := range idx {
		refs, consistent := prReferences(v.items[i].text, v.repo)
		if !consistent {
			return fail(VerdictLead, ReasonNoProvenance, "a pull request link of the cited item names a different number than its text"), nil
		}
		if len(refs) == 0 {
			return fail(VerdictLead, ReasonNoProvenance, "the cited item references no pull request of %s", v.repo.Key), nil
		}
		for _, n := range refs {
			prs[n] = true
		}
	}
	merged, f, err := v.rangePRs()
	if err != nil {
		return nil, err
	}
	if f != nil {
		return f, nil
	}
	numbers := make([]int, 0, len(prs))
	for n := range prs {
		numbers = append(numbers, n)
	}
	sort.Ints(numbers)
	for _, n := range numbers {
		commit, ok := merged[n]
		if !ok {
			return fail(VerdictLead, ReasonNoProvenance, "pull request #%d is in no commit subject of %s..%s", n, v.bundle.FromRelease.Tag, v.bundle.ToRelease.Tag), nil
		}
		res.Provenance = append(res.Provenance, PRProvenance{PR: n, Commit: commit})
	}
	return nil, nil
}

var (
	squashSubjectRE = regexp.MustCompile(`\(#([1-9][0-9]{0,8})\)`)
	mergeSubjectRE  = regexp.MustCompile(`^Merge pull request #([1-9][0-9]{0,8}) from `)
)

// rangePRs walks the release range once and indexes the pull request
// numbers its commit subjects carry, each with the smallest commit id.
func (v *verifier) rangePRs() (map[int]string, *verdictError, error) {
	if v.historyDone {
		return v.history, v.historyErr, nil
	}
	v.historyDone = true
	if v.in.History == nil {
		v.historyErr = fail(VerdictLead, ReasonProvenanceUnavailable, "%v", ErrHistoryUnavailable)
		return nil, v.historyErr, nil
	}
	subjects, err := v.in.History.RangeSubjects(v.repo, v.bundle.FromRelease.Commit, v.toCommit, v.limit)
	switch {
	case errors.Is(err, ErrHistoryUnbounded):
		v.historyErr = fail(VerdictLead, ReasonProvenanceUnbounded, "more than %d commits in %s..%s", v.limit, v.bundle.FromRelease.Tag, v.bundle.ToRelease.Tag)
		return nil, v.historyErr, nil
	case errors.Is(err, ErrHistoryUnavailable):
		v.historyErr = fail(VerdictLead, ReasonProvenanceUnavailable, "%v", err)
		return nil, v.historyErr, nil
	case err != nil:
		return nil, nil, fmt.Errorf("%w: %v", ErrInputsIncomplete, err)
	}
	v.history = map[int]string{}
	add := func(num, commit string) {
		n, err := strconv.Atoi(num)
		if err != nil {
			return
		}
		if old, ok := v.history[n]; !ok || commit < old {
			v.history[n] = commit
		}
	}
	for _, s := range subjects {
		for _, m := range squashSubjectRE.FindAllStringSubmatch(s.Subject, -1) {
			add(m[1], s.Commit)
		}
		if m := mergeSubjectRE.FindStringSubmatch(s.Subject); m != nil {
			add(m[1], s.Commit)
		}
	}
	return v.history, nil, nil
}

// item is one list item of the normalised section.
type item struct {
	start, end int // normalised line indexes, inclusive
	text       string
	prose      string // text without link targets and URLs
	key        string // text without the list marker, for identity
	hidden     bool
	flags      []string
}

// proseOf is the text names and cues are matched in: character references
// decoded, and every link (label and target) and URL removed, so a link
// label never counts as a citation.
func proseOf(s string) string { return html.UnescapeString(rawProseOf(s)) }

// rawProseOf is proseOf without decoding character references.
func rawProseOf(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = inlineLinkRE.ReplaceAllString(s, " ")
	s = linkTargetRE.ReplaceAllString(s, "] ")
	return urlRE.ReplaceAllString(s, " ")
}

var (
	itemStartRE  = regexp.MustCompile(`^ *[-*] `)
	headingRE    = regexp.MustCompile(`^#`)
	linkTargetRE = regexp.MustCompile(`\]\([^)]*\)`)
	urlRE        = regexp.MustCompile(`https?://[^\s)\]>]+`)
)

// listItems splits the section into list items. An item is a line that
// starts with a list marker and the non-empty lines after it that are not
// themselves list items or headings. A nested item is its own item.
func listItems(n Normalised) []item {
	var out []item
	cur := -1
	flush := func(end int) {
		if cur < 0 {
			return
		}
		it := item{start: cur, end: end}
		var lines []string
		flags := map[string]bool{}
		for i := cur; i <= end; i++ {
			l := n.Lines[i]
			lines = append(lines, l.Text)
			for _, f := range l.Flags {
				it.hidden = true
				flags[f] = true
			}
		}
		for f := range flags {
			it.flags = append(it.flags, f)
		}
		sort.Strings(it.flags)
		it.text = strings.Join(lines, "\n")
		joined := strings.Join(lines, " ")
		it.prose = proseOf(joined)
		it.key = strings.Join(strings.Fields(itemStartRE.ReplaceAllString(joined, "")), " ")
		out = append(out, it)
		cur = -1
	}
	for i, l := range n.Lines {
		switch {
		case itemStartRE.MatchString(l.Text):
			flush(i - 1)
			cur = i
		case strings.TrimSpace(l.Text) == "" || headingRE.MatchString(l.Text):
			flush(i - 1)
		}
	}
	flush(len(n.Lines) - 1)
	return out
}

func distinct(items []item, idx []int) int {
	set := map[string]bool{}
	for _, i := range idx {
		set[items[i].key] = true
	}
	return len(set)
}

// containsToken reports whether name occurs in text as a whole token: the
// characters around it are not letters, digits, marks, "_", "-" or "/",
// it is not preceded by "." and not followed by "." and a letter or digit.
func containsToken(text, name string) bool {
	if name == "" {
		return false
	}
	for off := 0; off <= len(text)-len(name); {
		i := strings.Index(text[off:], name)
		if i < 0 {
			return false
		}
		at := off + i
		end := at + len(name)
		before, after := true, true
		if at > 0 {
			r, _ := utf8.DecodeLastRuneInString(text[:at])
			before = !nameRune(r) && r != '.'
		}
		if end < len(text) {
			r, size := utf8.DecodeRuneInString(text[end:])
			if r == '.' {
				if end+size < len(text) {
					r2, _ := utf8.DecodeRuneInString(text[end+size:])
					after = !nameRune(r2)
				}
			} else {
				after = !nameRune(r)
			}
		}
		if before && after {
			return true
		}
		off = at + 1
	}
	return false
}

func nameRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || r == '_' || r == '-' || r == '/'
}

var pullURLRE = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)/pull/([1-9][0-9]{0,8})$`)

// prReferences returns the pull request numbers of repo that text
// references. Only inline link targets count, and only links outside code
// spans whose target is exactly https://github.com/<repo>/pull/N: never a
// bare "#N" or URL, a link title, an issue, another repository or another
// host. consistent is false when such a link's text is not exactly "#N".
func prReferences(text string, repo extract.RepoRef) (refs []int, consistent bool) {
	owner, name := repo.OwnerName()
	set := map[int]bool{}
	consistent = true
	plain := codeSpans(text)
	for _, loc := range inlineLinkRE.FindAllStringSubmatchIndex(plain, -1) {
		// "\[" is a literal bracket, not a link.
		bs := 0
		for j := loc[0] - 1; j >= 0 && plain[j] == '\\'; j-- {
			bs++
		}
		if bs%2 == 1 {
			continue
		}
		m := []string{plain[loc[0]:loc[1]], plain[loc[2]:loc[3]], plain[loc[4]:loc[5]]}
		u := pullURLRE.FindStringSubmatch(m[2])
		if u == nil || u[1] != owner || u[2] != name {
			continue
		}
		n, _ := strconv.Atoi(u[3])
		set[n] = true
		if m[1] != "#"+u[3] {
			consistent = false
		}
	}
	for n := range set {
		refs = append(refs, n)
	}
	sort.Ints(refs)
	return refs, consistent
}

// logSafe bounds and quotes text from a claim for a detail message.
func logSafe(s string) string {
	q := strconv.QuoteToASCII(s)
	q = q[1 : len(q)-1]
	if len(q) > 80 {
		q = q[:80] + "..."
	}
	return q
}
