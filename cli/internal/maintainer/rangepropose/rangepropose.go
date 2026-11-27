// SPDX-License-Identifier: AGPL-3.0-only

// Package rangepropose lists candidate version ranges for exact-pair rules
// from local bare clones, for a person to review. It compares cited source
// spans at release tags and nothing else: it does not check behaviour, a
// later reintroduction or the effect on decisions. It writes no pack, signs
// nothing, publishes nothing and uses no network.
package rangepropose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	// CandidatesSchema and ReviewSchema identify the two output documents.
	// Neither is a rule pack schema.
	CandidatesSchema = "prufyx.io/range-proposal-candidates/v1alpha1"
	ReviewSchema     = "prufyx.io/range-proposal-review/v1alpha1"

	StatusUnreviewed  = "unreviewed-proposal"
	StatusNeedsReview = "needs-review"
	StatusRefused     = "refused"

	// BasisReviewerMustDecide is not in the engine's basis vocabulary, so a
	// range holding it is refused as written.
	BasisReviewerMustDecide = "REVIEWER_MUST_DECIDE"

	// Disclaimer states the limit of every output.
	Disclaimer = "span-stable only; behaviour, absence of reintroduction and decision impact not checked"

	coverageNote = "A candidate range also covers patch releases that do not exist yet and tags that the local clone does not hold."
	basisNote    = "The two lines are adjacent. The tool does not observe in which release the behaviour changed, so a reviewer must decide the basis of from.lt and to.gte."
)

// Refusal codes.
const (
	CodeUnsupportedShape = "UNSUPPORTED_RULE_SHAPE"
	CodeAnchorNotRelease = "ANCHOR_NOT_RELEASE"
	CodeNotLineUpgrade   = "NOT_AN_UPGRADE_BETWEEN_LINES"
	CodeNoSources        = "NO_SOURCES"
	CodeSourceInvalid    = "SOURCE_REFERENCE_INVALID"
	CodeSourceURL        = "SOURCE_URL_INVALID"
	CodeSourceDigest     = "SOURCE_DIGEST_MISMATCH"
	CodeRepoNotProvided  = "REPO_NOT_PROVIDED"
	CodeRepoMissing      = "REPO_MISSING"
	CodeRepoNotBare      = "REPO_NOT_BARE"
	CodeRepoShallow      = "REPO_SHALLOW"
	CodeRepoGrafted      = "REPO_GRAFTED"
	CodeRepoPartial      = "REPO_PARTIAL"
	CodeRepoAlternates   = "REPO_ALTERNATES"
	CodeObjectMissing    = "OBJECT_MISSING"
	CodeNoReleaseTags    = "NO_RELEASE_TAGS"
	CodeTagMissing       = "TAG_MISSING"
	CodeTagMoved         = "TAG_MOVED"
	CodeTagUnlisted      = "TAG_UNLISTED"
	CodeTagGap           = "TAG_GAP"
	CodeTagNotCommit     = "TAG_NOT_COMMIT"
	CodeTagUnrecognised  = "TAG_UNRECOGNISED"
	CodeAnchorTagMissing = "ANCHOR_TAG_MISSING"
	CodeCommitOnTwoLines = "COMMIT_ON_TWO_LINES"
	CodeOverlap          = "SAME_KEY_OVERLAP"
	CodeGit              = "GIT_ERROR"
)

// Needs-review reason codes.
const (
	ReasonUncheckedSource = "UNCHECKED_SOURCE"
	ReasonNoCountedSource = "NO_COUNTED_SOURCE"
	ReasonTargetOnly      = "TARGET_ONLY"
	ReasonFromOnly        = "FROM_ONLY"
	ReasonSpanNotStable   = "SPAN_NOT_STABLE"
	ReasonOperator        = "INELIGIBLE_OPERATOR"
	ReasonAppliesWhen     = "CONDITIONAL_RULE"
)

// Observation results. Only resultSameFile counts as stable.
const (
	resultSameFile    = "same-file"
	resultFileChanged = "file-changed"
	resultMoved       = "moved"
	resultDiffers     = "differs"
	resultAmbiguous   = "ambiguous"
	resultAbsent      = "absent"
)

const (
	sideFrom = "from"
	sideTo   = "to"
)

type refusal struct{ code, detail string }

func (r *refusal) Error() string       { return r.code + ": " + r.detail }
func refuse(code, detail string) error { return &refusal{code, detail} }

// Options are the inputs of one run.
type Options struct {
	RulesRepo    string
	RulesCommit  string
	Config       Config
	Gaps         []string
	ToolRevision string
}

// Binding ties an output to its inputs.
type Binding struct {
	RulesCommit     string `json:"rulesCommit"`
	RulesFileDigest string `json:"rulesFileDigest"`
	ToolRevision    string `json:"toolRevision"`
}

// Report is the result of one run.
type Report struct {
	Binding     Binding
	Proposals   []Proposal
	NeedsReview []Review
	Refused     []Refused
	// AlreadyRanged and NotActive count rules that are not candidates.
	AlreadyRanged, NotActive int
}

// CandidateRange is deliberately not a rule range: ReviewStatus is a field
// the strict rule decoder refuses.
type CandidateRange struct {
	ReviewStatus string                        `json:"reviewStatus"`
	From         constraintengine.VersionBound `json:"from"`
	To           constraintengine.VersionBound `json:"to"`
	Bounds       []CandidateBound              `json:"bounds"`
}

// CandidateBound names a source only when the tool sets the basis.
type CandidateBound struct {
	Bound    string `json:"bound"`
	Basis    string `json:"basis"`
	SourceID string `json:"sourceId,omitempty"`
}

// Observation is what one cited span looks like at one release tag.
type Observation struct {
	Tag        string `json:"tag"`
	Commit     string `json:"commit"`
	Result     string `json:"result"`
	FileDigest string `json:"fileDigest,omitempty"`
	FirstLine  int    `json:"firstLine,omitempty"`
	LineDrift  int    `json:"lineDrift,omitempty"`
}

// Reference is the cited span found again at the highest tag of its line. Its
// keys differ from those of a rule source on purpose.
type Reference struct {
	Tag        string `json:"tag"`
	URL        string `json:"pinnedUrl"`
	Commit     string `json:"commit"`
	FileDigest string `json:"fileDigest"`
	FirstLine  int    `json:"firstLine"`
	LastLine   int    `json:"lastLine"`
}

// CheckedSource is one counted source of a side.
type CheckedSource struct {
	CitedSourceID string        `json:"citedSourceId"`
	Side          string        `json:"side"`
	Path          string        `json:"path"`
	Observations  []Observation `json:"observations"`
	Highest       *Reference    `json:"observedAtHighestTag,omitempty"`
}

// ListedSource is a source that does not count toward any side.
type ListedSource struct {
	CitedSourceID string `json:"citedSourceId"`
	Why           string `json:"why"`
}

// TagSet records the tags read for one side.
type TagSet struct {
	Side              string `json:"side"`
	Line              string `json:"line"`
	TagCount          int    `json:"tagCount"`
	HighestTag        string `json:"highestTag"`
	TagListDigest     string `json:"tagListDigest"`
	ExpectedListGiven bool   `json:"expectedListGiven"`
}

// Evaluated is what a rule that could be read shows.
type Evaluated struct {
	TagSets []TagSet        `json:"tagSets"`
	Sources []CheckedSource `json:"checkedSources"`
	Listed  []ListedSource  `json:"listedSources"`
}

// Proposal is a candidate whose counted spans are stable on both sides.
type Proposal struct {
	RuleID          string         `json:"ruleId"`
	Project         string         `json:"project"`
	Status          string         `json:"status"`
	BaseEntryDigest string         `json:"baseEntryDigest"`
	Flags           []string       `json:"flags"`
	Candidate       CandidateRange `json:"candidateRange"`
	BasisNote       string         `json:"basisNote,omitempty"`
	Evaluated
}

// Reason explains why a rule needs review.
type Reason struct {
	Code   string `json:"code"`
	Side   string `json:"side,omitempty"`
	Detail string `json:"detail"`
}

// Review is a rule with observations and no candidate range.
type Review struct {
	RuleID          string   `json:"ruleId"`
	Project         string   `json:"project"`
	Status          string   `json:"status"`
	BaseEntryDigest string   `json:"baseEntryDigest"`
	Reasons         []Reason `json:"reasons"`
	Evaluated
}

// Refused is a rule the tool could not evaluate.
type Refused struct {
	RuleID          string `json:"ruleId"`
	Project         string `json:"project"`
	Status          string `json:"status"`
	BaseEntryDigest string `json:"baseEntryDigest"`
	Code            string `json:"code"`
	Detail          string `json:"detail"`
}

type openedRepo struct {
	repo *repository
	err  error
}

// Run reads the pack at the named commit and evaluates every active rule
// without a range. An error means the run itself failed; a rule that cannot
// be evaluated is listed as refused.
func Run(ctx context.Context, o Options) (Report, error) {
	raw, rules, err := readPack(ctx, o.RulesRepo, o.RulesCommit)
	if err != nil {
		return Report{}, err
	}
	ordered, err := order(rules, o.Gaps)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Binding:   Binding{RulesCommit: o.RulesCommit, RulesFileDigest: digest(raw), ToolRevision: o.ToolRevision},
		Proposals: []Proposal{}, NeedsReview: []Review{}, Refused: []Refused{},
	}
	repos := map[string]openedRepo{}
	var candidates []packRule
	var proposals []Proposal
	for _, r := range ordered {
		switch {
		case r.shape.Evidence.State != "active":
			report.NotActive++
			continue
		case r.shape.Range != nil:
			report.AlreadyRanged++
			continue
		}
		proposal, review, err := evaluate(ctx, o.Config, repos, r)
		if ctx.Err() != nil {
			return Report{}, ctx.Err()
		}
		var no *refusal
		switch {
		case errors.As(err, &no):
			report.Refused = append(report.Refused, refusedRule(r, no.code, no.detail))
		case err != nil:
			return Report{}, fmt.Errorf("rule %s: %w", r.id, err)
		case review != nil:
			report.NeedsReview = append(report.NeedsReview, *review)
		default:
			candidates = append(candidates, r)
			proposals = append(proposals, *proposal)
		}
	}
	// Overlap is judged against the whole set of candidates, so two
	// candidates that collide are both refused.
	for i, p := range proposals {
		if others := overlapping(candidates[i], p.Candidate, rules, candidates, proposals); len(others) != 0 {
			report.Refused = append(report.Refused, refusedRule(candidates[i], CodeOverlap,
				"the candidate range overlaps, on the same constraint key, with "+strings.Join(others, ", ")))
			continue
		}
		report.Proposals = append(report.Proposals, p)
	}
	return report, nil
}

func refusedRule(r packRule, code, detail string) Refused {
	return Refused{RuleID: r.id, Project: clean(r.project), Status: StatusRefused, BaseEntryDigest: r.entryDigest, Code: code, Detail: clean(detail)}
}

// order puts the gap list's rules first, in its order, and the rest by id.
func order(rules []packRule, gaps []string) ([]packRule, error) {
	byID := map[string]packRule{}
	for _, r := range rules {
		byID[r.id] = r
	}
	out := make([]packRule, 0, len(rules))
	for _, id := range gaps {
		r, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("gap list: no rule %q at the rules commit", id)
		}
		out = append(out, r)
		delete(byID, id)
	}
	rest := make([]string, 0, len(byID))
	for id := range byID {
		rest = append(rest, id)
	}
	sort.Strings(rest)
	for _, id := range rest {
		out = append(out, byID[id])
	}
	return out, nil
}

type side struct {
	name string
	line line
	tags []releaseTag
}

// evaluate returns exactly one of a proposal, a review or an error.
func evaluate(ctx context.Context, config Config, repos map[string]openedRepo, r packRule) (*Proposal, *Review, error) {
	subject := r.shape.Subject
	if len(r.shape.Crossing) != 0 || len(subject.Chart) != 0 {
		return nil, nil, refuse(CodeUnsupportedShape, "chart and crossing rules are not supported")
	}
	from, fromOK := parseVersion(subject.From)
	to, toOK := parseVersion(subject.To)
	if !fromOK || !toOK {
		return nil, nil, refuse(CodeAnchorNotRelease, "both anchor versions must be final X.Y.Z releases")
	}
	if from.line() == to.line() || !from.less(to) {
		return nil, nil, refuse(CodeNotLineUpgrade, "the anchor pair is not an upgrade from one release line to a later one")
	}
	sources := r.shape.Evidence.Sources
	if len(sources) == 0 {
		return nil, nil, refuse(CodeNoSources, "the rule cites no source")
	}
	ids := map[string]bool{}
	locations := make([]location, len(sources))
	for i, s := range sources {
		if !nameRE.MatchString(s.ID) || ids[s.ID] {
			return nil, nil, refuse(CodeSourceInvalid, "a source id is empty, malformed or repeated")
		}
		ids[s.ID] = true
		loc, ok := parseSourceURL(s.URL)
		if !ok || loc.commit != s.Revision {
			return nil, nil, refuse(CodeSourceURL, "source "+s.ID+" does not pin a github.com file at its revision")
		}
		locations[i] = loc
	}
	project, ok := config.Projects[r.project]
	if !ok {
		return nil, nil, refuse(CodeRepoNotProvided, "the projects file has no entry for this project")
	}
	opened, ok := repos[r.project]
	if !ok {
		opened.repo, opened.err = openRepository(ctx, project)
		repos[r.project] = opened
	}
	if opened.err != nil {
		return nil, nil, opened.err
	}
	repo := opened.repo

	sides := []side{{name: sideFrom, line: from.line()}, {name: sideTo, line: to.line()}}
	anchors := []version{from, to}
	evaluated := Evaluated{TagSets: []TagSet{}, Sources: []CheckedSource{}, Listed: []ListedSource{}}
	for i := range sides {
		tags, err := repo.lineTags(project, sides[i].line, anchors[i])
		if err != nil {
			return nil, nil, err
		}
		sides[i].tags = tags
		var list strings.Builder
		for _, t := range tags {
			list.WriteString(t.name + " " + t.commit + "\n")
		}
		evaluated.TagSets = append(evaluated.TagSets, TagSet{Side: sides[i].name, Line: sides[i].line.String(), TagCount: len(tags),
			HighestTag: tags[len(tags)-1].name, TagListDigest: digest([]byte(list.String())), ExpectedListGiven: project.Tags != nil})
	}

	reasons := ineligible(r.shape)
	counted := map[string][]string{} // side name to counted source ids
	unstable := map[string]bool{}
	for i, s := range sources {
		loc := locations[i]
		notes := isReleaseNotes(loc.path)
		list := func(why string) {
			evaluated.Listed = append(evaluated.Listed, ListedSource{CitedSourceID: s.ID, Why: why})
		}
		// A source that is not release notes and cannot be checked sends
		// the whole rule to review.
		block := func(why string) {
			list(why)
			reasons = append(reasons, Reason{Code: ReasonUncheckedSource, Detail: "source " + s.ID + " cannot be checked: " + why})
		}
		if !strings.EqualFold(loc.repo, project.Repo) {
			if notes {
				list("release-notes")
			} else {
				block("other-repository")
			}
			continue
		}
		span, problem, err := citedSpan(ctx, repo, s, loc)
		if err != nil {
			return nil, nil, err
		}
		if notes {
			list("release-notes")
			continue
		}
		if problem != "" {
			block(problem)
			continue
		}
		var own *side
		for j := range sides {
			for _, t := range sides[j].tags {
				if t.commit == s.Revision {
					own = &sides[j]
				}
			}
		}
		if own == nil {
			why := "untagged-revision"
			for _, t := range repo.tags {
				if t.commit == s.Revision {
					why = "revision-outside-both-lines"
				}
			}
			block(why)
			continue
		}
		checked := CheckedSource{CitedSourceID: s.ID, Side: own.name, Path: loc.path}
		stable := true
		for _, t := range own.tags {
			seen, err := observe(ctx, repo, t, s, loc.path, span)
			if err != nil {
				return nil, nil, err
			}
			checked.Observations = append(checked.Observations, seen)
			if seen.Result != resultSameFile && stable {
				stable = false
				if !unstable[own.name] {
					unstable[own.name] = true
					reasons = append(reasons, Reason{Code: ReasonSpanNotStable, Side: own.name,
						Detail: "source " + s.ID + " first differs at tag " + t.name + ": " + seen.Result})
				}
			}
		}
		if stable {
			highest := own.tags[len(own.tags)-1]
			if highest.commit != s.Revision {
				checked.Highest = &Reference{Tag: highest.name, URL: "https://github.com/" + loc.repo + "/blob/" + highest.commit + "/" + loc.path,
					Commit: highest.commit, FileDigest: s.ContentDigest, FirstLine: s.StartLine, LastLine: s.EndLine}
			}
		}
		counted[own.name] = append(counted[own.name], s.ID)
		evaluated.Sources = append(evaluated.Sources, checked)
	}

	// A side without a counted source is never passed: a check over no
	// source proves nothing.
	switch hasFrom, hasTo := len(counted[sideFrom]) > 0, len(counted[sideTo]) > 0; {
	case !hasFrom && !hasTo:
		reasons = append(reasons, Reason{Code: ReasonNoCountedSource, Detail: "no counted source on either side; the tool does not look for new sources"})
	case !hasFrom:
		reasons = append(reasons, Reason{Code: ReasonTargetOnly, Side: sideFrom, Detail: "needs reviewer: target-only; the from side has no counted source"})
	case !hasTo:
		reasons = append(reasons, Reason{Code: ReasonFromOnly, Side: sideTo, Detail: "the to side has no counted source"})
	}
	if len(reasons) != 0 {
		return nil, &Review{RuleID: r.id, Project: clean(r.project), Status: StatusNeedsReview, BaseEntryDigest: r.entryDigest,
			Reasons: reasons, Evaluated: evaluated}, nil
	}

	p := &Proposal{RuleID: r.id, Project: clean(r.project), Status: StatusUnreviewed, BaseEntryDigest: r.entryDigest,
		Flags: []string{"span-stable-only"}, Evaluated: evaluated}
	fromLine, toLine := from.line(), to.line()
	fromID, toID := counted[sideFrom][0], counted[sideTo][0]
	p.Candidate = CandidateRange{
		ReviewStatus: StatusUnreviewed,
		From:         constraintengine.VersionBound{Gte: fromLine.start(), Lt: fromLine.next()},
		To:           constraintengine.VersionBound{Gte: toLine.start(), Lt: toLine.next()},
	}
	// Adjacent means the next minor of the same major. A new major is never
	// adjacent.
	if fromLine.major == toLine.major && fromLine.minor+1 == toLine.minor {
		p.Flags = append(p.Flags, "adjacent-lines", "release-boundary-not-set")
		p.BasisNote = basisNote
		p.Candidate.Bounds = []CandidateBound{
			{Bound: "from.gte", Basis: constraintengine.BasisPreviousMinorLine, SourceID: fromID},
			{Bound: "from.lt", Basis: BasisReviewerMustDecide},
			{Bound: "to.gte", Basis: BasisReviewerMustDecide},
			{Bound: "to.lt", Basis: constraintengine.BasisTargetSeries, SourceID: toID},
		}
	} else {
		p.Flags = append(p.Flags, "non-adjacent-lines")
		p.Candidate.Bounds = []CandidateBound{
			{Bound: "from.gte", Basis: constraintengine.BasisUpgradeFromSeries, SourceID: fromID},
			{Bound: "from.lt", Basis: constraintengine.BasisUpgradeFromSeries, SourceID: fromID},
			{Bound: "to.gte", Basis: constraintengine.BasisTargetSeries, SourceID: toID},
			{Bound: "to.lt", Basis: constraintengine.BasisTargetSeries, SourceID: toID},
		}
	}
	return p, nil, nil
}

// ineligible is the closed eligibility check. Only the two operators below can
// be proposed, and only without applicability conditions: the tool evaluates
// neither another operator nor appliesWhen, so such a rule goes to review.
func ineligible(shape ruleShape) []Reason {
	var reasons []Reason
	switch shape.Operator {
	case "forbid_predicate_value", constraintengine.OperatorForbidSetMember:
	default:
		reasons = append(reasons, Reason{Code: ReasonOperator,
			Detail: clean(fmt.Sprintf("the tool proposes no range for operator %q", shape.Operator))})
	}
	if raw := shape.AppliesWhen; len(raw) != 0 {
		// Only an absent member or an empty array is unconditional; null or
		// any other value is not.
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err != nil || list == nil || len(list) != 0 {
			var compact bytes.Buffer
			text := "unreadable"
			if json.Compact(&compact, raw) == nil {
				text = compact.String()
			}
			reasons = append(reasons, Reason{Code: ReasonAppliesWhen,
				Detail: clean("the tool does not evaluate appliesWhen: " + text)})
		}
	}
	return reasons
}

// citedSpan verifies a source reference against the clone and returns the
// cited whole lines. problem names why the cited file cannot be compared.
func citedSpan(ctx context.Context, repo *repository, s source, loc location) ([][]byte, string, error) {
	if err := repo.requireCommit(ctx, s.Revision); err != nil {
		return nil, "", err
	}
	file, err := repo.file(ctx, s.Revision, loc.path)
	if err != nil {
		return nil, "", err
	}
	if file == nil {
		return nil, "", refuse(CodeSourceInvalid, "source "+s.ID+" names a path its revision does not hold")
	}
	if file.problem != "" {
		return nil, file.problem, nil
	}
	if digest(file.data) != s.ContentDigest {
		return nil, "", refuse(CodeSourceDigest, "source "+s.ID+" does not match its content digest at its revision")
	}
	lines := splitLines(file.data)
	if s.StartLine < 1 || s.EndLine < s.StartLine || s.EndLine > len(lines) {
		return nil, "", refuse(CodeSourceInvalid, "source "+s.ID+" cites lines outside its file")
	}
	return lines[s.StartLine-1 : s.EndLine], "", nil
}

func observe(ctx context.Context, repo *repository, t releaseTag, s source, path string, span [][]byte) (Observation, error) {
	seen := Observation{Tag: t.name, Commit: t.commit}
	file, err := repo.file(ctx, t.commit, path)
	switch {
	case err != nil:
		return seen, err
	case file == nil:
		seen.Result = resultAbsent
		return seen, nil
	case file.problem != "":
		seen.Result = file.problem
		return seen, nil
	}
	seen.FileDigest = digest(file.data)
	found := occurrences(file.data, span)
	switch {
	case len(found) == 0:
		seen.Result = resultDiffers
		return seen, nil
	case len(found) > 1:
		seen.Result = resultAmbiguous
		return seen, nil
	}
	seen.FirstLine, seen.LineDrift = found[0], found[0]-s.StartLine
	switch {
	case seen.FileDigest == s.ContentDigest:
		seen.Result = resultSameFile
	case seen.LineDrift != 0:
		seen.Result = resultMoved
	default:
		seen.Result = resultFileChanged
	}
	return seen, nil
}
