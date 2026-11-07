// SPDX-License-Identifier: AGPL-3.0-only

package artifacthubchanges

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

// ResultSchema identifies the canonical JSON of a Result.
const ResultSchema = "prufyx.io/artifacthub-changes-scan/v1"

// EvidenceBasis is the basis of every candidate. It is a lead for a reviewer and never a derived basis.
const EvidenceBasis = "draft"

// ChangesAnnotation is the Chart.yaml annotation the reader looks at.
const ChangesAnnotation = "artifacthub.io/changes"

// Fixed limits.
const (
	MaxCharts             = 256
	MaxChartBytes         = 64 << 10
	MaxAnnotationBytes    = 32 << 10
	MaxChanges            = 256
	MaxLinksPerChange     = 16
	MaxDescriptionBytes   = 1024
	MaxCandidatesPerChart = 32
	MaxCandidates         = 4096
)

// Candidate types.
const (
	TypeFlag      = "flag"
	TypeValuesKey = "values_key"
)

// ComponentUnknown marks a flag candidate whose binary or component the
// changelog does not state.
const ComponentUnknown = "unknown"

// Actions. They equal the change kinds that produce candidates.
const (
	ActionRemoved    = "removed"
	ActionDeprecated = "deprecated"
)

// Candidate is one DRAFT lead. Member is the set member through the shared
// encoder: the flag name, or the encoded values key path.
type Candidate struct {
	Type   string `json:"type"`
	Action string `json:"action"`
	Member string `json:"member"`
	// Component is "unknown" for a flag: a changelog does not name the
	// binary that owns it, so a reviewer must attribute it before any use.
	Component     string `json:"component,omitempty"`
	Chart         string `json:"chart"`
	ChartVersion  string `json:"chartVersion"`
	File          string `json:"file"`
	ChangeKind    string `json:"changeKind"`
	Quote         string `json:"quote"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
	SpanExact     bool   `json:"spanExact"`
	SourceURL     string `json:"sourceUrl"`
	EvidenceBasis string `json:"evidenceBasis"`
	NeedsReview   bool   `json:"needsReview"`
}

// Result is the outcome of one scan. Candidates and Ledger are canonical
// (sorted, no duplicates).
type Result struct {
	Schema     string        `json:"schema"`
	Commit     string        `json:"commit"`
	FilesRead  int           `json:"filesRead"`
	Candidates []Candidate   `json:"candidates"`
	Ledger     []LedgerEntry `json:"ledger"`
}

// Target names the repository and the Chart.yaml paths to read. The paths are
// chosen by the caller; the reader never lists or searches the tree.
type Target struct {
	Repo   extract.RepoRef
	Charts []string
}

// changeKinds is the reviewed list of Artifact Hub change kinds; any other
// is withheld.
var changeKinds = map[string]bool{
	"added": true, "changed": true, "deprecated": true, "removed": true, "fixed": true, "security": true,
}

var (
	chartPathRE = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,63}/){0,8}Chart\.yaml$`)
	chartNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	versionRE   = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)
	tokenRE     = regexp.MustCompile("`([^`\\n]{1,200})`")
	flagRE      = regexp.MustCompile(`^--([a-z0-9][a-z0-9-]*)(=\S*)?$`)
	// valuesKeyRE: a dotted path of at least two segments. A bare word is
	// not accepted: it cannot be told from prose.
	valuesKeyRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`)
	// hostLikeRE: a trailing top level domain or file extension makes the
	// token a host name or file name rather than a values key.
	hostLikeRE = regexp.MustCompile(`(?i)\.(com|io|org|net|dev|yaml|yml|json|md|txt|tpl|go|sh)$`)

	removedRE   = regexp.MustCompile(`\b(removed|removes|removal|remove)\b`)
	futureRE    = regexp.MustCompile(`\b(will be|to be|is going to be|are going to be|scheduled to be|will soon be)\s+removed\b`)
	deprecateRE = regexp.MustCompile(`\b(deprecated|deprecates|deprecate|deprecation)\b`)
	negationRE  = regexp.MustCompile(`\b(not|never|no longer|isn't|aren't|won't|don't|doesn't|didn't|cannot|can't|without)\b[^.\n]{0,24}\b(removed|remove|deprecated|deprecate)\b`)
	replaceRE   = regexp.MustCompile(`\b(instead|replaced|replaces|replace|replacement|migrate|migrated|migration|use|using|renamed|rename|now|requirement|requires|required|default|defaults|defaulted|changed|changes|superseded|supersedes|favou?r|alternative|moved|move|merged|split|in place of)\b`)
	// modalRE: modal, planned or versioned prose is a forecast or a
	// possibility, not a statement that something was removed.
	modalRE = regexp.MustCompile(`\b(may|can|could|should|would|might|shall|must)\s+(also\s+|soon\s+)?(be\s+)?(removed|deprecated)\b|\b(planned|scheduled|slated|intended)\s+(for\s+)?(removal|deprecation|to be removed)\b|\bremoval\s+(in|from|by)\b|\bremoved\s+(in|from|by)\s+(the\s+)?(next|upcoming|following|v?\d)|\b(if|unless|when|once)\b[^.\n]{0,60}\b(removed|deprecated)\b`)
	verbRE  = `(?:removed|removes|remove|deprecated|deprecates|deprecate)\*{0,2}`
	listRE  = "(?:`[^`\\n]+`\\s*(?:,|and|or)?\\s*)*"
)

// Scan reads the changes annotation of the listed charts at commit sha. The
// reader must be pinned: sha is a full 40-character commit. At least one
// chart path is required.
func Scan(ctx context.Context, r extract.PinnedReader, t Target, sha string) (res *Result, err error) {
	if !extract.IsCommitSHA(sha) {
		return nil, errors.New("artifacthubchanges: sha must be a full 40-character commit SHA")
	}
	if len(t.Charts) == 0 {
		return nil, errors.New("artifacthubchanges: no chart paths given")
	}
	res = &Result{Schema: ResultSchema, Commit: sha, Candidates: []Candidate{}, Ledger: []LedgerEntry{}}
	l := ledgerSet{}
	defer func() {
		if p := recover(); p != nil {
			l.add(ReasonPanic, "charts")
			res.Candidates = []Candidate{}
			res.Ledger = l.canonical()
			err = nil
		}
	}()
	s := &scanner{ctx: ctx, r: r, repo: t.Repo, sha: sha, l: l}
	if err := s.run(res, t.Charts); err != nil {
		return nil, err
	}
	sort.Slice(res.Candidates, func(i, j int) bool { return lessCandidate(res.Candidates[i], res.Candidates[j]) })
	res.Candidates = dedupe(res.Candidates)
	if len(res.Candidates) > MaxCandidates {
		l.add(ReasonTooManyCandidates, "charts")
		res.Candidates = []Candidate{}
	}
	res.Ledger = l.canonical()
	return res, nil
}

func lessCandidate(a, b Candidate) bool {
	switch {
	case a.File != b.File:
		return a.File < b.File
	case a.StartLine != b.StartLine:
		return a.StartLine < b.StartLine
	case a.Type != b.Type:
		return a.Type < b.Type
	case a.Member != b.Member:
		return a.Member < b.Member
	case a.ChangeKind != b.ChangeKind:
		return a.ChangeKind < b.ChangeKind
	}
	return a.Action < b.Action
}

func dedupe(c []Candidate) []Candidate {
	w := 0
	for i := range c {
		if i > 0 && c[i] == c[w-1] {
			continue
		}
		c[w] = c[i]
		w++
	}
	return c[:w]
}

type scanner struct {
	ctx  context.Context
	r    extract.PinnedReader
	repo extract.RepoRef
	sha  string
	l    ledgerSet
}

func (s *scanner) run(res *Result, charts []string) error {
	if len(charts) > MaxCharts {
		s.l.add(ReasonTooManyCharts, "charts")
		return nil
	}
	paths := append([]string(nil), charts...)
	sort.Strings(paths)
	for i, p := range paths {
		if i > 0 && p == paths[i-1] {
			continue
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if !chartPathRE.MatchString(p) || path.Clean(p) != p {
			s.l.add(ReasonUnsafePath, ledgerSafeItem(p))
			continue
		}
		data, err := s.r.Read(s.repo, s.sha, p)
		if errors.Is(err, extract.ErrNotFound) {
			s.l.add(ReasonMissing, p)
			continue
		}
		if err != nil {
			return fmt.Errorf("artifacthubchanges: read %s: %w", p, err)
		}
		res.FilesRead++
		if len(data) > MaxChartBytes {
			s.l.add(ReasonTooLarge, p)
			continue
		}
		res.Candidates = append(res.Candidates, s.chart(p, data)...)
	}
	return nil
}

// ledgerSafeItem keeps a hostile path out of the ledger spelling rules: the
// ledger names such a path by a fixed placeholder.
func ledgerSafeItem(p string) string {
	if ledgerItemRE.MatchString(p) {
		return p
	}
	return "INVALID"
}

func (s *scanner) chart(file string, data []byte) []Candidate {
	var c chart
	if err := decodeStrict(data, &c); err != nil {
		s.l.add(ReasonParse, file)
		return nil
	}
	if c.APIVersion != "v2" {
		s.l.add(ReasonSchema, file)
		return nil
	}
	if !chartNameRE.MatchString(c.Name) || !versionRE.MatchString(c.Version) {
		s.l.add(ReasonParse, file)
		return nil
	}
	ann, ok := c.Annotations[ChangesAnnotation]
	if !ok {
		return nil
	}
	if len(ann.Value) > MaxAnnotationBytes {
		s.l.add(ReasonAnnotationTooLarge, file)
		return nil
	}
	var changes []change
	if err := decodeStrict([]byte(ann.Value), &changes); err != nil {
		s.l.add(ReasonParse, file)
		return nil
	}
	if len(changes) > MaxChanges {
		s.l.add(ReasonTooManyChanges, file)
		return nil
	}
	var out []Candidate
	for _, ch := range changes {
		if len(ch.Links) > MaxLinksPerChange {
			s.l.add(ReasonParse, file)
			continue
		}
		kind := ch.Kind.Value
		if !changeKinds[kind] {
			s.l.add(ReasonKindUnknown, file)
			continue
		}
		if kind != ActionRemoved && kind != ActionDeprecated {
			continue
		}
		if cand, ok := s.entry(file, &c, ann, ch, kind); ok {
			out = append(out, cand)
		}
	}
	if len(out) > MaxCandidatesPerChart {
		s.l.add(ReasonTooManyCandidates, file)
		return nil
	}
	return out
}

// lines maps the description to a span of the Chart.yaml. The span is exact
// only when the annotation is a literal block (its lines are the file's
// lines) and the description is a literal block of it.
func lines(ann, desc text) (start, end int, exact bool) {
	base := ann.Line
	if ann.Block {
		base++
	}
	if !ann.Literal {
		return base, base + strings.Count(strings.TrimRight(ann.Value, "\n"), "\n"), false
	}
	ds := desc.Line
	if desc.Block {
		ds++
	}
	n := strings.Count(strings.TrimRight(desc.Value, "\n"), "\n")
	start = base + ds - 1
	return start, start + n, desc.Literal
}

// entry classifies one deprecated or removed entry. It returns (candidate,
// true) or withholds the entry with a ledger entry and returns false.
func (s *scanner) entry(file string, c *chart, ann text, ch change, kind string) (Candidate, bool) {
	quote := strings.TrimSpace(ch.Description.Value)
	if len(quote) > MaxDescriptionBytes {
		s.l.add(ReasonTextTooLarge, file)
		return Candidate{}, false
	}
	lower := strings.ToLower(quote)
	removed := removedRE.MatchString(lower)
	deprecated := deprecateRE.MatchString(lower)
	if futureRE.MatchString(lower) {
		// "will be removed" announces a removal: a deprecation. Strip the
		// phrase before judging whether a plain removal is also stated.
		deprecated = true
		removed = removedRE.MatchString(futureRE.ReplaceAllString(lower, ""))
	}
	if !removed && !deprecated {
		s.l.add(ReasonNoSignal, file)
		return Candidate{}, false
	}
	if modalRE.MatchString(lower) || negationRE.MatchString(lower) || replaceRE.MatchString(lower) || (removed && deprecated) {
		s.l.add(ReasonAmbiguous, file)
		return Candidate{}, false
	}
	action := ActionDeprecated
	if removed {
		action = ActionRemoved
	}
	if action != kind {
		s.l.add(ReasonAmbiguous, file)
		return Candidate{}, false
	}
	if strings.Contains(quote, "```") || strings.Count(quote, "`")%2 != 0 {
		s.l.add(ReasonUnclassified, file)
		return Candidate{}, false
	}
	matches := tokenRE.FindAllStringSubmatch(quote, -1)
	if len(matches) == 0 {
		s.l.add(ReasonNoToken, file)
		return Candidate{}, false
	}
	var tok token
	seen := map[string]bool{}
	for _, m := range matches {
		raw := strings.TrimSpace(m[1])
		tk, ok := classify(raw)
		if !ok {
			s.l.add(ReasonUnclassified, file)
			return Candidate{}, false
		}
		if tk.typ == "" {
			s.l.add(ReasonMember, file)
			return Candidate{}, false
		}
		tk.raw = raw
		tok = tk
		seen[raw] = true
	}
	if len(seen) != 1 {
		s.l.add(ReasonMultipleTokens, file)
		return Candidate{}, false
	}
	if !adjacent(quote, tok.raw) {
		s.l.add(ReasonAmbiguous, file)
		return Candidate{}, false
	}
	comp := ""
	if tok.typ == TypeFlag {
		comp = ComponentUnknown
	}
	st, en, exact := lines(ann, ch.Description)
	return Candidate{
		Type: tok.typ, Action: action, Member: tok.member, Component: comp,
		Chart: c.Name, ChartVersion: c.Version, File: file, ChangeKind: kind, Quote: quote,
		StartLine: st, EndLine: en, SpanExact: exact,
		SourceURL:     s.repo.BlobURL(s.sha, file),
		EvidenceBasis: EvidenceBasis, NeedsReview: true,
	}, true
}

// adjacent reports whether the action verb stands right next to the token:
// before it ("Remove the flag `x`") or after it ("`x` flag is removed",
// "`x` will be removed").
func adjacent(quote, raw string) bool {
	q := regexp.QuoteMeta("`" + raw + "`")
	art := `(?:\s+(?:the|a|an|flags?|fields?|keys?|values?|options?|parameters?|settings?))*\s+`
	pre := regexp.MustCompile(`(?i)` + verbRE + art + listRE + q)
	post := regexp.MustCompile(`(?i)` + q + `(?:\s+(?:flag|field|key|value|option|parameter|setting))?\s+(?:(?:is|are|was|were|has been|have been|will be|to be)\s+)` + verbRE)
	return pre.MatchString(quote) || post.MatchString(quote)
}

type token struct {
	typ, member, raw string
}

// classify turns one backticked token into a typed token. ok is false when
// the token is not one of the supported shapes; ok with an empty typ means
// the shape was supported but the shared encoder refused the member.
func classify(t string) (token, bool) {
	if m := flagRE.FindStringSubmatch(t); m != nil {
		mem, err := membercode.Flag(m[1])
		if err != nil {
			return token{}, true
		}
		return token{typ: TypeFlag, member: mem}, true
	}
	if valuesKeyRE.MatchString(t) && !hostLikeRE.MatchString(t) {
		var segs []membercode.Seg
		for _, p := range strings.Split(t, ".") {
			segs = append(segs, membercode.Seg{Kind: membercode.Prop, Name: p})
		}
		mem, err := membercode.ConfigKey(segs)
		if err != nil {
			return token{}, true
		}
		return token{typ: TypeValuesKey, member: mem}, true
	}
	return token{}, false
}
