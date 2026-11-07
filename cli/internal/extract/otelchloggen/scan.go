// SPDX-License-Identifier: AGPL-3.0-only

package otelchloggen

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
const ResultSchema = "prufyx.io/otel-chloggen-scan/v1"

// EvidenceBasis is the basis of every candidate. It is a lead for a reviewer and never a derived basis.
const EvidenceBasis = "draft"

// ChloggenDir is where the project keeps its changelog fragments.
const ChloggenDir = ".chloggen"

// Fixed limits.
const (
	MaxFiles                 = 5000
	MaxFragmentBytes         = 64 << 10
	MaxQuoteBytes            = 4096
	MaxIssues                = 32
	MaxChangeLogs            = 4
	MaxCandidatesPerFragment = 32
	MaxCandidates            = 4096
)

// Candidate types.
const (
	TypeFlag      = "flag"
	TypeConfigKey = "config_key"
)

// ComponentUnknown marks a flag candidate: a fragment does not name the
// binary that owns a flag.
const ComponentUnknown = "unknown"

// Actions. A breaking fragment that does not say plainly "removed" is
// ActionRemovedOrChanged: the fragment says the change breaks users, not how.
const (
	ActionRemoved          = "removed"
	ActionDeprecated       = "deprecated"
	ActionRemovedOrChanged = "removed_or_changed"
)

// Change types.
const (
	ChangeBreaking    = "breaking"
	ChangeDeprecation = "deprecation"
)

// SectionNote names the fragment field a candidate came from. The subtext is
// read with the note and quoted with it.
const SectionNote = "note"

// Candidate is one DRAFT lead. Member is the set member through the shared
// encoder (flag name, or config key path).
type Candidate struct {
	Type   string `json:"type"`
	Action string `json:"action"`
	Member string `json:"member"`
	// Component is the canonical component for a config key, from the
	// hand-written table, and "unknown" for a flag.
	Component     string `json:"component"`
	File          string `json:"file"`
	ChangeType    string `json:"changeType"`
	Section       string `json:"section"`
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

// Target names the repository to read.
type Target struct {
	Repo extract.RepoRef
}

// knownComponents is the hand-written table from the component field of a
// fragment to the canonical component name. A fragment of another component
// is withheld. The table is not derived from any upstream tree; when this
// reader is wired into anything, it must be cross-checked against the
// component list of the pinned tree first.
var knownComponents = map[string]string{
	"batchprocessor":         "processor/batch",
	"confmap":                "confmap",
	"debugexporter":          "exporter/debug",
	"exporter/loadbalancing": "exporter/loadbalancing",
	"memorylimiterprocessor": "processor/memory_limiter",
	"otlpexporter":           "exporter/otlp",
	"otlphttpexporter":       "exporter/otlphttp",
	"otlpreceiver":           "receiver/otlp",
	"processor/filter":       "processor/filter",
	"processor/transform":    "processor/transform",
	"receiver/filelog":       "receiver/filelog",
	"receiver/hostmetrics":   "receiver/hostmetrics",
	"receiver/prometheus":    "receiver/prometheus",
	"service":                "service",
}

// changeTypes is the reviewed list of fragment change types; any other is
// withheld. Only breaking and deprecation can produce candidates.
var changeTypes = map[string]bool{
	"breaking": true, "deprecation": true, "new_component": true, "enhancement": true, "bug_fix": true,
}

// changeLogNames is the closed set of change_logs values.
var changeLogNames = map[logName]bool{"user": true, "api": true}

// fileSuffixes are never a config key: a token that ends in one names a file.
var fileSuffixes = []string{".yaml", ".yml", ".json", ".go", ".md"}

// ignoredNames are the two non-fragment files the tool keeps in the same
// directory. They are skipped by name and nothing else is.
var ignoredNames = map[string]bool{"TEMPLATE.yaml": true, "config.yaml": true}

var (
	fileNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.yaml$`)
	componentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/_.-]{0,99}$`)
	tokenRE     = regexp.MustCompile("`([^`\\n]{1,200})`")
	flagRE      = regexp.MustCompile(`^--([a-z0-9][a-z0-9-]*)(=\S*)?$`)
	keyRE       = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$`)

	removedRE   = regexp.MustCompile(`\b(removed|removes|removal|remove)\b`)
	futureRE    = regexp.MustCompile(`\b(will be|to be|is going to be|are going to be|scheduled to be|will soon be)\s+removed\b`)
	deprecateRE = regexp.MustCompile(`\b(deprecated|deprecates|deprecate|deprecation)\b`)
	negationRE  = regexp.MustCompile(`\b(not|never|no longer|isn't|aren't|won't|without)\b[^.\n]{0,24}\b(removed|remove|deprecated|deprecate)\b`)
	replaceRE   = regexp.MustCompile(`\b(instead|replaced|replaces|replace|replacement|migrate|migration|use|uses|using|renamed|rename|renames|now|requirement|requires|required|require|default|defaults|defaulted|value|values|change|changed|changes|superseded|supersedes|equivalent|prefer|preferred|favor|favour|gate|gates|featuregate|featuregates|only|unless)\b`)
	// modalRE: modal, planned, conditional or versioned prose is a forecast
	// or a possibility, not a statement that something was removed.
	modalRE = regexp.MustCompile(`\b(may|can|could|should|would|might|shall|must)\s+(also\s+|soon\s+)?(be\s+)?(removed|deprecated)\b` +
		`|\b(will|to|going to|scheduled to|about to)\s+(soon\s+)?(be\s+)?deprecated\b` +
		`|\b(planned|scheduled|slated|intended)\s+(for\s+)?(removal|deprecation|to be removed|to be deprecated)\b` +
		`|\b(removal|deprecation)\s+(in|from|by|since|after|before)\b` +
		`|\b(removed|deprecated)\s+(in|from|by|since|after|before|starting|as of)\s+(the\s+)?(next|upcoming|following|version|release|v?\d)` +
		`|\b(if|unless|when|once)\b[^.\n]{0,60}\b(removed|deprecated)\b`)
	verbRE = `(?:removed|removes|remove|deprecated|deprecates|deprecate)\*{0,2}`
	listRE = "(?:`[^`\\n]+`\\s*(?:,|and|or)?\\s*)*"
)

// reservedKeys are words that are never a config key.
var reservedKeys = map[string]bool{"true": true, "false": true, "null": true, "nil": true, "yaml": true}

// Scan reads the fragments of the repository at commit sha. The reader must
// be pinned: sha is a full 40-character commit.
func Scan(ctx context.Context, r extract.PinnedReader, t Target, sha string) (res *Result, err error) {
	if !extract.IsCommitSHA(sha) {
		return nil, errors.New("otelchloggen: sha must be a full 40-character commit SHA")
	}
	res = &Result{Schema: ResultSchema, Commit: sha, Candidates: []Candidate{}, Ledger: []LedgerEntry{}}
	l := ledgerSet{}
	defer func() {
		if p := recover(); p != nil {
			l.add(ReasonPanic, ChloggenDir)
			res.Candidates = []Candidate{}
			res.Ledger = l.canonical()
			err = nil
		}
	}()
	s := &scanner{ctx: ctx, r: r, repo: t.Repo, sha: sha, l: l}
	if err := s.run(res); err != nil {
		return nil, err
	}
	sort.Slice(res.Candidates, func(i, j int) bool { return lessCandidate(res.Candidates[i], res.Candidates[j]) })
	res.Candidates = dedupe(res.Candidates)
	if len(res.Candidates) > MaxCandidates {
		l.add(ReasonTooManyCandidates, ChloggenDir)
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
	case a.Component != b.Component:
		return a.Component < b.Component
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

func (s *scanner) run(res *Result) error {
	entries, err := s.r.List(s.repo, s.sha, ChloggenDir)
	if errors.Is(err, extract.ErrNotFound) {
		s.l.add(ReasonDirMissing, ChloggenDir)
		return nil
	}
	if err != nil {
		return fmt.Errorf("otelchloggen: list %s: %w", ChloggenDir, err)
	}
	if len(entries) > MaxFiles {
		s.l.add(ReasonTooManyFiles, ChloggenDir)
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, e := range entries {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if path.Dir(e.Path) != ChloggenDir || !fileNameRE.MatchString(path.Base(e.Path)) {
			s.l.add(ReasonUnsafeName, ledgerSafeItem(e.Path))
			continue
		}
		if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") {
			s.l.add(ReasonEntryNotFile, e.Path)
			continue
		}
		if ignoredNames[path.Base(e.Path)] {
			continue
		}
		data, err := s.r.Read(s.repo, s.sha, e.Path)
		if errors.Is(err, extract.ErrNotFound) {
			s.l.add(ReasonUnreadable, e.Path)
			continue
		}
		if err != nil {
			return fmt.Errorf("otelchloggen: read %s: %w", e.Path, err)
		}
		res.FilesRead++
		if len(data) > MaxFragmentBytes {
			s.l.add(ReasonTooLarge, e.Path)
			continue
		}
		res.Candidates = append(res.Candidates, s.fragment(e.Path, data)...)
	}
	return nil
}

// ledgerSafeItem keeps a hostile entry name out of the ledger spelling
// rules: the ledger names such an entry by a fixed placeholder.
func ledgerSafeItem(p string) string {
	if ledgerItemRE.MatchString(p) {
		return p
	}
	return ChloggenDir + "/INVALID"
}

func (s *scanner) fragment(file string, data []byte) []Candidate {
	f, err := decodeFragment(data)
	if err != nil || !componentRE.MatchString(f.Component) || strings.TrimSpace(f.Note.Value) == "" ||
		len(f.Issues) == 0 || len(f.Issues) > MaxIssues || len(f.ChangeLogs) > MaxChangeLogs {
		s.l.add(ReasonParse, file)
		return nil
	}
	for _, c := range f.ChangeLogs {
		if !changeLogNames[c] {
			s.l.add(ReasonParse, file)
			return nil
		}
	}
	if !changeTypes[f.ChangeType] {
		s.l.add(ReasonChangeTypeUnknown, file)
		return nil
	}
	if f.ChangeType != ChangeBreaking && f.ChangeType != ChangeDeprecation {
		// Additions, enhancements and fixes carry no removal or deprecation
		// intent: nothing to propose and nothing withheld.
		return nil
	}
	comp, ok := knownComponents[f.Component]
	if !ok {
		s.l.add(ReasonComponentUnknown, file)
		return nil
	}
	cs, ok := s.unit(file, f, comp)
	if !ok {
		return nil
	}
	if len(cs) > MaxCandidatesPerFragment {
		s.l.add(ReasonTooManyCandidates, file)
		return nil
	}
	return cs
}

// span returns the line span of a text and whether it is exact.
func span(t text) (start, end int, exact bool) {
	start = t.Line
	if t.Block {
		start++
	}
	lines := strings.Count(strings.TrimRight(t.Value, "\n"), "\n")
	return start, start + lines, t.Literal
}

type token struct {
	typ, member, raw string
}

// unit classifies the note and its subtext as one text. It returns
// (candidates, true) or withholds the text with a ledger entry and returns
// (nil, false). Every check below runs on the whole text, whatever the number
// of tokens.
func (s *scanner) unit(file string, f *fragment, comp string) ([]Candidate, bool) {
	st, en, exact := span(f.Note)
	quote := strings.TrimSpace(f.Note.Value)
	if sub := strings.TrimSpace(f.Subtext.Value); sub != "" {
		ss, se, _ := span(f.Subtext)
		quote += "\n" + sub
		if ss < st {
			st = ss
		}
		if se > en {
			en = se
		}
		exact = false
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
	if modalRE.MatchString(lower) || negationRE.MatchString(lower) || (removed && deprecated) {
		s.l.add(ReasonAmbiguous, file)
		return nil, false
	}
	// action is what the text states; the change type must agree with it.
	// A deprecation fragment must say deprecated, and a breaking fragment
	// that says deprecated is not a removal or a change.
	action := ""
	switch f.ChangeType {
	case ChangeDeprecation:
		if removed || !deprecated {
			s.l.add(ReasonAmbiguous, file)
			return nil, false
		}
		action = ActionDeprecated
	default:
		switch {
		case deprecated:
			s.l.add(ReasonAmbiguous, file)
			return nil, false
		case removed:
			action = ActionRemoved
		default:
			action = ActionRemovedOrChanged
		}
	}
	if len(quote) > MaxQuoteBytes {
		s.l.add(ReasonTextTooLarge, file)
		return nil, false
	}
	if strings.Contains(quote, "```") || strings.Count(quote, "`")%2 != 0 {
		s.l.add(ReasonUnclassified, file)
		return nil, false
	}
	matches := tokenRE.FindAllStringSubmatch(quote, -1)
	if len(matches) == 0 {
		s.l.add(ReasonNoToken, file)
		return nil, false
	}
	seen := map[token]bool{}
	var toks []token
	for _, m := range matches {
		tk, ok := classify(strings.TrimSpace(m[1]))
		tk.raw = strings.TrimSpace(m[1])
		if !ok {
			s.l.add(ReasonUnclassified, file)
			return nil, false
		}
		if tk.typ == "" {
			s.l.add(ReasonMember, file)
			return nil, false
		}
		if !seen[tk] {
			seen[tk] = true
			toks = append(toks, tk)
		}
	}
	if replaceRE.MatchString(lower) {
		// The text probably names a replacement, a default, a gate or a
		// requirement next to the name; what the action applies to cannot
		// be decided.
		s.l.add(ReasonAmbiguous, file)
		return nil, false
	}
	if action != ActionRemovedOrChanged {
		for _, tk := range toks {
			if !adjacent(quote, tk.raw) {
				s.l.add(ReasonAmbiguous, file)
				return nil, false
			}
		}
	}
	var out []Candidate
	for _, tk := range toks {
		c := comp
		if tk.typ == TypeFlag {
			c = ComponentUnknown
		}
		out = append(out, Candidate{
			Type: tk.typ, Action: action, Member: tk.member, Component: c,
			File: file, ChangeType: f.ChangeType, Section: SectionNote, Quote: quote,
			StartLine: st, EndLine: en, SpanExact: exact,
			SourceURL:     s.repo.BlobURL(s.sha, file),
			EvidenceBasis: EvidenceBasis, NeedsReview: true,
		})
	}
	return out, true
}

// adjacent reports whether the action verb stands right next to the token:
// before it ("Remove the flag `x`", also through a list of tokens) or after
// it ("`x` flag is removed", "`x` will be removed").
func adjacent(quote, raw string) bool {
	q := regexp.QuoteMeta("`" + raw + "`")
	art := `(?:\s+(?:the|a|an|flags?|fields?|keys?|options?|settings?|config|configuration))*\s+`
	pre := regexp.MustCompile(`(?i)` + verbRE + art + listRE + q)
	post := regexp.MustCompile(`(?i)` + q + `(?:\s*(?:,|and|or)\s*` + "`[^`\\n]+`" + `)*(?:\s+(?:flag|field|key|option|setting))*\s+(?:(?:is|are|was|were|has been|have been|will be|to be)\s+)` + verbRE)
	return pre.MatchString(quote) || post.MatchString(quote)
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
	for _, suf := range fileSuffixes {
		if strings.HasSuffix(t, suf) {
			return token{}, false
		}
	}
	if keyRE.MatchString(t) && !reservedKeys[t] {
		var segs []membercode.Seg
		for _, p := range strings.Split(t, ".") {
			segs = append(segs, membercode.Seg{Kind: membercode.Prop, Name: p})
		}
		mem, err := membercode.ConfigKey(segs)
		if err != nil {
			return token{}, true
		}
		return token{typ: TypeConfigKey, member: mem}, true
	}
	return token{}, false
}
