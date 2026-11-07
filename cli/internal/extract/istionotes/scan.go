// SPDX-License-Identifier: AGPL-3.0-only

package istionotes

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
const ResultSchema = "prufyx.io/istio-notes-scan/v1"

// EvidenceBasis is the basis of every candidate. It is a lead for a reviewer and never a derived basis.
const EvidenceBasis = "draft"

// NotesDir is where Istio keeps the fragments.
const NotesDir = "releasenotes/notes"

// Fixed limits.
const (
	MaxFiles             = 5000
	MaxNoteBytes         = 64 << 10
	MaxQuoteBytes        = 4096
	MaxCandidatesPerNote = 32
	MaxCandidates        = 4096
)

// Candidate types.
const (
	TypeFlag    = "flag"
	TypeField   = "field"
	TypeCRDKind = "crd_kind"
)

// ComponentUnknown marks a flag candidate whose binary or component the note
// does not state.
const ComponentUnknown = "unknown"

// Actions.
const (
	ActionRemoved    = "removed"
	ActionDeprecated = "deprecated"
)

// Section names the note field a candidate came from.
const (
	SectionReleaseNotes = "releaseNotes"
	SectionUpgradeNotes = "upgradeNotes"
)

// Candidate is one DRAFT lead. Member is the set member through the shared
// encoder (flag name, or encoded field path); it is empty for a CRD kind,
// which the shared encoder has no form for (Group and Kind identify it).
type Candidate struct {
	Type   string `json:"type"`
	Action string `json:"action"`
	Member string `json:"member,omitempty"`
	// Component is "unknown" for a flag: a note does not name the binary
	// that owns it, so a reviewer must attribute it before any use.
	Component     string `json:"component,omitempty"`
	Group         string `json:"group,omitempty"`
	Kind          string `json:"kind,omitempty"`
	File          string `json:"file"`
	NoteKind      string `json:"noteKind"`
	Area          string `json:"area"`
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

// knownKinds is the reviewed table of Istio CRD kinds and their API groups.
// "Gateway" is deliberately absent: the name is shared with the Kubernetes
// Gateway API, so a bare mention cannot be attributed.
var knownKinds = map[string]string{
	"AuthorizationPolicy":   "security.istio.io",
	"DestinationRule":       "networking.istio.io",
	"EnvoyFilter":           "networking.istio.io",
	"IstioOperator":         "install.istio.io",
	"PeerAuthentication":    "security.istio.io",
	"ProxyConfig":           "networking.istio.io",
	"RequestAuthentication": "security.istio.io",
	"ServiceEntry":          "networking.istio.io",
	"Sidecar":               "networking.istio.io",
	"Telemetry":             "telemetry.istio.io",
	"VirtualService":        "networking.istio.io",
	"WasmPlugin":            "extensions.istio.io",
	"WorkloadEntry":         "networking.istio.io",
	"WorkloadGroup":         "networking.istio.io",
}

// noteKinds is the reviewed list of fragment kinds; any other is withheld.
var noteKinds = map[string]bool{
	"bug-fix": true, "cleanup": true, "deprecation": true, "documentation": true,
	"feature": true, "improvement": true, "optimization": true, "removal": true,
	"security-fix": true, "test": true,
}

var (
	fileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.yaml$`)
	areaRE     = regexp.MustCompile(`^[a-z][a-z0-9 -]{0,63}$`)
	tokenRE    = regexp.MustCompile("`([^`\\n]{1,200})`")
	flagRE     = regexp.MustCompile(`^--([a-z0-9][a-z0-9-]*)(=\S*)?$`)
	fieldRE    = regexp.MustCompile(`^([A-Z][A-Za-z0-9]*)\.([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*)$`)

	removedRE   = regexp.MustCompile(`\b(removed|removes|removal|remove)\b`)
	futureRE    = regexp.MustCompile(`\b(will be|to be|is going to be|are going to be|scheduled to be|will soon be)\s+removed\b`)
	deprecateRE = regexp.MustCompile(`\b(deprecated|deprecates|deprecate|deprecation)\b`)
	negationRE  = regexp.MustCompile(`\b(not|never|no longer|isn't|aren't|won't|without)\b[^.\n]{0,24}\b(removed|remove|deprecated|deprecate)\b`)
	replaceRE   = regexp.MustCompile(`\b(instead|replaced|replaces|replace|replacement|migrate|use|renamed|rename|now|requirement|requires|required|default|defaults|defaulted|value|values|changed|changes)\b`)
	// modalRE: modal, planned or versioned prose is a forecast or a
	// possibility, not a statement that something was removed.
	modalRE = regexp.MustCompile(`\b(may|can|could|should|would|might|shall|must)\s+(also\s+|soon\s+)?(be\s+)?(removed|deprecated)\b|\b(planned|scheduled|slated|intended)\s+(for\s+)?(removal|deprecation|to be removed)\b|\bremoval\s+(in|from|by)\b|\bremoved\s+(in|from|by)\s+(the\s+)?(next|upcoming|following|v?\d)|\b(if|unless|when|once)\b[^.\n]{0,60}\b(removed|deprecated)\b`)
	verbRE  = `(?:removed|removes|deprecated|deprecates)\*{0,2}`
	listRE  = "(?:`[^`\\n]+`\\s*(?:,|and|or)?\\s*)*"
)

// Scan reads the notes of the repository at commit sha. The reader must be
// pinned: sha is a full 40-character commit.
func Scan(ctx context.Context, r extract.PinnedReader, t Target, sha string) (res *Result, err error) {
	if !extract.IsCommitSHA(sha) {
		return nil, errors.New("istionotes: sha must be a full 40-character commit SHA")
	}
	res = &Result{Schema: ResultSchema, Commit: sha, Candidates: []Candidate{}, Ledger: []LedgerEntry{}}
	l := ledgerSet{}
	defer func() {
		if p := recover(); p != nil {
			l.add(ReasonPanic, NotesDir)
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
		l.add(ReasonTooManyCandidates, NotesDir)
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
	case a.Group != b.Group:
		return a.Group < b.Group
	case a.Kind != b.Kind:
		return a.Kind < b.Kind
	case a.Member != b.Member:
		return a.Member < b.Member
	case a.Section != b.Section:
		return a.Section < b.Section
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
	entries, err := s.r.List(s.repo, s.sha, NotesDir)
	if errors.Is(err, extract.ErrNotFound) {
		s.l.add(ReasonDirMissing, NotesDir)
		return nil
	}
	if err != nil {
		return fmt.Errorf("istionotes: list %s: %w", NotesDir, err)
	}
	if len(entries) > MaxFiles {
		s.l.add(ReasonTooManyFiles, NotesDir)
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, e := range entries {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if path.Dir(e.Path) != NotesDir || !fileNameRE.MatchString(path.Base(e.Path)) {
			s.l.add(ReasonUnsafeName, ledgerSafeItem(e.Path))
			continue
		}
		if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") {
			s.l.add(ReasonEntryNotFile, e.Path)
			continue
		}
		data, err := s.r.Read(s.repo, s.sha, e.Path)
		if errors.Is(err, extract.ErrNotFound) {
			s.l.add(ReasonUnreadable, e.Path)
			continue
		}
		if err != nil {
			return fmt.Errorf("istionotes: read %s: %w", e.Path, err)
		}
		res.FilesRead++
		if len(data) > MaxNoteBytes {
			s.l.add(ReasonTooLarge, e.Path)
			continue
		}
		res.Candidates = append(res.Candidates, s.note(e.Path, data)...)
	}
	return nil
}

// ledgerSafeItem keeps a hostile entry name out of the ledger spelling
// rules: the ledger names such an entry by a fixed placeholder.
func ledgerSafeItem(p string) string {
	if ledgerItemRE.MatchString(p) {
		return p
	}
	return NotesDir + "/INVALID"
}

type unit struct {
	section string
	quote   string
	start   int
	end     int
	exact   bool
	title   string
}

func (s *scanner) note(file string, data []byte) []Candidate {
	n, err := decodeNote(data)
	if err != nil {
		s.l.add(ReasonParse, file)
		return nil
	}
	if n.APIVersion != "release-notes/v2" {
		s.l.add(ReasonSchema, file)
		return nil
	}
	if !noteKinds[n.Kind] {
		s.l.add(ReasonKindUnknown, file)
		return nil
	}
	if !areaRE.MatchString(n.Area) {
		s.l.add(ReasonParse, file)
		return nil
	}
	var units []unit
	for _, t := range n.ReleaseNotes {
		st, en, exact := span(t)
		units = append(units, unit{section: SectionReleaseNotes, quote: strings.TrimSpace(t.Value), start: st, end: en, exact: exact})
	}
	for _, u := range n.UpgradeNotes {
		st, en, exact := span(u.Content)
		q := strings.TrimSpace(u.Title.Value) + "\n" + strings.TrimSpace(u.Content.Value)
		if u.Title.Line < st {
			st = u.Title.Line
		}
		units = append(units, unit{section: SectionUpgradeNotes, quote: q, start: st, end: en, exact: exact && u.Title.Line < u.Content.Line})
	}
	var out []Candidate
	for _, u := range units {
		cs, ok := s.unit(file, n, u)
		if !ok {
			continue
		}
		out = append(out, cs...)
	}
	if len(out) > MaxCandidatesPerNote {
		s.l.add(ReasonTooManyCandidates, file)
		return nil
	}
	return out
}

func span(t text) (start, end int, exact bool) {
	start = t.Line
	if t.Block {
		start++
	}
	lines := strings.Count(strings.TrimRight(t.Value, "\n"), "\n")
	return start, start + lines, t.Literal
}

type token struct {
	typ, member, group, kind, raw string
}

// unit classifies one text. It returns (candidates, true) or withholds the
// text with a ledger entry and returns (nil, false). A text that carries no
// action signal at all is not an error and yields nothing.
func (s *scanner) unit(file string, n *note, u unit) ([]Candidate, bool) {
	lower := strings.ToLower(u.quote)
	removed := removedRE.MatchString(lower)
	deprecated := deprecateRE.MatchString(lower)
	if futureRE.MatchString(lower) {
		// "will be removed" announces a removal: a deprecation. Strip the
		// phrase before judging whether a plain removal is also stated.
		deprecated = true
		removed = removedRE.MatchString(futureRE.ReplaceAllString(lower, ""))
	}
	kindAction := ""
	switch n.Kind {
	case "removal":
		kindAction = ActionRemoved
	case "deprecation":
		kindAction = ActionDeprecated
	}
	if !removed && !deprecated && kindAction == "" {
		return nil, false
	}
	if modalRE.MatchString(lower) || negationRE.MatchString(lower) || (removed && deprecated) {
		s.l.add(ReasonAmbiguous, file)
		return nil, false
	}
	action := kindAction
	switch {
	case removed:
		action = ActionRemoved
	case deprecated:
		action = ActionDeprecated
	}
	if kindAction != "" && action != kindAction {
		s.l.add(ReasonAmbiguous, file)
		return nil, false
	}
	if len(u.quote) > MaxQuoteBytes {
		s.l.add(ReasonTextTooLarge, file)
		return nil, false
	}
	if strings.Contains(u.quote, "```") || strings.Count(u.quote, "`")%2 != 0 {
		s.l.add(ReasonUnclassified, file)
		return nil, false
	}
	matches := tokenRE.FindAllStringSubmatch(u.quote, -1)
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
		// The text probably names a replacement, a default or a requirement
		// next to the name; what the action applies to cannot be decided.
		s.l.add(ReasonAmbiguous, file)
		return nil, false
	}
	for _, tk := range toks {
		if !adjacent(u.quote, tk.raw) {
			s.l.add(ReasonAmbiguous, file)
			return nil, false
		}
	}
	var out []Candidate
	for _, tk := range toks {
		comp := ""
		if tk.typ == TypeFlag {
			comp = ComponentUnknown
		}
		out = append(out, Candidate{
			Component: comp, Type: tk.typ, Action: action, Member: tk.member, Group: tk.group, Kind: tk.kind,
			File: file, NoteKind: n.Kind, Area: n.Area, Section: u.section, Quote: u.quote,
			StartLine: u.start, EndLine: u.end, SpanExact: u.exact,
			SourceURL:     s.repo.BlobURL(s.sha, file),
			EvidenceBasis: EvidenceBasis, NeedsReview: true,
		})
	}
	return out, true
}

// adjacent reports whether the action verb stands right next to the token:
// before it ("Removed the flag `x`", also through a list of tokens) or after
// it ("`x` flag is removed", "`x` will be removed").
func adjacent(quote, raw string) bool {
	q := regexp.QuoteMeta("`" + raw + "`")
	art := `(?:\s+(?:the|a|an|flags?|fields?|kinds?|options?|resources?))*\s+`
	pre := regexp.MustCompile(`(?i)` + verbRE + art + listRE + q)
	post := regexp.MustCompile(`(?i)` + q + `(?:\s*(?:,|and|or)\s*` + "`[^`\\n]+`" + `)*(?:\s+(?:flag|field|kind))?\s+(?:(?:is|are|was|were|has been|have been|will be|to be)\s+)` + verbRE)
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
	if grp, ok := knownKinds[t]; ok {
		return token{typ: TypeCRDKind, group: grp, kind: t}, true
	}
	if m := fieldRE.FindStringSubmatch(t); m != nil {
		grp, ok := knownKinds[m[1]]
		if !ok {
			return token{}, false
		}
		var segs []membercode.Seg
		for _, p := range strings.Split(m[2], ".") {
			segs = append(segs, membercode.Seg{Kind: membercode.Prop, Name: p})
		}
		mem, err := membercode.Field(grp, m[1], segs)
		if err != nil {
			return token{}, true
		}
		return token{typ: TypeField, member: mem, group: grp, kind: m[1]}, true
	}
	return token{}, false
}
