// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"context"
	"errors"
	"fmt"
	goscanner "go/scanner"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// PairSchema identifies the canonical JSON of a PairResult.
const PairSchema = "prufyx.io/cli-flags-pair/v1"

// FactRef names the set fact a pair's removals would feed, and whether the
// registry knows it. A removal is stated only for a registered fact.
//
// Digest is a SHA-256 over the matched registry definition (id, component,
// type, enum tokens) and the fixed shape of the fact; it is empty when the
// fact is unregistered. It is recorded in the Proof because the registry is
// not part of the code digest: a Proof derived against one registry is never
// byte-equal to one derived against another. A registry change can only turn
// "unregistered" into "registered", which adds candidates; it never removes a
// withhold of any other kind.
type FactRef struct {
	ID         string
	Component  string
	Registered bool
	Digest     string
}

// FactShape is the contract of the member of a cli_flags_set fact, hashed
// into FactRef.Digest.
const FactShape = "cli_flags_set:set:long-flag-names-without-dashes"

// PairResult is the comparison of two scans. It is the Proof of a pair. It
// states removal candidates and a ledger, and nothing else: it never says
// that a flag set is complete for a line, so it is never attestable.
//
// Candidates (Removed) are stated only when both scans are complete and
// ledger-free, the reviewed exclusions of both sides agree, the fact is
// registered, and for each name: every registration of it in the older tree
// is usable for a removal (Binary.Removable), no binary of the newer tree
// registers it (Binary.Present, which counts withheld registrations too), and
// no non-test Go file of the newer tree holds a string literal that spells it.
// Anything else is a ledger entry and the pair is not attested.
type PairResult struct {
	Schema    string `json:"schema"`
	Component string `json:"component"`
	FactID    string `json:"factId"`
	FactKnown bool   `json:"factRegistered"`
	// FactDigest is FactRef.Digest.
	FactDigest string `json:"factDigest"`
	// SourceNote says what the rule sources of this pair prove.
	SourceNote string  `json:"sourceNote"`
	From       *Result `json:"from"`
	To         *Result `json:"to"`
	// Exclusions are the reviewed exclusions that matched a directory, per
	// side. They are carried here as well as inside the scans.
	Exclusions PairExclusions `json:"exclusions"`
	// Removed are the flag names stated as removed, sorted. Empty when
	// anything withholds the whole pair.
	Removed []string `json:"removed"`
	// Omissions are the pair-level withheld items, as report text.
	Omissions []Omission `json:"omissions"`
	// Ledger is the canonical ledger of the pair: the pair-level entries and
	// the entries of both scans (item prefixed by the side, a reserved
	// LEDGER_ code renamed to SCAN_LEDGER_), in the form the framework
	// records. Top-level on purpose: the knowledge gate reads it by name.
	Ledger []LedgerEntry `json:"ledger"`
	// Residual states what this comparison cannot see.
	Residual []string `json:"residual"`
}

// PairExclusions are the matched exclusions of the two scans.
type PairExclusions struct {
	From []Exclusion `json:"from"`
	To   []Exclusion `json:"to"`
}

// Residual risks, recorded in every Proof.
var pairResidual = []string{
	"a flag name built by concatenation or Sprintf is not a literal and is not seen by the sweep",
	"environment variable forms of a flag are not inspected",
	"a renamed flag is stated as an ordinary removal; the replacement is not named",
}

// Attestable is always false: a comparison of two scans states candidates
// only, never that a set is complete for a release line.
func (p *PairResult) Attestable() bool { return false }

// ComparePair compares the scans of two pinned trees. A non-nil error means
// pinned bytes could not be read (reader failure, cancelled context, bad
// input); anything else that cannot be decided is in the ledger.
func ComparePair(ctx context.Context, r extract.PinnedReader, t Target, fromSHA, toSHA string, fact FactRef) (*PairResult, error) {
	from, err := Scan(ctx, r, t, fromSHA)
	if err != nil {
		return nil, err
	}
	to, err := Scan(ctx, r, t, toSHA)
	if err != nil {
		return nil, err
	}
	return comparePair(ctx, r, t, from, to, fact)
}

type pairBuilder struct {
	res *PairResult
	om  []Omission
}

func (b *pairBuilder) add(reason, subject, detail string) {
	b.om = append(b.om, Omission{Reason: reason, Subject: subject, Count: 1, Detail: detail})
}

func comparePair(ctx context.Context, r extract.PinnedReader, t Target, from, to *Result, fact FactRef) (*PairResult, error) {
	res := &PairResult{Schema: PairSchema, Component: fact.Component, FactID: fact.ID, FactKnown: fact.Registered, FactDigest: fact.Digest,
		SourceNote: "rule sources cite go.mod at both commits as a pin of the tree only; the flags were read from the binary directories listed in from.binaries and to.binaries",
		From:       from, To: to, Removed: []string{}, Omissions: []Omission{}, Ledger: []LedgerEntry{},
		Exclusions: PairExclusions{From: nonNilExcl(from.Excluded), To: nonNilExcl(to.Excluded)},
		Residual:   append([]string{}, pairResidual...)}
	b := &pairBuilder{res: res}

	// Whole-pair blocks: nothing is stated as removed.
	blocked := false
	if !fact.Registered {
		b.add(ReasonFactUnregistered, fact.ID, "")
		blocked = true
	}
	for _, s := range []struct {
		side string
		r    *Result
	}{{"from", from}, {"to", to}} {
		if !s.r.Attestable() {
			b.add(ReasonScanIncomplete, s.side, "")
			blocked = true
		}
	}
	for _, side := range []struct{ name, sha string }{{"from", from.Commit}, {"to", to.Commit}} {
		libs, err := unhashedLibs(ctx, r, t.Repo, side.sha)
		if err != nil {
			return nil, err
		}
		for _, l := range libs {
			b.add(ReasonLibUnhashed, side.name+":"+l, "")
			blocked = true
		}
	}
	for _, d := range exclusionDiff(from.Excluded, to.Excluded) {
		b.add(ReasonExclusionMismatch, d, "")
		blocked = true
	}

	if !blocked {
		removed, err := candidates(ctx, r, t, from, to, b)
		if err != nil {
			return nil, err
		}
		res.Removed = removed
	}
	if len(res.Removed) > constraintengine.MaxForbiddenMembers {
		b.add(ReasonSetTooLarge, "removed", "")
		res.Removed = []string{}
	}
	res.finish(b.om)
	return res, nil
}

func nonNilExcl(e []Exclusion) []Exclusion {
	if e == nil {
		return []Exclusion{}
	}
	return e
}

// exclusionDiff lists the directories whose matched exclusion is not the same
// on both sides (present on one side only, or with another reason).
func exclusionDiff(a, b []Exclusion) []string {
	ma, mb := map[string]string{}, map[string]string{}
	for _, e := range a {
		ma[e.Dir] = e.Reason
	}
	for _, e := range b {
		mb[e.Dir] = e.Reason
	}
	seen := map[string]bool{}
	var out []string
	for d, ra := range ma {
		if rb, ok := mb[d]; !ok || rb != ra {
			seen[d] = true
		}
	}
	for d, rb := range mb {
		if ra, ok := ma[d]; !ok || ra != rb {
			seen[d] = true
		}
	}
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// candidates decides, for the older tree's flags, which are stated as removed.
// Both scans are attestable here.
func candidates(ctx context.Context, r extract.PinnedReader, t Target, from, to *Result, b *pairBuilder) ([]string, error) {
	toDirs := map[string]*Binary{}
	for i := range to.Binaries {
		toDirs[to.Binaries[i].Dir] = &to.Binaries[i]
	}
	presentAnywhere := func(name string) bool {
		for i := range to.Binaries {
			if to.Binaries[i].Present(name) {
				return true
			}
		}
		return false
	}
	// Per name: every older registration must be usable for a removal.
	type state struct{ ok bool }
	names := map[string]*state{}
	for i := range from.Binaries {
		fb := &from.Binaries[i]
		tb, kept := toDirs[fb.Dir]
		if !kept {
			b.add(ReasonBinaryRemoved, "from:"+fb.Dir, "")
			continue
		}
		for _, f := range fb.Flags {
			st := names[f.Name]
			if st == nil {
				st = &state{ok: true}
				names[f.Name] = st
			}
			switch {
			case tb.Present(f.Name):
				// Same binary still registers it: not a removal. It must not
				// make another binary's removal of the name a removal.
				st.ok = false
			case presentAnywhere(f.Name):
				// Registered elsewhere in the newer tree: moved, not removed.
				b.add(ReasonNameStillPresent, fb.Dir+":"+f.Name, "registered by another binary of the newer tree")
				st.ok = false
			case !fb.Removable(f.Name):
				for _, w := range f.Withheld {
					b.add(w, fb.Dir+":"+f.Name, "")
				}
				if len(f.Withheld) == 0 {
					// Not removable without a reason of its own: never a
					// removal.
					b.add(ReasonScanIncomplete, "from:"+fb.Dir, f.Name)
				}
				st.ok = false
			}
		}
	}
	// A name is a candidate only when every registration of it in a kept
	// binary of the older tree stands for a removal. A binary that vanished
	// has its own ledger entry and contributes no name.
	var cand []string
	for n, st := range names {
		if st.ok {
			cand = append(cand, n)
		}
	}
	sort.Strings(cand)
	if len(cand) == 0 {
		return []string{}, nil
	}
	hits, why, err := sweepLiterals(ctx, r, t.Repo, to.Commit, cand)
	if err != nil {
		return nil, err
	}
	if why != "" {
		b.add(ReasonSweepIncomplete, "to", why)
		return []string{}, nil
	}
	var out []string
	for _, n := range cand {
		if p, found := hits[n]; found {
			b.add(ReasonNameStillPresent, n, "string literal in "+p)
			continue
		}
		if m, err := membercodeCheck(n); err != nil {
			b.add(m, n, "")
			continue
		}
		out = append(out, n)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// membercodeCheck re-checks the member contract of a stated removal. A name
// that fails was already unusable in the scan; this is the belt to that brace.
func membercodeCheck(name string) (string, error) {
	if code := MemberCode(name); code != "" {
		return code, errors.New("name is not a set member")
	}
	if !constraintengine.ValidSetMember(name) {
		return ReasonMemberCharset, errors.New("name is not a set member")
	}
	return "", nil
}

// ---- literal sweep ----

// sweepLiterals looks, in every non-test Go file of the tree at sha, for a
// string literal that spells one of names: the name, -name or --name, or a
// literal that starts with -name= or --name=. It returns the first file (in
// sorted walk order) per name found. A non-empty why means the sweep could
// not be completed (and nothing may be concluded from hits); a non-nil error
// is a read failure.
func sweepLiterals(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, sha string, names []string) (map[string]string, string, error) {
	return sweepLimited(ctx, r, repo, sha, names, defaultLimits())
}

func sweepLimited(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, sha string, names []string, lim limits) (map[string]string, string, error) {
	want := map[string][]string{}
	for _, n := range names {
		want[norm(n)] = append(want[norm(n)], n)
	}
	sw := &sweeper{ctx: ctx, r: r, repo: repo, sha: sha, want: want, hits: map[string]string{}, lim: lim}
	if err := sw.walk("", 0); err != nil {
		return nil, "", err
	}
	if sw.why != "" {
		return nil, sw.why, nil
	}
	return sw.hits, "", nil
}

type sweeper struct {
	ctx         context.Context
	r           extract.PinnedReader
	repo        extract.RepoRef
	sha         string
	want        map[string][]string
	hits        map[string]string
	lim         limits
	dirs, files int
	bytes       int
	why         string
	stopped     bool
}

func (s *sweeper) stop(why string) {
	if s.why == "" {
		s.why = why
	}
	s.stopped = true
}

func (s *sweeper) walk(dir string, depth int) error {
	if s.stopped {
		return nil
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if depth > s.lim.depth {
		s.stop("tree deeper than the limit")
		return nil
	}
	s.dirs++
	if s.dirs > s.lim.dirs {
		s.stop("more directories than the limit")
		return nil
	}
	entries, err := s.r.List(s.repo, s.sha, dir)
	switch {
	case errors.Is(err, extract.ErrNotFound):
		if dir == "" {
			s.stop("the tree has no root listing")
		}
		return nil
	case err != nil:
		return fmt.Errorf("cliflags: sweep list %s: %w", showDir(dir), err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, e := range entries {
		if s.stopped {
			return nil
		}
		if e.Path != path.Clean(e.Path) || strings.HasPrefix(e.Path, "/") || strings.HasPrefix(e.Path, "..") || (dir != "" && !strings.HasPrefix(e.Path, dir+"/")) {
			s.stop("a listing entry is not a clean path inside its directory")
			return nil
		}
		switch {
		case e.Type == "tree":
			if err := s.walk(e.Path, depth+1); err != nil {
				return err
			}
		case e.Type == "commit":
			s.stop("a submodule in the tree")
		case e.Type != "blob":
			s.stop("an entry of unknown type in the tree")
		case e.Mode == "120000" && strings.HasSuffix(e.Path, ".go"):
			s.stop("a Go file that is a link")
		case strings.HasSuffix(e.Path, ".go") && !strings.HasSuffix(e.Path, "_test.go"):
			if err := s.file(e.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *sweeper) file(p string) error {
	s.files++
	if s.files > s.lim.files {
		s.stop("more Go files than the limit")
		return nil
	}
	data, err := s.r.Read(s.repo, s.sha, p)
	if err != nil {
		return fmt.Errorf("cliflags: sweep read %s: %w", p, err)
	}
	if len(data) > s.lim.fileBytes {
		s.stop("a Go file over the size limit")
		return nil
	}
	s.bytes += len(data)
	if s.bytes > s.lim.totalBytes {
		s.stop("more bytes than the limit")
		return nil
	}
	fset := token.NewFileSet()
	f := fset.AddFile(p, fset.Base(), len(data))
	var sc goscanner.Scanner
	bad := false
	sc.Init(f, data, func(token.Position, string) { bad = true }, 0)
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok != token.STRING {
			continue
		}
		v, err := strconv.Unquote(lit)
		if err != nil {
			bad = true
			continue
		}
		for _, n := range spelled(v, s.want) {
			if _, seen := s.hits[n]; !seen {
				s.hits[n] = p
			}
		}
	}
	if bad {
		s.stop("a Go file could not be tokenised: " + clipPath(p))
	}
	return nil
}

func clipPath(p string) string {
	if len(p) > 100 {
		return p[:100]
	}
	return p
}

// norm folds the spellings a flag library may treat alike: case, and
// underscore versus dash.
func norm(v string) string {
	return strings.ReplaceAll(strings.ToLower(v), "_", "-")
}

// spelled returns the wanted names that literal v spells, after folding case
// and underscore/dash. want is keyed by the folded name.
func spelled(v string, want map[string][]string) []string {
	var out []string
	v = norm(v)
	try := func(c string) { out = append(out, want[c]...) }
	try(v)
	for _, dash := range []string{"-", "--"} {
		rest, ok := strings.CutPrefix(v, dash)
		if !ok {
			continue
		}
		try(rest)
		if name, _, has := strings.Cut(rest, "="); has {
			try(name)
		}
	}
	return out
}

// flagLibs are the flag libraries whose registrations live in their own code.
var flagLibs = []string{
	"github.com/spf13/pflag", "github.com/spf13/cobra", "github.com/alecthomas/kingpin",
	"gopkg.in/alecthomas/kingpin", "github.com/urfave/cli", "gopkg.in/urfave/cli",
	"k8s.io/component-base", "github.com/alecthomas/kong",
}

func isFlagLib(path string) (string, bool) {
	for _, l := range flagLibs {
		if path == l || strings.HasPrefix(path, l+"/") || strings.HasPrefix(path, l+".") {
			return l, true
		}
	}
	return "", false
}

// unhashedLibs lists the flag libraries go.mod requires that are neither
// bundled in the tree (listed by vendor/modules.txt) nor replaced: their
// source is not part of the pinned tree, so a registration inside one is
// invisible to the scan and the sweep. Items are the required module paths.
func unhashedLibs(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, sha string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	gm, err := r.Read(repo, sha, "go.mod")
	if errors.Is(err, extract.ErrNotFound) {
		return nil, nil // the scan has its own fault for this
	}
	if err != nil {
		return nil, fmt.Errorf("cliflags: read go.mod: %w", err)
	}
	required, replaced := goModLibs(string(gm))
	var out []string
	var vendored string
	loaded := false
	for _, mod := range required {
		if _, ok := isFlagLib(mod); !ok || replaced[mod] {
			continue
		}
		if !loaded {
			loaded = true
			mt, err := r.Read(repo, sha, "vendor/modules.txt")
			switch {
			case errors.Is(err, extract.ErrNotFound):
			case err != nil:
				return nil, fmt.Errorf("cliflags: read vendor/modules.txt: %w", err)
			default:
				vendored = string(mt)
			}
		}
		bundled := false
		for _, line := range strings.Split(vendored, "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "#" && f[1] == mod {
				bundled = true
			}
		}
		if !bundled {
			out = append(out, mod)
		}
	}
	sort.Strings(out)
	return out, nil
}

// goModLibs reads the required module paths and the old paths of replace
// directives of a go.mod, in single-line and block forms.
func goModLibs(gomod string) (required []string, replaced map[string]bool) {
	replaced = map[string]bool{}
	block := ""
	for _, line := range strings.Split(gomod, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		unq := func(x string) string { return strings.Trim(x, `"`) }
		switch {
		case block != "" && f[0] == ")":
			block = ""
		case block == "require":
			required = append(required, unq(f[0]))
		case block == "replace":
			replaced[unq(f[0])] = true
		case len(f) >= 2 && f[1] == "(" && (f[0] == "require" || f[0] == "replace"):
			block = f[0]
		case f[0] == "require" && len(f) >= 2:
			required = append(required, unq(f[1]))
		case f[0] == "replace" && len(f) >= 2:
			replaced[unq(f[1])] = true
		}
	}
	return required, replaced
}

// ---- ledger ----

const frameworkItemChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:/@+*[]-"

// ledgerItem turns an item into the framework's item form: its charset, at
// most MaxLedgerItemLen bytes. An item is an identifier, so a replaced
// character only changes a label.
func ledgerItem(item string) string {
	var sb strings.Builder
	for _, c := range []byte(item) {
		if strings.IndexByte(frameworkItemChars, c) >= 0 {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('_')
		}
	}
	out := sb.String()
	if out == "" {
		return "-"
	}
	if len(out) > MaxLedgerItemLen {
		out = out[:MaxLedgerItemLen]
	}
	return out
}

// scanCode renames a reserved ledger code of a scan: the framework refuses an
// extractor ledger that uses the reserved prefix.
func scanCode(code string) string {
	if strings.HasPrefix(code, ledgerReservedPrefix) {
		return "SCAN_" + code
	}
	return code
}

// PairLedgerOverflow replaces a ledger that would hold more entries than the
// framework accepts.
const PairLedgerOverflow = "FLAG_PAIR_LEDGER_OVERFLOW"

// finish sets Omissions and the canonical Ledger, and clears Removed when the
// ledger could not be recorded completely.
func (p *PairResult) finish(om []Omission) {
	sort.Slice(om, func(i, j int) bool {
		if om[i].Reason != om[j].Reason {
			return om[i].Reason < om[j].Reason
		}
		if om[i].Subject != om[j].Subject {
			return om[i].Subject < om[j].Subject
		}
		return om[i].Detail < om[j].Detail
	})
	p.Omissions = append(p.Omissions[:0], om...)
	var l []LedgerEntry
	for _, o := range om {
		l = append(l, LedgerEntry{Code: o.Reason, Item: ledgerItem(o.Subject)})
	}
	for _, s := range []struct {
		side string
		r    *Result
	}{{"from", p.From}, {"to", p.To}} {
		for _, e := range s.r.Ledger {
			l = append(l, LedgerEntry{Code: scanCode(e.Code), Item: ledgerItem(s.side + ":" + e.Item)})
		}
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].Code != l[j].Code {
			return l[i].Code < l[j].Code
		}
		return l[i].Item < l[j].Item
	})
	w := 0
	for i, e := range l {
		if i > 0 && e == l[w-1] {
			continue
		}
		l[w] = e
		w++
	}
	l = l[:w]
	if len(l) > extract.MaxLedgerEntries {
		l = []LedgerEntry{{Code: PairLedgerOverflow, Item: "ledger"}}
		p.Removed = []string{}
	}
	if l == nil {
		l = []LedgerEntry{}
	}
	p.Ledger = l
}
