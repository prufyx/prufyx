// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// ClassifyInput is what the mechanical-neutral classifier sees of one item.
type ClassifyInput struct {
	Component string
	Tag       string
	Item      ce.Item
	// Text is the item's lines, LF joined, as read at the tag.
	Text string
}

// Classifier decides whether an item without a reviewed mark is mechanically
// neutral. It has one output: true says the item needs no mark; false leaves
// it needing one. It can never emit a rule and never drop an item. A nil
// Classifier makes mechanical-neutral unavailable, so every item needs a
// reviewed mark.
type Classifier interface {
	MechanicalNeutral(ClassifyInput) bool
}

// Config is everything one component's attestation reads besides the
// repository: the reviewed target row, the reviewed dispositions, the pack
// rules and the optional classifier.
type Config struct {
	Target       ce.Target
	Dispositions *Dispositions
	// PackRules are the rules of the pack as raw JSON: every one whose
	// subject is the component on the attested line is listed by the
	// attestation.
	PackRules  []json.RawMessage
	Classifier Classifier
}

// Disposition of one item, as recorded in the proof.
type Disposition struct {
	Tag         string `json:"tag"`
	ItemDigest  string `json:"itemDigest"`
	Occurrence  int    `json:"occurrence"`
	Disposition string `json:"disposition"`
}

// Proof is the account of one derivation, recorded in the manifest.
type Proof struct {
	Component    string        `json:"component"`
	Line         string        `json:"line"`
	Window       []string      `json:"window"`
	Entries      []*ce.Entry   `json:"entries"`
	Dispositions []Disposition `json:"dispositions"`
	RuleIDs      []string      `json:"ruleIds"`
}

// Result is a derived attestation candidate and its proof.
type Result struct {
	Candidate extract.AttestationCandidate
	Proof     Proof
}

type rel struct {
	maj, min, pat int
	version       string
	tag           extract.Tag
}

var relRE = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

func parseRel(t extract.Tag) (rel, bool) {
	m := relRE.FindStringSubmatch(t.Name)
	if m == nil || !extract.IsCommitSHA(t.Commit) {
		return rel{}, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return rel{a, b, c, fmt.Sprintf("%d.%d.%d", a, b, c), t}, true
}

func less(a, b rel) bool {
	if a.maj != b.maj {
		return a.maj < b.maj
	}
	if a.min != b.min {
		return a.min < b.min
	}
	return a.pat < b.pat
}

func failf(c ce.Code, format string, a ...any) error {
	return &ce.Failure{Code: c, Detail: fmt.Sprintf(format, a...)}
}

type packRule struct {
	id         string
	component  string
	transition constraintengine.RuleTransition
	line       string
	state      string
	sources    []constraintengine.SourceEvidence
}

func parsePackRules(raw []json.RawMessage) ([]packRule, error) {
	var out []packRule
	ids := map[string]bool{}
	for _, r := range raw {
		var s struct {
			ID      string `json:"id"`
			Subject struct {
				Component string                     `json:"component"`
				From      string                     `json:"from"`
				To        string                     `json:"to"`
				Chart     *constraintengine.ChartRef `json:"chart"`
			} `json:"subject"`
			Range    *constraintengine.VersionRange `json:"range"`
			Crossing *constraintengine.CrossingSpec `json:"crossing"`
			Evidence struct {
				State   string                            `json:"state"`
				Sources []constraintengine.SourceEvidence `json:"sources"`
			} `json:"evidence"`
		}
		if err := json.Unmarshal(r, &s); err != nil {
			return nil, fmt.Errorf("pack rule: %w", err)
		}
		if s.ID == "" || ids[s.ID] {
			return nil, fmt.Errorf("pack rule id %q is empty or appears twice", s.ID)
		}
		ids[s.ID] = true
		p := packRule{id: s.ID, component: s.Subject.Component, state: s.Evidence.State, sources: s.Evidence.Sources,
			transition: constraintengine.RuleTransition{Component: s.Subject.Component, From: s.Subject.From, To: s.Subject.To, Range: s.Range, Crossing: s.Crossing, Chart: s.Subject.Chart}}
		p.line, _ = lineattest.LineOf(s.Subject.To)
		out = append(out, p)
	}
	return out, nil
}

// finalTags reads the final release tags of an index: one tag per version,
// sorted ascending. A version tagged at two commits is refused (TAG_MOVED).
func finalTags(tags []extract.Tag) (map[string]rel, []rel, error) {
	byVersion := map[string]rel{}
	var all []rel
	for _, tg := range tags {
		x, ok := parseRel(tg)
		if !ok {
			continue
		}
		if prev, dup := byVersion[x.version]; dup {
			if prev.tag.Commit != tg.Commit {
				return nil, nil, failf(ce.TagMoved, "release %s is tagged at two commits", x.version)
			}
			if prev.tag.Name <= tg.Name {
				continue
			}
		}
		byVersion[x.version] = x
	}
	for _, x := range byVersion {
		all = append(all, x)
	}
	sort.Slice(all, func(i, j int) bool { return less(all[i], all[j]) })
	return byVersion, all, nil
}

// Attest derives the attestation candidate of one pair Lf -> Lt of the
// config's component from the repository's final tags. The window is the
// entries of Lf.1..Lf.n and Lt.0..Lt.m: the entry of Lf.0 describes the hop
// into Lf and is never read. Every item of every window entry must be
// resolved: by a reviewed mark of the dispositions file (a rule or
// not-operator-facing), or mechanically neutral by the injected classifier.
// Any failure is a *changelogentries.Failure with its typed code; any other
// error is a read failure. Nothing is attested on a failure.
func Attest(r extract.PinnedReader, cfg Config, tags []extract.Tag, pair extract.VersionPair) (*Result, error) {
	t := cfg.Target
	if cfg.Dispositions == nil || cfg.Dispositions.Component != t.Component {
		return nil, failf(ce.NoChangelogTarget, "no reviewed dispositions for %s", t.Component)
	}
	rules, err := parsePackRules(cfg.PackRules)
	if err != nil {
		return nil, failf(ce.RuleNotLineWide, "%v", err)
	}

	// Final tags, one commit per version.
	byVersion, all, err := finalTags(tags)
	if err != nil {
		return nil, err
	}

	from, okf := parseRel(extract.Tag{Name: pair.FromTag, Commit: pair.FromCommit})
	to, okt := parseRel(extract.Tag{Name: pair.ToTag, Commit: pair.ToCommit})
	if !okf || !okt || from.maj != to.maj || from.min+1 != to.min {
		return nil, failf(ce.NotPreviousMinor, "%s -> %s is not a hop to the next minor line of one major", pair.From, pair.To)
	}
	for _, p := range []rel{from, to} {
		if got, ok := byVersion[p.version]; !ok || got.tag.Commit != p.tag.Commit {
			return nil, failf(ce.TagMoved, "the pair's tag %s is not in the tag index at that commit", p.tag.Name)
		}
	}
	if l, ok := lineattest.LineOf(pair.To); !ok || l != fmt.Sprintf("%d.%d", to.maj, to.min) {
		return nil, failf(ce.NotPreviousMinor, "%s has no minor line", pair.To)
	}
	line := fmt.Sprintf("%d.%d", to.maj, to.min)
	var lf, lt []rel
	for _, x := range all {
		switch {
		case x.maj == from.maj && x.min == from.min:
			lf = append(lf, x)
		case x.maj == to.maj && x.min == to.min:
			lt = append(lt, x)
		}
	}
	if len(lf) == 0 || len(lt) == 0 || len(lf) > lineattest.MaxReleases || len(lt) > lineattest.MaxReleases {
		return nil, failf(ce.NotPreviousMinor, "a line has no final release or more than %d", lineattest.MaxReleases)
	}
	if lt[0].pat != 0 {
		return nil, failf(ce.EntryMissing, "line %s has no final tag for %d.%d.0", line, to.maj, to.min)
	}

	// The window. Lf.0 is not in it.
	var window []rel
	for _, x := range lf {
		if x.pat >= 1 {
			window = append(window, x)
		}
	}
	window = append(window, lt...)
	if len(window) > constraintengine.MaxSources {
		return nil, failf(ce.LineTooManyFinals, "line %s has a window of %d final releases; a record cites at most %d sources", line, len(window), constraintengine.MaxSources)
	}
	newest := all[len(all)-1]

	// Rules of the component on the line: every one is listed and must be
	// line-wide.
	family, _ := lineattest.LookupFamily(lineattest.FamilyChangelogAttestedEntries)
	ruleByID := map[string]packRule{}
	var ruleIDs []string
	for _, p := range rules {
		ruleByID[p.id] = p
		if p.component != t.Component {
			continue
		}
		if p.line != line {
			if p.line == "" {
				return nil, failf(ce.RuleNotLineWide, "rule %s of %s has no release line in subject.to", p.id, t.Component)
			}
			continue
		}
		if !family.CoversLine(t.Component, p.transition, line) {
			return nil, failf(ce.RuleNotLineWide, "rule %s does not match every transition into line %s", p.id, line)
		}
		ruleIDs = append(ruleIDs, p.id)
	}
	listed := map[string]bool{}
	for _, id := range ruleIDs {
		listed[id] = true
	}

	idx := cfg.Dispositions.index()
	used := map[markKey]bool{}
	windowNames := map[string]bool{}
	for _, w := range window {
		windowNames[w.tag.Name] = true
	}

	proof := Proof{Component: t.Component, Line: line, Window: []string{}, Entries: []*ce.Entry{}, Dispositions: []Disposition{}}
	var sources []extract.SourceRef
	byTagItems := map[string]map[markKey]bool{}
	for _, w := range window {
		e, err := ce.Locate(r, t, w.tag)
		if err != nil {
			return nil, err
		}
		if e.TagCommit != w.tag.Commit || e.Source.Commit != w.tag.Commit {
			return nil, failf(ce.TagMoved, "the entry of %s was not read at the tag commit", w.tag.Name)
		}
		// Amendment: the same version's section at the newest final tag
		// must hold no item the tag's own read lacks.
		if newest.tag.Commit != w.tag.Commit {
			n, err := ce.Locate(r, t, extract.Tag{Name: w.tag.Name, Commit: newest.tag.Commit})
			if err != nil {
				return nil, err
			}
			have := map[markKey]bool{}
			for _, it := range e.Items {
				have[markKey{it.Digest, it.Occurrence}] = true
			}
			for _, it := range n.Items {
				if !have[markKey{it.Digest, it.Occurrence}] {
					return nil, failf(ce.EntryAmended, "the entry of %s at %s holds an item the tag's own read lacks (line %d)", w.tag.Name, newest.tag.Name, it.StartLine)
				}
			}
		}
		var lines []string
		if cfg.Classifier != nil {
			lines, err = itemLines(r, t, e)
			if err != nil {
				return nil, err
			}
		}
		items := map[markKey]bool{}
		for _, it := range e.Items {
			k := markKey{it.Digest, it.Occurrence}
			items[k] = true
			disp, err := resolve(cfg, w, e, it, idx[k], ruleByID, listed, lines, line)
			if err != nil {
				return nil, err
			}
			used[k] = true
			proof.Dispositions = append(proof.Dispositions, Disposition{Tag: w.tag.Name, ItemDigest: it.Digest, Occurrence: it.Occurrence, Disposition: disp})
		}
		byTagItems[w.tag.Name] = items
		proof.Window = append(proof.Window, w.tag.Name)
		proof.Entries = append(proof.Entries, e)
		sources = append(sources, extract.SourceRef{ID: "changelog-" + w.version, Repo: t.Repo, Commit: w.tag.Commit, Path: t.Path,
			StartLine: e.Section.StartLine, EndLine: e.Section.EndLine})
	}
	// A mark that points into the window but matches no item of its tag is a
	// stale or mistyped mark: refused, never ignored.
	for _, m := range cfg.Dispositions.Marks {
		k := markKey{m.ItemDigest, m.Occurrence}
		if used[k] {
			if !byTagItems[m.Tag][k] {
				return nil, failf(ce.ItemUnresolved, "mark of item %s names tag %q, which is not the tag of that item", short(m.ItemDigest), m.Tag)
			}
			continue
		}
		if windowNames[m.Tag] {
			return nil, failf(ce.ItemUnresolved, "mark of item %s matches no item of tag %s", short(m.ItemDigest), m.Tag)
		}
	}

	rels := func(list []rel) []lineattest.Release {
		out := make([]lineattest.Release, 0, len(list))
		for _, x := range list {
			out = append(out, lineattest.Release{Version: x.version, Commit: x.tag.Commit})
		}
		return out
	}
	sort.Strings(ruleIDs)
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	proof.RuleIDs = ruleIDs
	return &Result{
		Candidate: extract.AttestationCandidate{
			Basis: extract.BasisMechanical, Component: t.Component, Line: line, FactFamily: lineattest.FamilyChangelogAttestedEntries,
			RuleIDs: ruleIDs, Releases: &lineattest.Releases{From: rels(lf), To: rels(lt)}, Sources: sources,
		},
		Proof: proof,
	}, nil
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// itemLines reads the entry's file again at its tag commit and returns its
// lines, after checking it is the very blob the entry was derived from.
func itemLines(r extract.PinnedReader, t ce.Target, e *ce.Entry) ([]string, error) {
	raw, err := r.Read(t.Repo, e.Source.Commit, t.Path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != e.Source.FileDigest {
		return nil, failf(ce.TagMoved, "the file of %s changed between two reads", e.Tag)
	}
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n"), nil
}

// resolve decides one item. It returns the disposition token or a typed
// failure; there is no third outcome.
func resolve(cfg Config, w rel, e *ce.Entry, it ce.Item, marks []Mark, rules map[string]packRule, listed map[string]bool, lines []string, line string) (string, error) {
	var neutral []string
	var bound []string
	for _, m := range marks {
		if m.Tag != w.tag.Name {
			return "", failf(ce.ItemUnresolved, "mark of item %s names tag %q, the item is in %s", short(it.Digest), m.Tag, w.tag.Name)
		}
		switch m.Kind {
		case KindNotOperatorFacing:
			neutral = append(neutral, "reviewed-neutral:"+m.ReasonClass)
		case KindRule:
			// A patch release's change cannot be a line-wide rule: the
			// release-note rule shape covers x.y.0 only.
			if w.pat != 0 {
				return "", failf(ce.ItemRuleShapeUnsupported, "item at line %d of %s is in a patch release: no rule shape covers it", it.StartLine, w.tag.Name)
			}
			if err := checkRule(cfg, rules, listed, m.RuleID, e, it); err != nil {
				return "", err
			}
			bound = append(bound, "rule:"+m.RuleID)
		}
	}
	switch {
	case len(bound) > 0:
		return strings.Join(bound, ","), nil
	case len(neutral) > 0:
		return neutral[0], nil
	}
	if cfg.Classifier != nil && lines != nil && it.EndLine <= len(lines) {
		in := ClassifyInput{Component: cfg.Target.Component, Tag: w.tag.Name, Item: it, Text: strings.Join(lines[it.StartLine-1:it.EndLine], "\n")}
		if cfg.Classifier.MechanicalNeutral(in) {
			return "mechanical-neutral", nil
		}
	}
	return "", failf(ce.ItemUnresolved, "item at lines %d-%d of %s has no reviewed mark", it.StartLine, it.EndLine, w.tag.Name)
}

func checkRule(cfg Config, rules map[string]packRule, listed map[string]bool, id string, e *ce.Entry, it ce.Item) error {
	p, ok := rules[id]
	switch {
	case !ok:
		return failf(ce.ItemUnresolved, "rule %s is not in the pack", id)
	case p.component != cfg.Target.Component:
		return failf(ce.ItemUnresolved, "rule %s is a rule of another component", id)
	case !listed[id]:
		return failf(ce.ItemUnresolved, "rule %s is not a rule of the attested line", id)
	case p.state != "active":
		return failf(ce.ItemUnresolved, "rule %s is %q, not active", id, p.state)
	}
	url := cfg.Target.Repo.BlobURL(e.Source.Commit, e.Source.Path)
	for _, s := range p.sources {
		if s.URL == url && s.Revision == e.Source.Commit && s.ContentDigest == "sha256:"+e.Source.FileDigest &&
			s.StartLine >= it.StartLine && s.EndLine <= it.EndLine && s.StartLine <= s.EndLine {
			return nil
		}
	}
	return failf(ce.ItemUnresolved, "rule %s cites no span inside item lines %d-%d of %s", id, it.StartLine, it.EndLine, e.Tag)
}

// ScopeText is the family's scope statement with X..Y filled from the tags
// of the proof's window: the first and last tag whose entry was read.
func ScopeText(p Proof) (string, bool) {
	family, ok := lineattest.LookupFamily(lineattest.FamilyChangelogAttestedEntries)
	if !ok || len(p.Window) == 0 {
		return "", false
	}
	s := family.Scope()
	const marker = "tags X..Y"
	if strings.Count(s, marker) != 1 {
		return "", false
	}
	return strings.Replace(s, marker, "tags "+p.Window[0]+".."+p.Window[len(p.Window)-1], 1), true
}
