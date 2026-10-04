// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NormaliserVersion identifies the section rules, the line grammar and
// the character rules below. Any change to what Normalise outputs or
// accepts must change it.
const NormaliserVersion = "2"

// Bounds of a release notes file and of list nesting.
const (
	MaxSourceBytes = 2 << 20
	MaxLineBytes   = 64 << 10
	// MaxListDepth bounds list nesting: item markers are indented by 0, 2,
	// ... 2*(MaxListDepth-1) spaces.
	MaxListDepth = 4
)

// Line flags: characters removed from a line. Both make a line hidden
// content; a citation of a hidden line is never verified.
const (
	FlagInvisibleCharacter = "invisible-character"
	FlagControlCharacter   = "control-character"
)

// SectionSpec names the release notes file and the release whose section
// is selected.
type SectionSpec struct {
	// Repo is the repository key, e.g. "github.com/kubernetes/kubernetes".
	Repo string
	// Path is the repository path of the release notes file.
	Path string
	// Version is the release, e.g. "v1.31.0".
	Version string
}

// Refusal is a release notes file or section the normaliser will not
// produce output for. Code is a short stable token.
type Refusal struct {
	Code   string
	Detail string
}

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return r.Code
	}
	return r.Code + ": " + r.Detail
}

func refuse(code, format string, a ...any) error {
	return &Refusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// Line is one line of the selected section.
type Line struct {
	Text string
	// Original is the 1-based line number in the source file.
	Original int
	// Flags name what was removed from the line, sorted.
	Flags []string
	// Problem is set when the line is outside the line grammar.
	Problem string
}

// Hidden reports whether characters were removed from the line.
func (l Line) Hidden() bool { return len(l.Flags) > 0 }

// Problem is a line of the section outside the line grammar.
type Problem struct {
	// Original is the 1-based line number in the source file.
	Original int    `json:"original"`
	Reason   string `json:"reason"`
}

// Normalised is the selected section: the release's citable subsections,
// in file order, each starting with its heading.
type Normalised struct {
	Section string
	Lines   []Line
	// Problems lists every line outside the line grammar, and every
	// construct left open before a subsection starts. A section with a
	// problem is not citable.
	Problems []Problem
}

// Parsed reports whether every line of the section is inside the grammar.
func (n Normalised) Parsed() bool { return len(n.Problems) == 0 }

// Text is the normalised section: its lines joined by LF, with a final LF.
func (n Normalised) Text() []byte {
	var b strings.Builder
	for _, l := range n.Lines {
		b.WriteString(l.Text)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// Digest is the lowercase hex sha256 of Text.
func (n Normalised) Digest() string {
	sum := sha256.Sum256(n.Text())
	return hex.EncodeToString(sum[:])
}

// FileDigest is the lowercase hex sha256 of a file's bytes.
func FileDigest(src []byte) string {
	sum := sha256.Sum256(src)
	return hex.EncodeToString(sum[:])
}

// KubernetesRepo is the only repository with a section rule.
const KubernetesRepo = "github.com/kubernetes/kubernetes"

var (
	k8sChangelogPath = regexp.MustCompile(`^CHANGELOG/CHANGELOG-1\.(0|[1-9][0-9]{0,2})\.md$`)
	k8sReleaseTag    = regexp.MustCompile(`^v1\.(0|[1-9][0-9]{0,2})\.0$`)
)

// sectionRule is how one repository's release notes are read.
type sectionRule struct {
	// heading opens the release's section (a level-1 heading); the
	// section ends at the next level-1 heading.
	heading string
	// subsections are the level-2 headings whose content is citable; each
	// ends at the next heading of level 1 or 2.
	subsections []string
	// owner and name of the repository whose pull requests are cited.
	owner, name string
	// docsHosts are the hosts a link may point at besides the repository's
	// pull requests and issues and a contributor's profile.
	docsHosts []string
}

// ruleFor returns the section rule. Only Kubernetes has one:
// CHANGELOG/CHANGELOG-1.N.md, the section "# v1.N.0", and in it the
// subsections "## Urgent Upgrade Notes" and "## Changes by Kind".
func ruleFor(spec SectionSpec) (sectionRule, error) {
	if spec.Repo != KubernetesRepo {
		return sectionRule{}, refuse("no-section-rule", "no section rule for repository %q", spec.Repo)
	}
	pm := k8sChangelogPath.FindStringSubmatch(spec.Path)
	vm := k8sReleaseTag.FindStringSubmatch(spec.Version)
	if pm == nil || vm == nil || pm[1] != vm[1] {
		return sectionRule{}, refuse("no-section-rule", "the section rule needs CHANGELOG/CHANGELOG-1.N.md and v1.N.0 with the same N")
	}
	return sectionRule{
		heading:     "# " + spec.Version,
		subsections: []string{"## Urgent Upgrade Notes", "## Changes by Kind"},
		owner:       "kubernetes", name: "kubernetes",
		docsHosts: []string{"kubernetes.io", "k8s.io", "docs.k8s.io"},
	}, nil
}

// KubernetesMinor returns N of a v1.N.0 tag.
func KubernetesMinor(tag string) (int, bool) {
	m := k8sReleaseTag.FindStringSubmatch(tag)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// invisible reports runes that render as nothing or reorder text: zero
// width and joiner characters, bidirectional controls, invisible operators,
// the byte order mark, soft hyphen, variation selectors and tag characters.
func invisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x2069,
		r == 0xFEFF, r == 0x00AD, r == 0x034F, r == 0x061C, r == 0x115F, r == 0x1160, r == 0x17B4, r == 0x17B5,
		r == 0x180E, r == 0x2028, r == 0x2029, r == 0x3164, r == 0xFFA0,
		r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0000 && r <= 0xE007F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return false
}

// control reports C0 and C1 control characters other than tab.
func control(r rune) bool {
	return (r < 0x20 && r != '\t') || r == 0x7F || (r >= 0x80 && r <= 0x9F)
}

var (
	level1RE = regexp.MustCompile(`^ {0,3}#([ \t]|$)`)
	level2RE = regexp.MustCompile(`^ {0,3}#{1,2}([ \t]|$)`)
)

// Normalise selects the release's citable subsections of a release notes
// file and checks every line against the line grammar. Characters are
// removed only when invisible or control characters (and the line is
// flagged); nothing else is rewritten. It is deterministic.
func Normalise(src []byte, spec SectionSpec) (Normalised, error) {
	rule, err := ruleFor(spec)
	if err != nil {
		return Normalised{}, err
	}
	if len(src) > MaxSourceBytes {
		return Normalised{}, refuse("too-large", "%d bytes, at most %d", len(src), MaxSourceBytes)
	}
	if !utf8.Valid(src) {
		return Normalised{}, refuse("invalid-utf8", "the file is not valid UTF-8")
	}
	raw := strings.Split(string(src), "\n")
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	lines := make([]Line, len(raw))
	for i, text := range raw {
		if len(text) > MaxLineBytes {
			return Normalised{}, refuse("line-too-long", "line %d has %d bytes, at most %d", i+1, len(text), MaxLineBytes)
		}
		// CRLF becomes LF; any other carriage return is a control
		// character below.
		lines[i] = stripCharacters(strings.TrimSuffix(text, "\r"), i+1)
	}

	start := -1
	for i, l := range lines {
		if strings.TrimRight(l.Text, " \t") == rule.heading {
			if start >= 0 {
				return Normalised{}, refuse("section-ambiguous", "%q appears on lines %d and %d", rule.heading, lines[start].Original, l.Original)
			}
			start = i
		}
	}
	if start < 0 {
		return Normalised{}, refuse("no-section", "no %q heading", rule.heading)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if level1RE.MatchString(lines[i].Text) {
			end = i
			break
		}
	}

	out := Normalised{Section: spec.Version}
	opens := blockStates(lines)
	found := map[string]bool{}
	for i := start + 1; i < end; i++ {
		head := strings.TrimRight(lines[i].Text, " \t")
		if !contains(rule.subsections, head) {
			continue
		}
		if found[head] {
			return Normalised{}, refuse("section-ambiguous", "%q appears twice in the section", head)
		}
		found[head] = true
		stop := end
		for j := i + 1; j < end; j++ {
			if level2RE.MatchString(lines[j].Text) {
				stop = j
				break
			}
		}
		sub := append([]Line{}, lines[i:stop]...)
		g := grammar{rule: rule}
		for k := range sub {
			var p string
			if k > 0 {
				p = g.line(sub[k].Text)
			}
			// A heading inside a construct opened before it is rendered
			// as part of that construct.
			if open := opens[i+k]; p == "" && open != "" && strings.HasPrefix(sub[k].Text, "#") {
				p = open + " left open before the heading"
			}
			if p != "" {
				sub[k].Problem = p
				out.Problems = append(out.Problems, Problem{Original: sub[k].Original, Reason: p})
			}
		}
		for k := range sub {
			sub[k].Text = strings.TrimRight(sub[k].Text, " ")
		}
		out.Lines = append(out.Lines, sub...)
	}
	if len(found) == 0 {
		return Normalised{}, refuse("no-section", "no citable subsection in %q", rule.heading)
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// stripCharacters removes invisible and control characters from one line.
func stripCharacters(text string, original int) Line {
	var b strings.Builder
	flags := map[string]bool{}
	for _, r := range text {
		switch {
		case invisible(r):
			flags[FlagInvisibleCharacter] = true
		case control(r):
			flags[FlagControlCharacter] = true
		default:
			b.WriteRune(r)
		}
	}
	l := Line{Text: b.String(), Original: original}
	for _, f := range []string{FlagControlCharacter, FlagInvisibleCharacter} {
		if flags[f] {
			l.Flags = append(l.Flags, f)
		}
	}
	return l
}

var (
	fenceOpenRE = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
	// CommonMark HTML block start conditions 1-5 (which end at a marker)
	// and 6-7 (which end at a blank line).
	htmlBlock1RE = regexp.MustCompile(`(?i)^ {0,3}<(script|pre|style|textarea)([ \t>]|$)`)
	htmlBlock6RE = regexp.MustCompile(`(?i)^ {0,3}</?[a-z][a-z0-9-]*([ \t>]|/>|$)`)
	html1EndRE   = regexp.MustCompile(`(?i)</(script|pre|style|textarea)>`)
)

// blockStates returns, for every line, the block construct that is open
// at its start ("" when none): a fenced code block, an HTML block or an
// HTML comment opened on an earlier line. A subsection that starts inside
// one is rendered as part of it, not as a heading.
func blockStates(lines []Line) []string {
	out := make([]string, len(lines))
	state, end, fence := "", "", ""
	for i, l := range lines {
		out[i] = state
		t := l.Text
		switch state {
		case "fenced code":
			if s := strings.TrimSpace(t); len(s) >= len(fence) && strings.Trim(s, fence[:1]) == "" {
				state = ""
			}
			continue
		case "HTML block":
			if end == "" {
				if strings.TrimSpace(t) == "" {
					state = ""
				}
			} else if (end == "html1" && html1EndRE.MatchString(t)) || (end != "html1" && strings.Contains(t, end)) {
				state = ""
			}
			continue
		}
		trimmed := strings.TrimLeft(t, " ")
		lead := len(t) - len(trimmed)
		skip := 0 // bytes of the opener, after which the end marker may close the block on its first line
		switch {
		case fenceOpenRE.MatchString(t):
			state, fence = "fenced code", fenceOpenRE.FindStringSubmatch(t)[1]
			continue
		case lead <= 3 && strings.HasPrefix(trimmed, "<!--"):
			// "<!-->" and "<!--->" are complete comments.
			state, end, skip = "HTML block", "-->", 2
		case htmlBlock1RE.MatchString(t):
			state, end = "HTML block", "html1"
		case lead <= 3 && strings.HasPrefix(trimmed, "<?"):
			state, end, skip = "HTML block", "?>", 2
		case lead <= 3 && strings.HasPrefix(trimmed, "<![CDATA["):
			state, end, skip = "HTML block", "]]>", 9
		case lead <= 3 && len(trimmed) > 2 && strings.HasPrefix(trimmed, "<!") && trimmed[2] >= 'A' && trimmed[2] <= 'Z':
			state, end, skip = "HTML block", ">", 2
		case htmlBlock6RE.MatchString(t):
			// Ends at the next blank line.
			state, end = "HTML block", ""
			continue
		default:
			continue
		}
		if end == "html1" {
			if html1EndRE.MatchString(t) {
				state = ""
			}
		} else if strings.Contains(trimmed[skip:], end) {
			state = ""
		}
	}
	return out
}

var (
	headingLineRE    = regexp.MustCompile(`^#{3,6}([ ]|$)`)
	itemLineRE       = regexp.MustCompile(`^( *)([-*]) (.*)$`)
	emptyItemRE      = regexp.MustCompile(`^( *)[-*]$`)
	breakLineRE      = regexp.MustCompile(`^ *(=+|-+|\*+|_+|(- *){3,}|(\* *){3,}|(_ *){3,}) *$`)
	orderedLineRE    = regexp.MustCompile(`^[0-9]{1,9}[.)]( |$)`)
	linkRefDefRE     = regexp.MustCompile(`^\[[^\]]*\]:`)
	inlineLinkRE     = regexp.MustCompile(`\[([^\[\]]*)\]\(([^()\s]*)\)`)
	rawHTMLRE        = regexp.MustCompile(`<[A-Za-z!?/]`)
	pullOrIssueRE    = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)/(pull|issues)/[1-9][0-9]{0,8}$`)
	profileRE        = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))$`)
	docsURLRE        = regexp.MustCompile(`^https://([a-z0-9.-]+)(/[A-Za-z0-9._~%/#?=&+:@-]*)?$`)
	forbiddenInlines = []struct{ token, reason string }{
		{"-->", "comment marker"}, {"![", "image"}, {"|", "table cell"}, {"~", "strikethrough"},
		{"[^", "footnote"}, {"][", "reference link"}, {"\t", "tab"},
	}
)

// grammar checks the lines of one subsection. The grammar is: blank lines;
// ATX headings of level 3-6 at column 0; list items "- " or "* " indented
// by a multiple of 2, at most MaxListDepth deep (an indented item needs an
// open item); continuation lines of an open item indented by at most five
// columns more than its marker (never code); plain paragraph lines at
// column 0. Inline, outside code spans: text, emphasis, entities,
// and links whose target is a pull request or issue of the repository, a
// contributor's profile ("[@login](https://github.com/login)") or a page
// on a documentation host. Anything else is a problem.
type grammar struct {
	rule     sectionRule
	item     int // marker indentation of the open item, -1 for none
	started  bool
	sawBlank bool
}

func (g *grammar) line(t string) string {
	if !g.started {
		g.started, g.item = true, -1
	}
	if strings.TrimSpace(t) == "" {
		g.sawBlank = true
		return ""
	}
	blank := g.sawBlank
	g.sawBlank = false
	if strings.Contains(t, "\t") {
		return "tab"
	}
	indent := len(t) - len(strings.TrimLeft(t, " "))
	rest := t[indent:]
	if indent == 0 && strings.HasPrefix(rest, "#") {
		if !headingLineRE.MatchString(rest) {
			return "heading form"
		}
		g.item = -1
		return g.inline(strings.TrimLeft(rest, "#"))
	}
	if strings.HasPrefix(rest, "#") {
		return "indented heading"
	}
	if breakLineRE.MatchString(rest) {
		return "setext underline or thematic break"
	}
	if emptyItemRE.MatchString(t) {
		return "empty list item"
	}
	if m := itemLineRE.FindStringSubmatch(t); m != nil {
		switch {
		case indent%2 != 0:
			return "list item indentation"
		case indent/2 >= MaxListDepth:
			return "list nesting too deep"
		case indent > 0 && g.item < 0:
			return "list item indentation"
		}
		g.item = indent
		return g.inline(m[3])
	}
	if p := blockStart(rest); p != "" {
		return p
	}
	if indent == 0 {
		if blank {
			g.item = -1
		}
		return g.inline(rest)
	}
	// A continuation line of an open item. Code inside an item needs at
	// least four columns past the item's content (marker + 2), so up to
	// marker + 5 is always text.
	if g.item < 0 || indent > g.item+5 {
		return "indented code or unaligned indentation"
	}
	return g.inline(rest)
}

// blockStart names a block construct outside the grammar that starts a
// line (after its indentation).
func blockStart(rest string) string {
	switch {
	case strings.HasPrefix(rest, "```") || strings.HasPrefix(rest, "~~~"):
		return "fenced code"
	case strings.HasPrefix(rest, ">"):
		return "block quote"
	case strings.HasPrefix(rest, "+ ") || rest == "+":
		return "list marker +"
	case orderedLineRE.MatchString(rest):
		return "ordered list"
	case breakLineRE.MatchString(rest):
		return "setext underline or thematic break"
	case linkRefDefRE.MatchString(rest):
		return "link reference definition"
	}
	return ""
}

// inline checks text outside code spans.
func (g *grammar) inline(s string) string {
	plain := codeSpans(s)
	if rawHTMLRE.MatchString(plain) {
		return "raw HTML"
	}
	for _, f := range forbiddenInlines {
		if strings.Contains(plain, f.token) {
			return f.reason
		}
	}
	var bad string
	rest := inlineLinkRE.ReplaceAllStringFunc(plain, func(link string) string {
		m := inlineLinkRE.FindStringSubmatch(link)
		if bad == "" && !g.allowedLink(m[1], m[2]) {
			bad = "link target " + logSafe(m[2])
		}
		return " "
	})
	if bad != "" {
		return bad
	}
	if strings.Contains(rest, "](") {
		return "link form"
	}
	return ""
}

func (g *grammar) allowedLink(text, dest string) bool {
	if m := pullOrIssueRE.FindStringSubmatch(dest); m != nil {
		return m[1] == g.rule.owner && m[2] == g.rule.name
	}
	if m := profileRE.FindStringSubmatch(dest); m != nil {
		return text == "@"+m[1]
	}
	if m := docsURLRE.FindStringSubmatch(dest); m != nil {
		return contains(g.rule.docsHosts, m[1])
	}
	return false
}

// codeSpans replaces the content of inline code spans (a run of backticks
// up to the next run of the same length) with spaces, keeping unmatched
// runs as text.
func codeSpans(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] != '`' {
			b.WriteByte(s[i])
			i++
			continue
		}
		n := 0
		for i+n < len(s) && s[i+n] == '`' {
			n++
		}
		closeAt := -1
		for j := i + n; j < len(s); {
			if s[j] != '`' {
				j++
				continue
			}
			m := 0
			for j+m < len(s) && s[j+m] == '`' {
				m++
			}
			if m == n {
				closeAt = j
				break
			}
			j += m
		}
		if closeAt < 0 {
			b.WriteString(s[i : i+n])
			i += n
			continue
		}
		b.WriteString(strings.Repeat(" ", closeAt+n-i))
		i = closeAt + n
	}
	return b.String()
}
