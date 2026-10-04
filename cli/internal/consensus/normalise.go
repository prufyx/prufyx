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

// NormaliserVersion identifies the section rules and stripping rules
// below. Any change to what Normalise outputs must change it.
const NormaliserVersion = "1"

// Bounds of a release notes file.
const (
	MaxSourceBytes = 2 << 20
	MaxLineBytes   = 64 << 10
)

// Line flags. A flag in hiddenFlags marks a line that held content a
// reader of the rendered page would not see, or would see differently;
// a citation of such a line is never verified.
const (
	FlagHTMLComment           = "html-comment"
	FlagUnterminatedComment   = "unterminated-comment"
	FlagHTMLTag               = "html-tag"
	FlagInvisibleCharacter    = "invisible-character"
	FlagControlCharacter      = "control-character"
	FlagCodeBlock             = "code-block"
	FlagUnterminatedCodeBlock = "unterminated-code-block"
	FlagLinkReference         = "link-reference"
	FlagImage                 = "image"
)

var hiddenFlags = map[string]bool{
	FlagHTMLComment: true, FlagUnterminatedComment: true, FlagHTMLTag: true,
	FlagInvisibleCharacter: true, FlagControlCharacter: true,
}

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

// Line is one normalised line of the selected section.
type Line struct {
	Text string
	// Original is the 1-based line number in the source file.
	Original int
	// Flags name what was removed from the line, sorted.
	Flags []string
}

// Hidden reports whether the line held hidden content.
func (l Line) Hidden() bool {
	for _, f := range l.Flags {
		if hiddenFlags[f] {
			return true
		}
	}
	return false
}

// Normalised is the selected, normalised section.
type Normalised struct {
	Section string
	Lines   []Line
	// Truncated is set when an unterminated comment or code block removed
	// everything after it.
	Truncated bool
}

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

// sectionHeading returns the heading line that opens the release's section
// and the prefix of a heading that ends it. Only Kubernetes has a rule:
// CHANGELOG/CHANGELOG-1.N.md, from "# v1.N.0" to the next "# v" heading.
func sectionHeading(spec SectionSpec) (string, string, error) {
	if spec.Repo != KubernetesRepo {
		return "", "", refuse("no-section-rule", "no section rule for repository %q", spec.Repo)
	}
	pm := k8sChangelogPath.FindStringSubmatch(spec.Path)
	vm := k8sReleaseTag.FindStringSubmatch(spec.Version)
	if pm == nil || vm == nil || pm[1] != vm[1] {
		return "", "", refuse("no-section-rule", "the section rule needs CHANGELOG/CHANGELOG-1.N.md and v1.N.0 with the same N")
	}
	return "# " + spec.Version, "# v", nil
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

type workLine struct {
	text  string
	orig  int
	flags map[string]bool
}

func (w *workLine) flag(f string) {
	if w.flags == nil {
		w.flags = map[string]bool{}
	}
	w.flags[f] = true
}

// Normalise selects the release's own section of a release notes file and
// normalises it. It is deterministic: equal input gives equal output.
func Normalise(src []byte, spec SectionSpec) (Normalised, error) {
	open, next, err := sectionHeading(spec)
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
	lines := make([]*workLine, len(raw))
	for i, text := range raw {
		if len(text) > MaxLineBytes {
			return Normalised{}, refuse("line-too-long", "line %d has %d bytes, at most %d", i+1, len(text), MaxLineBytes)
		}
		// CRLF becomes LF; any other carriage return is a control
		// character below.
		text = strings.TrimSuffix(text, "\r")
		lines[i] = &workLine{text: text, orig: i + 1}
		stripCharacters(lines[i])
	}
	truncated := stripComments(lines)

	start := -1
	for i, l := range lines {
		if strings.TrimRight(l.text, " \t") == open {
			if start >= 0 {
				return Normalised{}, refuse("section-ambiguous", "%q appears on lines %d and %d", open, lines[start].orig, l.orig)
			}
			start = i
		}
	}
	if start < 0 {
		return Normalised{}, refuse("no-section", "no %q heading", open)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i].text, next) {
			end = i
			break
		}
	}
	section := lines[start:end]
	if stripCodeBlocks(section) {
		truncated = true
	}
	for _, l := range section {
		stripMarkup(l)
		l.text = strings.TrimRight(l.text, " \t")
	}
	out := Normalised{Section: spec.Version, Truncated: truncated, Lines: make([]Line, len(section))}
	for i, l := range section {
		out.Lines[i] = Line{Text: l.text, Original: l.orig, Flags: sortedFlags(l.flags)}
	}
	return out, nil
}

func sortedFlags(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for f := range m {
		out = append(out, f)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// stripCharacters removes invisible and control characters from one line.
func stripCharacters(l *workLine) {
	var b strings.Builder
	for _, r := range l.text {
		switch {
		case invisible(r):
			l.flag(FlagInvisibleCharacter)
		case control(r):
			l.flag(FlagControlCharacter)
		default:
			b.WriteRune(r)
		}
	}
	l.text = b.String()
}

// stripComments removes HTML comments across lines. An unterminated comment
// removes everything after its start; the function then returns true.
func stripComments(lines []*workLine) bool {
	in := false
	startLine := -1
	for i, l := range lines {
		var b strings.Builder
		rest := l.text
		touched := false
		for {
			if in {
				touched = true
				j := strings.Index(rest, "-->")
				if j < 0 {
					rest = ""
					break
				}
				rest = rest[j+3:]
				in = false
				continue
			}
			j := strings.Index(rest, "<!--")
			if j < 0 {
				b.WriteString(rest)
				break
			}
			b.WriteString(rest[:j])
			rest = rest[j+4:]
			in, startLine, touched = true, i, true
		}
		if touched {
			l.flag(FlagHTMLComment)
		}
		l.text = b.String()
	}
	if in {
		lines[startLine].flag(FlagUnterminatedComment)
		return true
	}
	return false
}

var fenceRE = regexp.MustCompile("^[ \t]*(`{3,}|~{3,})")

// stripCodeBlocks empties fenced code blocks, fences included. An
// unterminated block empties everything after it and returns true.
func stripCodeBlocks(lines []*workLine) bool {
	var fence string
	start := -1
	for i, l := range lines {
		m := fenceRE.FindStringSubmatch(l.text)
		if fence == "" {
			if m == nil {
				continue
			}
			fence, start = m[1], i
		} else if t := strings.TrimSpace(l.text); len(t) >= len(fence) && strings.Trim(t, fence[:1]) == "" {
			fence = ""
		}
		l.text = ""
		l.flag(FlagCodeBlock)
	}
	if fence != "" {
		lines[start].flag(FlagUnterminatedCodeBlock)
		return true
	}
	return false
}

var (
	linkRefRE  = regexp.MustCompile(`^[ \t]*\[[^\]]+\]:`)
	imageRE    = regexp.MustCompile(`!\[[^\]]*\](\([^)]*\)|\[[^\]]*\])`)
	autolinkRE = regexp.MustCompile(`<(https?://[^\s<>]+)>`)
	tagRE      = regexp.MustCompile(`</?[A-Za-z][A-Za-z0-9-]*(\s[^<>]*)?/?>|<[!?][^<>]*>`)
	tagStartRE = regexp.MustCompile(`</?[A-Za-z!?]`)
)

// stripMarkup removes link reference definitions, images and raw HTML
// from one line. Text inside inline code spans is left as written.
func stripMarkup(l *workLine) {
	if linkRefRE.MatchString(l.text) {
		l.text = ""
		l.flag(FlagLinkReference)
		return
	}
	l.text = outsideCode(l.text, func(s string) string {
		if imageRE.MatchString(s) {
			s = imageRE.ReplaceAllString(s, "")
			l.flag(FlagImage)
		}
		s = autolinkRE.ReplaceAllString(s, "$1")
		if tagRE.MatchString(s) {
			s = tagRE.ReplaceAllString(s, "")
			l.flag(FlagHTMLTag)
		}
		if tagStartRE.MatchString(s) {
			// The start of a tag that continues on another line.
			l.flag(FlagHTMLTag)
		}
		return s
	})
}

// outsideCode applies fn to the parts of s outside inline code spans (a
// run of backticks up to the next run of the same length). An unmatched
// run is ordinary text.
func outsideCode(s string, fn func(string) string) string {
	var b strings.Builder
	plain := 0
	i := 0
	for i < len(s) {
		if s[i] != '`' {
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
			i += n
			continue
		}
		b.WriteString(fn(s[plain:i]))
		b.WriteString(s[i : closeAt+n])
		i = closeAt + n
		plain = i
	}
	b.WriteString(fn(s[plain:]))
	return b.String()
}
