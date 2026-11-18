// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"fmt"
	"path"
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Forms of a changelog source. FormFile, FormPerLineFile and FormPerVersionFile are read; the others return their
// typed reason without reading anything.
const (
	// FormFile: one changelog file with one section per version, present at
	// the tag.
	FormFile = "changelog-file"
	// FormGithubRelease: the body of a GitHub release (mutable, no commit).
	FormGithubRelease = "github-release"
	// FormPostTag: the entry lands after the tag is cut.
	FormPostTag = "post-tag"
	// FormDocsPage: an upgrade guide or docs page, not a per-tag changelog.
	FormDocsPage = "docs-page"
	// FormMonorepo: a shared changelog of several components.
	FormMonorepo = "monorepo"
	// FormPerLineFile: one changelog file per release line; Path is a
	// template holding "{line}" (major.minor of the tag version) once. The
	// file at the tag is then read as FormFile.
	FormPerLineFile = "changelog-per-line-file"
	// FormPerVersionFile: one file per version; Path is a template holding
	// "{version}" once. The whole file is the entry.
	FormPerVersionFile = "changelog-per-version-file"
)

// MaxFileBytes is the hard bound on a changelog file; a larger one is
// withheld, never truncated. MaxSectionLines bounds one entry.
const (
	MaxFileBytes    = 2 << 20
	MaxSectionLines = 5000
)

// Target is one reviewed row: where a component's changelog lives and how its
// version headings are written. It is reviewed data, never derived.
type Target struct {
	Component string
	Repo      extract.RepoRef
	Form      string
	// Path is the repository-relative file path at the tag commit.
	Path string
	// HeadingPattern matches the text of a final release heading. It must be
	// anchored (^...$) and have exactly one capture group, named "version",
	// which must read a canonical final version (major.minor.patch, no
	// leading zeros).
	HeadingPattern string
	// BoundaryPatterns match the text of headings that are release headings
	// but not final ones (unreleased, release candidate, in progress). They
	// may end a section; they never name an entry. Anchored, no captures
	// needed.
	BoundaryPatterns []string
	// InnerPatterns match headings at the same level as a release heading
	// that nevertheless belong to the entry above them (see InnerPattern).
	InnerPatterns []InnerPattern
	// MaxBytes bounds the file; zero means MaxFileBytes.
	MaxBytes int
	// MinLocatedNewest is the row's coverage bar for rows-check: how many of
	// the newest DefaultMinLocatedNewest final versions must be located. Zero
	// means DefaultMinLocatedNewest; otherwise 5 to 8 (the loader refuses
	// anything else). It never affects what is located, only whether a row
	// passes the check.
	MinLocatedNewest int
}

// InnerPattern is an anchored pattern for a same-level inner heading.
// FirstOnly keeps it to the first heading after the release heading.
type InnerPattern struct {
	Pattern   string
	FirstOnly bool
}

type compiled struct {
	heading  *regexp.Regexp
	boundary []*regexp.Regexp
	inner    []compiledInner
	max      int
}

type compiledInner struct {
	re        *regexp.Regexp
	firstOnly bool
}

// compileAnchored compiles a pattern that must be one anchored expression:
// the parsed form is a concatenation that begins with the start-of-text
// anchor and ends with the end-of-text anchor. A top-level alternation
// (^a|b$), an escaped dollar, or a multi-line anchor is refused.
func compileAnchored(p string) (*regexp.Regexp, error) {
	tree, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return nil, err
	}
	if tree.Op != syntax.OpConcat || len(tree.Sub) < 2 ||
		tree.Sub[0].Op != syntax.OpBeginText || tree.Sub[len(tree.Sub)-1].Op != syntax.OpEndText {
		return nil, fmt.Errorf("pattern %q must be one expression anchored with ^ and $", p)
	}
	return regexp.Compile(p)
}

func (t Target) compile() (compiled, error) {
	var c compiled
	if t.Component == "" || strings.ContainsRune(t.Component, 0) {
		return c, fmt.Errorf("component is empty")
	}
	if r, err := extract.ParseRepo(t.Repo.Key); err != nil || r.Key != t.Repo.Key {
		return c, fmt.Errorf("repo %q is not a canonical repository key", t.Repo.Key)
	}
	if t.Path == "" || path.IsAbs(t.Path) || path.Clean(t.Path) != t.Path || t.Path == ".." || strings.HasPrefix(t.Path, "../") {
		return c, fmt.Errorf("path %q must be a clean repository-relative path", t.Path)
	}
	if !markdownPath(t.Path) {
		return c, fmt.Errorf("path %q is not a markdown file", t.Path)
	}
	re, err := compileAnchored(t.HeadingPattern)
	if err != nil {
		return c, err
	}
	names := re.SubexpNames()
	// One group named version; a style that carries a link target may add the
	// groups slug and ref after it, checked by linkTargetMatches.
	linked := len(names) == 4 && names[2] == "slug" && (names[3] == "ref" || names[3] == "line")
	if len(names) < 2 || names[1] != "version" || (len(names) != 2 && !linked) {
		return c, fmt.Errorf("heading pattern needs one capture group named version (and, for a link target, slug and ref)")
	}
	c.heading = re
	for _, p := range t.BoundaryPatterns {
		b, err := compileAnchored(p)
		if err != nil {
			return c, err
		}
		c.boundary = append(c.boundary, b)
	}
	for _, in := range t.InnerPatterns {
		b, err := compileAnchored(in.Pattern)
		if err != nil {
			return c, err
		}
		c.inner = append(c.inner, compiledInner{re: b, firstOnly: in.FirstOnly})
	}
	if t.MinLocatedNewest != 0 && !minLocatedNewestValues[t.MinLocatedNewest] {
		return c, fmt.Errorf("MinLocatedNewest %d is not one of 5, 6, 7, 8", t.MinLocatedNewest)
	}
	c.max = MaxFileBytes
	if t.MaxBytes < 0 || t.MaxBytes > MaxFileBytes {
		return c, fmt.Errorf("MaxBytes %d outside 0..%d", t.MaxBytes, MaxFileBytes)
	}
	if t.MaxBytes > 0 {
		c.max = t.MaxBytes
	}
	return c, nil
}

var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

// finalVersion reads a canonical final version "x.y.z" (no prefix).
func finalVersion(s string) bool { return versionRE.MatchString(s) }

// tagVersion reads a release tag: an optional "v" and a canonical final
// version. Anything else (a release candidate, a build suffix, a prefix) is
// not a final tag.
func tagVersion(tag string) (string, bool) {
	v := strings.TrimPrefix(tag, "v")
	if !finalVersion(v) {
		return "", false
	}
	return v, true
}
