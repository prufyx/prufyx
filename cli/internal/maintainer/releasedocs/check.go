// SPDX-License-Identifier: AGPL-3.0-only

// Package releasedocs is the release-docs gate: it proves that the generated
// coverage text of a tree (README block, counts file, release notes, CHANGELOG
// entry) equals its regeneration and that the prose around it makes no number
// or coverage claim the generator did not write. It reads files and git
// objects only, writes nothing and fails closed: every problem is a finding,
// and one finding fails the check. There is no warning mode.
package releasedocs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// Modes. Unreleased is the CI mode: every committed notes file whose tag is
// not published yet. Release is the tag job of the release workflow. Cut is
// Release plus the site copy and the name list, run by the release manager
// before the tag is pushed.
const (
	ModeUnreleased = "unreleased"
	ModeRelease    = "release"
	ModeCut        = "cut"
)

// Exit codes, one per class of finding. 2 is a usage error.
const (
	CodeUsage     = 2
	CodeReadme    = 10
	CodeCounts    = 11
	CodeNotes     = 12
	CodeChangelog = 13
	CodeSite      = 14
	CodePrevious  = 15
	CodeProse     = 16
	CodeDeny      = 17
	CodeLabels    = 18
	CodeTag       = 19
	CodeFeatures  = 20
)

const (
	readmePath    = "README.md"
	changelogPath = "CHANGELOG.md"
	notesPrefix   = "cli/docs/release-notes-"
	notesSuffix   = ".md"
	maxFile       = 16 << 20
)

// CoverageKeywords select the lines of README.md and CHANGELOG.md (outside the
// generated markers) that are coverage sentences: any bare integer on such a
// line fails. A notes file is scanned on every line.
var CoverageKeywords = []string{"project", "pair", "version", "coverage", "covered", "decided", "catalog", "cncf", "attested", "attestation", "%"}

// CoverageLabels are the fixed labels of the generator's sentences. A "N
// projects covered" claim is accepted only with one of them in the sentence.
var CoverageLabels = []string{"catalogued", "rule-decided", "attestation-only", "gap"}

// DenyPhrases is the generic deny list, matched case-insensitively in the
// notes, the CHANGELOG sections under check and the README. The vendor and
// model names are not here: they come from the mandatory --deny-file.
var DenyPhrases = []string{"production-supported", "all cncf", "full coverage", "fully covered", "complete coverage"}

var (
	denySafe      = regexp.MustCompile(`\bSAFE\b`)
	denyUnlabeled = regexp.MustCompile(`(?i)\b(?:cover(?:s|ed|ing)?|support(?:s|ed|ing)?)\s+[0-9][0-9,]*\s+(?:cncf\s+)?projects\b|\b[0-9][0-9,]*\s+(?:cncf\s+)?projects\s+(?:are\s+)?(?:covered|supported)\b`)

	tagGrammar = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z-]*(\.[0-9A-Za-z-]+)*)?$`)
	headerLine = regexp.MustCompile("(?m)^Changes from `([^`]+)`(?: \\(([0-9a-f]{12})\\))? to `([^`]+)`(?: \\(([0-9a-f]{12})\\))?, computed by ")
	headingRe  = regexp.MustCompile(`(?m)^## \[([^\]]*)\]`)
	h1Re       = regexp.MustCompile(`(?m)^# (.*)$`)

	semverException = regexp.MustCompile(`v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?|v[0-9]+(?:\.[0-9]+)*`)
	dateException   = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2}`)
	listIndex       = regexp.MustCompile(`^\s*[0-9]+[.)]\s`)
	dottedVersion   = regexp.MustCompile(`[0-9]+\.[0-9]+([^%0-9]|$)`)
	exitCodes       = regexp.MustCompile("(?i)\\bexits?\\s+(?:codes?\\s+)?`?[0-9]{1,3}`?")
	units           = regexp.MustCompile(`(?i)[0-9]+\s*(?:KB|MB|GB|TB|KiB|MiB|GiB|TiB|vCPUs?|CPUs?|cores?)\b`)
	bareNumberSpan  = regexp.MustCompile("^`[0-9,.]*`$")
	codeSpan        = regexp.MustCompile("`[^`]*`")
	identSuffix     = regexp.MustCompile(`[A-Za-z]\.[0-9]+`)
)

// Regenerator regenerates what the tree commits. The default reads the tree's
// own data (the one implementation of `coverage readme`); tests replace it.
type Regenerator interface {
	// ReadmeStale lists the files whose generated coverage block differs from
	// its regeneration, or an error (missing, duplicated or misplaced markers).
	ReadmeStale(root string) ([]string, error)
	// Counts returns the bytes the counts file must have.
	Counts(root string) ([]byte, error)
}

type treeRegenerator struct{}

func (treeRegenerator) ReadmeStale(root string) ([]string, error) {
	return knowledgegate.RegenerateBlocks(root, true, readmePath)
}
func (treeRegenerator) Counts(root string) ([]byte, error) { return knowledgegate.ReadmeCounts(root) }

// Options of one check.
type Options struct {
	Root       string
	Mode       string
	Tag        string // release and cut
	Previous   string // release and cut
	SiteCounts string // cut (mandatory); release and unreleased (optional)
	DenyFile   string // release and cut (mandatory); unreleased (optional)
	Regenerate Regenerator
}

// Finding is one failed check.
type Finding struct {
	Code int
	Msg  string
}

// Result of a check.
type Result struct {
	Findings []Finding
	// Notices are facts the caller must print, such as a skipped name list.
	Notices []string
}

// ExitCode is 0 without findings, otherwise the code of the lowest class.
func (r Result) ExitCode() int {
	if len(r.Findings) == 0 {
		return 0
	}
	c := r.Findings[0].Code
	for _, f := range r.Findings {
		if f.Code < c {
			c = f.Code
		}
	}
	return c
}

// UsageError is an invalid option set.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

type checker struct {
	o        Options
	regen    Regenerator
	root     string
	res      Result
	deny     []string
	toRev    string          // revision of the tree under check ("" = the checked-out files)
	bound    bool            // release and cut: the checkout is the tagged commit
	owned    map[string]bool // rendered lines of the works features
	features *releasenotes.Features
}

func (c *checker) fail(code int, format string, args ...any) {
	c.res.Findings = append(c.res.Findings, Finding{Code: code, Msg: fmt.Sprintf(format, args...)})
}

// Check runs the gate. The error is a *UsageError for an invalid option set;
// every other problem is a finding.
func Check(o Options) (Result, error) {
	switch o.Mode {
	case ModeUnreleased:
		if o.Tag != "" || o.Previous != "" {
			return Result{}, &UsageError{"--tag and --previous belong to the release and cut modes"}
		}
	case ModeRelease, ModeCut:
		if o.Tag == "" || o.Previous == "" {
			return Result{}, &UsageError{"--tag and --previous are required in " + o.Mode + " mode"}
		}
		if o.DenyFile == "" {
			return Result{}, &UsageError{"--deny-file is required in " + o.Mode + " mode"}
		}
		if o.Mode == ModeCut && o.SiteCounts == "" {
			return Result{}, &UsageError{"--site-counts is required in cut mode"}
		}
	default:
		return Result{}, &UsageError{"--mode must be unreleased, release or cut"}
	}
	if o.Root == "" {
		return Result{}, &UsageError{"--root is required"}
	}
	root, err := filepath.Abs(o.Root)
	if err != nil {
		return Result{}, &UsageError{"--root is unusable"}
	}
	c := &checker{o: o, regen: o.Regenerate, root: root}
	if c.regen == nil {
		c.regen = treeRegenerator{}
	}
	if o.DenyFile != "" {
		words, err := loadDeny(o.DenyFile)
		if err != nil {
			return Result{}, &UsageError{"--deny-file: " + err.Error()}
		}
		c.deny = words
	} else {
		c.res.Notices = append(c.res.Notices, "release-docs: the vendor and model name list was NOT checked (no --deny-file); the release cut always checks it")
	}
	c.run()
	sort.SliceStable(c.res.Findings, func(i, j int) bool { return c.res.Findings[i].Code < c.res.Findings[j].Code })
	return c.res, nil
}

func loadDeny(path string) ([]string, error) {
	raw, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	var words []string
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		words = append(words, strings.ToLower(l))
	}
	if len(words) == 0 {
		return nil, errors.New("the file has no entry")
	}
	return words, nil
}

func readBounded(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > maxFile {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return os.ReadFile(path)
}

func (c *checker) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", c.root}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// tagCommit resolves a published tag to its full commit; ok is false when
// there is no such tag, err when git itself fails.
func (c *checker) tagCommit(tag string) (sha string, ok bool, err error) {
	cmd := exec.Command("git", "-C", c.root, "rev-parse", "-q", "--verify", "--end-of-options", "refs/tags/"+tag+"^{commit}")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(out.String()), true, nil
}

func (c *checker) readRoot(rel string) ([]byte, error) {
	return readBounded(filepath.Join(c.root, filepath.FromSlash(rel)))
}

func (c *checker) run() {
	c.checkGenerated()
	if c.o.SiteCounts != "" {
		c.checkSite()
	}
	var tags []string
	if c.o.Mode == ModeUnreleased {
		tags = c.unpublishedNotes()
	} else {
		tags = []string{c.o.Tag}
		c.checkTagBinding()
	}
	c.features = c.checkFeatures()
	c.owned = map[string]bool{}
	if c.features != nil {
		for _, x := range c.features.Features {
			if x.State == releasenotes.StateWorks {
				c.owned[releasenotes.WorksLine(x)] = true
			}
		}
	}
	changelog, err := c.readRoot(changelogPath)
	if err != nil {
		c.fail(CodeChangelog, "CHANGELOG.md: %v", err)
	} else {
		c.taggedHistory(string(changelog))
	}
	sections := map[string]bool{"Unreleased": true}
	var scanned []scanText
	for _, tag := range tags {
		if c.o.Mode != ModeUnreleased && !c.bound {
			break // the tag binding failed and is reported; nothing is read from an unbound tree
		}
		c.checkRelease(tag, string(changelog), &scanned)
		sections[strings.TrimPrefix(tag, "v")] = true
	}
	if err == nil {
		scanned = append(scanned, c.changelogScans(string(changelog), sections)...)
	}
	readme, rerr := c.readRoot(readmePath)
	if rerr != nil {
		c.fail(CodeReadme, "README.md: %v", rerr)
	} else {
		scanned = append(scanned, readmeScan(string(readme)))
	}
	for _, s := range scanned {
		c.scan(s)
	}
}

// checkGenerated regenerates the README block and the counts file.
func (c *checker) checkGenerated() {
	stale, err := c.regen.ReadmeStale(c.root)
	if err != nil {
		c.fail(CodeReadme, "README coverage block cannot be checked: %v", err)
	} else if len(stale) > 0 {
		c.fail(CodeReadme, "the README coverage block differs from its regeneration (%s)", strings.Join(stale, ", "))
	}
	want, err := c.regen.Counts(c.root)
	if err != nil {
		c.fail(CodeCounts, "the counts file cannot be regenerated: %v", err)
		return
	}
	got, err := c.readRoot(releasenotes.CountsPath)
	if err != nil {
		c.fail(CodeCounts, "%s: %v", releasenotes.CountsPath, err)
		return
	}
	if !bytes.Equal(got, want) {
		c.fail(CodeCounts, "%s differs from its regeneration", releasenotes.CountsPath)
	}
	readme, rerr := c.readRoot(readmePath)
	if rerr != nil {
		return // reported by the README scan
	}
	if _, err := releasenotes.LoadCounts(got, readme); err != nil {
		c.fail(CodeCounts, "%s: %v", releasenotes.CountsPath, err)
	}
}

func (c *checker) checkSite() {
	got, err := c.readRoot(releasenotes.CountsPath)
	if err != nil {
		return // reported by checkGenerated
	}
	site, err := readBounded(c.o.SiteCounts)
	if err != nil {
		c.fail(CodeSite, "site counts: %v", err)
		return
	}
	if !bytes.Equal(site, got) {
		c.fail(CodeSite, "the site counts file differs byte for byte from %s", releasenotes.CountsPath)
	}
}

// checkTagBinding requires the checked-out commit to be the tagged commit and
// the checked-out files to be unmodified.
func (c *checker) checkTagBinding() {
	if !tagGrammar.MatchString(c.o.Tag) {
		c.fail(CodeTag, "%q is not a v-prefixed semantic version", c.o.Tag)
		return
	}
	tagSha, ok, err := c.tagCommit(c.o.Tag)
	if err != nil || !ok {
		c.fail(CodeTag, "the tag %s does not resolve to a commit: %v", c.o.Tag, err)
		return
	}
	head, err := c.git("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || head != tagSha {
		c.fail(CodeTag, "the checked-out commit is not the commit of tag %s", c.o.Tag)
		return
	}
	dirty, err := c.git("status", "--porcelain", "--untracked-files=no")
	if err != nil || dirty != "" {
		c.fail(CodeTag, "the checkout has modified tracked files; the gate reads the tagged tree only")
		return
	}
	c.toRev = "refs/tags/" + c.o.Tag
	c.bound = true
}

// unpublishedNotes lists the tags of the committed notes files that have no
// git tag yet. An unreadable tag state is a finding, never "published".
func (c *checker) unpublishedNotes() []string {
	entries, err := os.ReadDir(filepath.Join(c.root, filepath.FromSlash(strings.TrimSuffix(notesPrefix, "release-notes-"))))
	if err != nil {
		c.fail(CodeNotes, "cannot list the release notes: %v", err)
		return nil
	}
	var tags []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, "release-notes-") || !strings.HasSuffix(n, notesSuffix) {
			continue
		}
		tag := strings.TrimSuffix(strings.TrimPrefix(n, "release-notes-"), notesSuffix)
		if !tagGrammar.MatchString(tag) {
			c.fail(CodeLabels, "%s: the file name does not carry a v-prefixed semantic version", n)
			continue
		}
		_, ok, err := c.tagCommit(tag)
		if err != nil {
			c.fail(CodeTag, "cannot read the tag state of %s: %v", tag, err)
			continue
		}
		if !ok {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	return tags
}

// scanText is one text to scan: its name, the lines outside the generated
// blocks (fenced code excluded for README and CHANGELOG) and whether every
// line (not only the coverage keyword lines) is scanned for integers, with the
// strict exceptions only; whole is the text for the deny list.
type scanText struct {
	name      string
	whole     string
	outside   []string
	everyLine bool // notes: every line, strict exceptions only
}

func (c *checker) checkRelease(tag, changelog string, scanned *[]scanText) {
	name := notesPrefix + tag + notesSuffix
	raw, err := c.readRoot(name)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		c.fail(CodeNotes, "%s is missing or empty", name)
		return
	}
	doc := string(raw)
	if !tagGrammar.MatchString(tag) {
		c.fail(CodeLabels, "%q is not a v-prefixed semantic version", tag)
		return
	}
	// Labels.
	if m := h1Re.FindStringSubmatch(doc); m == nil || !containsWord(m[1], tag) {
		c.fail(CodeLabels, "%s: the first heading does not name %s", name, tag)
	}
	if c.o.Mode != ModeUnreleased {
		if rd, err := c.readRoot(readmePath); err == nil && !statusNames(string(rd), tag) {
			c.fail(CodeLabels, "README.md: the status line does not name %s", tag)
		}
	}
	version := strings.TrimPrefix(tag, "v")
	section, sectionOK := changelogSection(changelog, version)
	entry := version
	switch {
	case !sectionOK && strings.Count(changelog, "## ["+version+"]") > 1:
		c.fail(CodeChangelog, "CHANGELOG.md needs exactly one [%s] heading", version)
	case !sectionOK && c.o.Mode == ModeUnreleased:
		// Before the cut the entry is generated into [Unreleased]; the cut
		// renames that heading. Release and cut modes need the real heading.
		section, sectionOK = changelogSection(changelog, "Unreleased")
		entry = "Unreleased"
		if !sectionOK {
			c.fail(CodeChangelog, "CHANGELOG.md needs exactly one [%s] or [Unreleased] heading", version)
		}
	case !sectionOK:
		c.fail(CodeChangelog, "CHANGELOG.md needs exactly one [%s] heading", version)
	}
	// Header: previous and commit labels.
	m := headerLine.FindStringSubmatch(doc)
	if m == nil {
		c.fail(CodeNotes, "%s: the generated block has no \"Changes from\" line (markers missing or the block was reworded)", name)
		// The markers are still checked below through ReplaceBlock.
		if _, err := releasenotes.ReplaceBlock(doc, ""); err != nil {
			c.fail(CodeNotes, "%s: %v", name, err)
		}
		return
	}
	prev, toLabel, toCommit := m[1], m[3], m[4]
	if toLabel != tag {
		c.fail(CodeLabels, "%s: the block describes %s, not %s", name, toLabel, tag)
		return
	}
	if c.o.Mode != ModeUnreleased {
		if prev != c.o.Previous {
			c.fail(CodePrevious, "%s: the block compares against %s, not %s", name, prev, c.o.Previous)
			return
		}
	}
	r3, r4, ok := c.render(name, tag, prev, toCommit)
	if !ok {
		return
	}
	if updated, err := releasenotes.ReplaceBlock(doc, r3); err != nil {
		c.fail(CodeNotes, "%s: %v", name, err)
	} else if updated != doc {
		c.fail(CodeNotes, "%s: the generated block differs from its regeneration", name)
	}
	if sectionOK {
		if updated, err := releasenotes.ReplaceBlock(section, r4); err != nil {
			c.fail(CodeChangelog, "CHANGELOG.md [%s]: %v", entry, err)
		} else if updated != section {
			c.fail(CodeChangelog, "CHANGELOG.md [%s]: the generated block differs from its regeneration", entry)
		}
	}
	*scanned = append(*scanned, notesScan(name, doc))
}

// render regenerates the notes block at level 3 and 4.
func (c *checker) render(name, tag, prev, toCommit string) (r3, r4 string, ok bool) {
	if !tagGrammar.MatchString(prev) {
		c.fail(CodePrevious, "%s: %q is not a v-prefixed semantic version", name, prev)
		return
	}
	if cmp, err := semverCompare(prev, tag); err != nil || cmp >= 0 {
		c.fail(CodePrevious, "%s: the previous release %s is not strictly lower than %s", name, prev, tag)
		return
	}
	prevSha, found, err := c.tagCommit(prev)
	if err != nil || !found {
		c.fail(CodePrevious, "%s: the previous tag %s does not resolve to a commit: %v", name, prev, err)
		return
	}
	var toTree releasenotes.Tree
	toCommitFull := ""
	if c.o.Mode == ModeUnreleased {
		toTree = releasenotes.DirTree{Root: c.root}
		head, err := c.git("rev-parse", "--verify", "HEAD^{commit}")
		if err != nil {
			c.fail(CodeTag, "%s: cannot resolve HEAD: %v", name, err)
			return
		}
		toCommitFull = head
	} else {
		toTree = releasenotes.GitTree{Repo: c.root, Rev: c.toRev}
		toCommitFull, _, _ = c.tagCommit(tag)
	}
	if isAnc, err := releasenotes.IsAncestor(c.root, prevSha, toCommitFull); err != nil || !isAnc {
		c.fail(CodePrevious, "%s: the previous tag %s is not an ancestor of the tree under check", name, prev)
		return
	}
	if toCommit != "" {
		if _, err := releasenotes.Commit(c.root, toCommit); err != nil {
			c.fail(CodeLabels, "%s: the commit %s named in the block does not exist", name, toCommit)
			return
		}
		if isAnc, err := releasenotes.IsAncestor(c.root, toCommit, toCommitFull); err != nil || !isAnc {
			c.fail(CodeLabels, "%s: the commit %s named in the block is not in the history of the tree under check", name, toCommit)
			return
		}
	}
	features, err := releasenotes.ReadFeatures(toTree)
	if err != nil {
		c.fail(CodeFeatures, "%s: the notes need the feature file of the tree under check: %v", name, err)
		return
	}
	fromTree := releasenotes.GitTree{Repo: c.root, Rev: "refs/tags/" + prev}
	// The previous counts pin is the sha256 of the previous tag's own
	// committed counts file (or the code constant for the bootstrap tag);
	// it is never read from the notes under test.
	wantSha := ""
	if prev != releasenotes.BootstrapTag {
		data, err := fromTree.Read(releasenotes.CountsPath)
		if err != nil {
			c.fail(CodePrevious, "%s: the counts file of %s: %v", name, prev, err)
			return
		}
		wantSha = releasenotes.Sum256Hex(data)
	}
	prevCounts, err := releasenotes.ReadPreviousCounts(fromTree, toTree, prev, wantSha)
	if err != nil {
		c.fail(CodePrevious, "%s: %v", name, err)
		return
	}
	curCounts, err := releasenotes.ReadCounts(toTree, releasenotes.CountsPath)
	if err != nil {
		c.fail(CodeCounts, "%s: %v", name, err)
		return
	}
	a, err := releasenotes.ReadSnapshot(fromTree)
	if err != nil {
		c.fail(CodePrevious, "%s: cannot read the tree of %s: %v", name, prev, err)
		return
	}
	b, err := releasenotes.ReadSnapshot(toTree)
	if err != nil {
		c.fail(CodeNotes, "%s: cannot read the tree under check: %v", name, err)
		return
	}
	fromShort, err := releasenotes.Commit(c.root, "refs/tags/"+prev)
	if err != nil {
		c.fail(CodePrevious, "%s: %v", name, err)
		return
	}
	opts := releasenotes.Options{
		FromLabel: prev, ToLabel: tag,
		FromCommit: fromShort, ToCommit: toCommit,
		OmitMergedPRs: true,
		Prev:          prevCounts, Cur: curCounts,
		Features: features,
		Previous: releasenotes.PreviousPin{Tag: prev, Commit: fromShort, CountsSha256: prevCounts.Sha256},
	}
	opts.Level = 3
	r3, err = releasenotes.Render(a, b, opts)
	if err != nil {
		c.fail(CodeNotes, "%s: %v", name, err)
		return
	}
	opts.Level = 4
	r4, err = releasenotes.Render(a, b, opts)
	if err != nil {
		c.fail(CodeChangelog, "%s: %v", name, err)
		return
	}
	return r3, r4, true
}

// changelogSection returns the text of the single "## [version]" entry.
func changelogSection(doc, version string) (string, bool) {
	locs := headingRe.FindAllStringSubmatchIndex(doc, -1)
	found := -1
	for i, l := range locs {
		if doc[l[2]:l[3]] == version {
			if found >= 0 {
				return "", false
			}
			found = i
		}
	}
	if found < 0 {
		return "", false
	}
	end := len(doc)
	if found+1 < len(locs) {
		end = locs[found+1][0]
	}
	return doc[locs[found][0]:end], true
}

func (c *checker) changelogScans(doc string, want map[string]bool) []scanText {
	var out []scanText
	locs := headingRe.FindAllStringSubmatchIndex(doc, -1)
	for i, l := range locs {
		if !want[doc[l[2]:l[3]]] {
			continue
		}
		end := len(doc)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, outsideScan("CHANGELOG.md ["+doc[l[2]:l[3]]+"]", doc[l[0]:end], false, [2]string{releasenotes.MarkerBegin, releasenotes.MarkerEnd}))
	}
	return out
}

// claims is the text the form rules read: the whole text of a notes file or
// CHANGELOG entry (the generated lists included), the hand-written text of the
// README (its generated block states the form definitions).
func (s scanText) claims() string {
	if s.name == readmePath {
		return strings.Join(s.outside, "\n")
	}
	return s.whole
}

func notesScan(name, doc string) scanText {
	return outsideScan(name, doc, true, [2]string{releasenotes.MarkerBegin, releasenotes.MarkerEnd})
}

func readmeScan(doc string) scanText {
	// The regions RegenerateBlocks renders (and checks) in README.md.
	return outsideScan("README.md", doc, false,
		[2]string{coveragereport.READMEBegin, coveragereport.READMEEnd},
		[2]string{coveragereport.READMEBasisBegin, coveragereport.READMEBasisEnd},
		[2]string{coveragereport.READMECRDBegin, coveragereport.READMECRDEnd},
		[2]string{coveragereport.READMEValidityBegin, coveragereport.READMEValidityEnd})
}

// outsideScan splits doc into the lines outside the generated regions, given
// as begin/end marker line pairs. Text inside a region is generated and
// compared byte for byte elsewhere. Outside a notes file (every) fenced code
// blocks are examples, not prose, and are left out of the integer scan.
func outsideScan(name, doc string, every bool, pairs ...[2]string) scanText {
	s := scanText{name: name, whole: doc, everyLine: every}
	end := ""
	fenced := false
	for _, l := range strings.Split(doc, "\n") {
		t := strings.TrimRight(l, " \r")
		if end != "" {
			if t == end {
				end = ""
			}
			continue
		}
		opened := false
		for _, p := range pairs {
			if t == p[0] {
				end, opened = p[1], true
			}
		}
		if opened {
			continue
		}
		if !every && strings.HasPrefix(strings.TrimLeft(t, " "), "```") {
			fenced = !fenced
			continue
		}
		if !fenced {
			s.outside = append(s.outside, l)
		}
	}
	return s
}

// scan applies the integer rule (R1) and the deny list.
func (c *checker) scan(s scanText) {
	for i, l := range s.outside {
		if !s.everyLine && !hasKeyword(l) {
			continue
		}
		if n := bareIntegers(l, !s.everyLine); len(n) > 0 {
			c.fail(CodeProse, "%s: a number outside the generated block (%s) in: %s", s.name, strings.Join(n, ", "), clip(l, i))
		}
	}
	// The deny list covers the generated text as well.
	lower := strings.ToLower(s.whole)
	for _, p := range DenyPhrases {
		if strings.Contains(lower, p) {
			c.fail(CodeDeny, "%s: the phrase %q is not allowed", s.name, p)
		}
	}
	if denySafe.MatchString(s.whole) {
		c.fail(CodeDeny, "%s: \"SAFE\" as a verdict claim is not allowed", s.name)
	}
	for _, sentence := range sentences(s.whole) {
		if denyUnlabeled.MatchString(sentence) && !hasLabel(sentence) {
			c.fail(CodeDeny, "%s: a project count without its coverage label: %s", s.name, clip(sentence, 0))
		}
	}
	c.featurePhrases(s.name, s.whole)
	c.formClaims(s.name, s.claims())
	if s.everyLine {
		c.proseOutside(s.name, s.outside)
	}
	for _, w := range c.deny {
		if containsName(lower, w) {
			c.fail(CodeDeny, "%s: a name on the deny list appears", s.name)
		}
	}
}

func clip(s string, _ int) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func hasKeyword(l string) bool {
	l = strings.ToLower(l)
	for _, k := range CoverageKeywords {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func hasLabel(sentence string) bool {
	l := strings.ToLower(sentence)
	for _, k := range CoverageLabels {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

var sentenceSplit = regexp.MustCompile(`[.!?]\s+|\n`)

func sentences(text string) []string { return sentenceSplit.Split(text, -1) }

// containsName matches a deny-list entry as a whole word, case-insensitively
// (lower is already lower case, the entry too).
func containsName(lower, word string) bool {
	return regexp.MustCompile(`(?:^|[^a-z0-9])` + regexp.QuoteMeta(word) + `(?:[^a-z0-9]|$)`).MatchString(lower)
}

// bareIntegers returns every integer of a line that is not an allowed token.
// Always allowed: a semantic version, an ISO date, a v-prefixed version, a
// list index, the digits of a pre-release label (beta.0) and digits inside a
// word (sha256, k8s). With loose (README and CHANGELOG lines, which carry
// examples and exit codes) also: a dotted version such as 1.30 not followed by
// %, an exit code (exit 10), a number with a size unit (128 GB) and the
// content of an inline code span that is not a bare number.
func bareIntegers(line string, loose bool) []string {
	line = listIndex.ReplaceAllString(line, " ")
	if loose {
		line = codeSpan.ReplaceAllStringFunc(line, func(span string) string {
			if bareNumberSpan.MatchString(span) {
				return span
			}
			return " "
		})
		line = exitCodes.ReplaceAllString(line, " ")
		line = units.ReplaceAllString(line, " ")
	}
	line = dateException.ReplaceAllString(line, " ")
	line = semverException.ReplaceAllString(line, " ")
	if loose {
		line = dottedVersion.ReplaceAllString(line, " $1")
	}
	line = identSuffix.ReplaceAllStringFunc(line, func(m string) string { return m[:1] + " " })
	var out []string
	b := []byte(line)
	for i := 0; i < len(b); {
		if b[i] < '0' || b[i] > '9' {
			i++
			continue
		}
		j := i
		for j < len(b) && b[j] >= '0' && b[j] <= '9' {
			j++
		}
		if i == 0 || !isWordByte(b[i-1]) {
			out = append(out, string(b[i:j]))
		}
		i = j
	}
	return out
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func containsWord(text, word string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], word)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(word)
		before := start == 0 || !tagByte(text[start-1])
		after := end == len(text) || !tagByte(text[end])
		if before && after {
			return true
		}
		i = start + 1
	}
}

func tagByte(c byte) bool {
	return c == '.' || c == '-' || c == '+' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// statusNames reports whether the README status line names the tag.
func statusNames(readme, tag string) bool {
	for _, l := range strings.Split(readme, "\n") {
		if strings.HasPrefix(l, "> **Status:") {
			return containsWord(l, tag)
		}
	}
	return false
}

// semverCompare compares two v-prefixed semantic versions (-1, 0, 1).
func semverCompare(a, b string) (int, error) {
	pa, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if pa.n[i] != pb.n[i] {
			if pa.n[i] < pb.n[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	switch {
	case len(pa.pre) == 0 && len(pb.pre) == 0:
		return 0, nil
	case len(pa.pre) == 0:
		return 1, nil
	case len(pb.pre) == 0:
		return -1, nil
	}
	for i := 0; i < len(pa.pre) && i < len(pb.pre); i++ {
		x, y := pa.pre[i], pb.pre[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1, nil
				}
				return 1, nil
			}
		case xerr == nil:
			return -1, nil
		case yerr == nil:
			return 1, nil
		case x != y:
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	switch {
	case len(pa.pre) < len(pb.pre):
		return -1, nil
	case len(pa.pre) > len(pb.pre):
		return 1, nil
	}
	return 0, nil
}

type semver struct {
	n   [3]int
	pre []string
}

func parseSemver(v string) (semver, error) {
	m := tagGrammar.FindStringSubmatch(v)
	if m == nil {
		return semver{}, fmt.Errorf("%q is not a semantic version", v)
	}
	var s semver
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return semver{}, err
		}
		s.n[i] = n
	}
	if m[4] != "" {
		s.pre = strings.Split(m[4][1:], ".")
	}
	return s, nil
}
