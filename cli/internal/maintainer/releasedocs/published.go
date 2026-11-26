// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// CodeBase is the exit code of an unusable base revision: the published text
// cannot be compared.
const CodeBase = 20

// Published is the pull request guard for published release text. Check skips
// every version that has a tag, so this compares, for each version tag of the
// repository, the generated block of its notes file and its CHANGELOG entry in
// the commit under check (HEAD) with the same text in the base revision. The
// tag's own tree is not the reference: published text may already differ from
// it on the base branch. Both sides are read from git objects; nothing is
// written. It fails closed: tags, base or a file that cannot be read are
// findings. The error is a *UsageError for a missing option.
func Published(root, base string) (Result, error) {
	if root == "" {
		return Result{}, &UsageError{"--root is required"}
	}
	if base == "" {
		return Result{}, &UsageError{"--base is required"}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Result{}, &UsageError{"--root is unusable"}
	}
	c := &checker{root: abs}
	c.published(base)
	return c.res, nil
}

func (c *checker) published(base string) {
	head, versions, ok := c.publishedVersions()
	if !ok {
		return
	}
	out, err := c.objects("rev-parse", "--verify", "--end-of-options", base+"^{commit}")
	if err != nil {
		c.fail(CodeBase, "the base revision %q does not resolve to a commit: %v", base, err)
		return
	}
	baseSha := strings.TrimSpace(string(out))
	if baseSha == head {
		c.fail(CodeBase, "the base revision %q is the commit under check; a commit compared with itself proves nothing", base)
		return
	}
	oldLog, oldFound, err := c.committed(baseSha, changelogPath)
	if err != nil || !oldFound {
		c.fail(CodeBase, "CHANGELOG.md of the base cannot be read (present: %t): %v", oldFound, err)
		return
	}
	newLog, newFound, err := c.committed(head, changelogPath)
	if err != nil || !newFound {
		c.fail(CodeChangelog, "CHANGELOG.md of the commit under check cannot be read (present: %t): %v", newFound, err)
		return
	}
	for _, tag := range versions {
		version := strings.TrimPrefix(tag, "v")
		if !slices.Equal(changelogEntries(string(oldLog), version), changelogEntries(string(newLog), version)) {
			c.fail(CodeChangelog, "CHANGELOG.md [%s]: the entry of the published release %s differs from the base", version, tag)
		}
		c.publishedNotes(tag, baseSha, head)
	}
}

// publishedVersions returns the commit under check and every version tag. A
// repository whose tags may be incomplete, or that shows none, is refused.
func (c *checker) publishedVersions() (head string, tags []string, ok bool) {
	out, err := c.objects("rev-parse", "--show-prefix")
	if err != nil || strings.TrimSpace(string(out)) != "" {
		c.fail(CodeTag, "--root is not the top level of a git work tree: %v", err)
		return "", nil, false
	}
	out, err = c.objects("rev-parse", "--is-shallow-repository")
	if err != nil || strings.TrimSpace(string(out)) != "false" {
		c.fail(CodeTag, "the tags cannot be trusted: the repository is shallow or its state is unreadable: %v", err)
		return "", nil, false
	}
	out, err = c.objects("for-each-ref", "--format=%(refname)", "refs/tags")
	if err != nil {
		c.fail(CodeTag, "cannot read the tags: %v", err)
		return "", nil, false
	}
	for _, ref := range strings.Split(string(out), "\n") {
		if tag := strings.TrimPrefix(ref, "refs/tags/"); tagGrammar.MatchString(tag) {
			tags = append(tags, tag)
		}
	}
	if len(tags) == 0 {
		c.fail(CodeTag, "no version tag is visible; fetch the tags before this check")
		return "", nil, false
	}
	out, err = c.objects("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		c.fail(CodeTag, "cannot resolve HEAD: %v", err)
		return "", nil, false
	}
	return strings.TrimSpace(string(out)), tags, true
}

// publishedNotes compares the notes file of one published version. An
// unchanged file passes. A changed file passes only when both sides carry
// exactly one generated block and the two blocks are equal.
func (c *checker) publishedNotes(tag, baseSha, head string) {
	name := notesPrefix + tag + notesSuffix
	old, oldFound, err := c.committed(baseSha, name)
	if err != nil {
		c.fail(CodeBase, "%s of the base cannot be read: %v", name, err)
		return
	}
	cur, curFound, err := c.committed(head, name)
	if err != nil {
		c.fail(CodeNotes, "%s of the commit under check cannot be read: %v", name, err)
		return
	}
	if oldFound == curFound && bytes.Equal(old, cur) {
		return
	}
	if !oldFound || !curFound {
		c.fail(CodeNotes, "%s: the notes of the published release %s may not be added, removed or renamed (in base: %t, now: %t)", name, tag, oldFound, curFound)
		return
	}
	a, aok := generatedBlock(string(old))
	b, bok := generatedBlock(string(cur))
	if !aok || !bok || a != b {
		c.fail(CodeNotes, "%s: the generated block of the published release %s differs from the base, or cannot be compared", name, tag)
	}
}

// generatedBlock returns the lines from the begin marker to the end marker; ok
// is false unless ReplaceBlock accepts the markers of doc.
func generatedBlock(doc string) (string, bool) {
	if _, err := releasenotes.ReplaceBlock(doc, ""); err != nil {
		return "", false
	}
	lines := strings.Split(doc, "\n")
	at := func(marker string) int {
		return slices.IndexFunc(lines, func(l string) bool { return strings.TrimRight(l, " \r") == marker })
	}
	return strings.Join(lines[at(releasenotes.MarkerBegin):at(releasenotes.MarkerEnd)+1], "\n"), true
}

// changelogEntries returns every "## [version]" entry, so that a removed or
// repeated heading differs as much as a rewritten entry.
func changelogEntries(doc, version string) []string {
	var out []string
	locs := headingRe.FindAllStringSubmatchIndex(doc, -1)
	for i, l := range locs {
		if doc[l[2]:l[3]] != version {
			continue
		}
		end := len(doc)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, doc[l[0]:end])
	}
	return out
}

// objects runs git on c.root and returns its raw output. Variables that would
// point git at another repository, and replace refs, are not honoured.
func (c *checker) objects(args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", c.root}, args...)...)
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE":
			return true
		}
		return false
	}), "GIT_NO_REPLACE_OBJECTS=1")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// committed reads one file of a commit. found is false only when the commit's
// tree has no such path; a link, a directory, an oversized or an unreadable
// object is an error.
func (c *checker) committed(commit, rel string) (data []byte, found bool, err error) {
	entry, err := c.objects("ls-tree", "-z", "-l", "--full-tree", commit, "--", rel)
	if err != nil {
		return nil, false, err
	}
	if len(entry) == 0 {
		return nil, false, nil
	}
	meta, path, ok := strings.Cut(strings.TrimSuffix(string(entry), "\x00"), "\t")
	f := strings.Fields(meta) // mode, type, object, size
	if !ok || path != rel || len(f) != 4 || f[1] != "blob" || (f[0] != "100644" && f[0] != "100755") {
		return nil, false, errors.New(rel + " is not a regular file")
	}
	if size, err := strconv.ParseInt(f[3], 10, 64); err != nil || size > maxFile {
		return nil, false, fmt.Errorf("%s is too large or has no readable size", rel)
	}
	data, err = c.objects("cat-file", "blob", f[2])
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
