// SPDX-License-Identifier: AGPL-3.0-only

package releasedocs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

var commitID = regexp.MustCompile(`^[0-9a-f]{40}$`)

const zeroCommit = "0000000000000000000000000000000000000000"

// GitEnv returns env without any inherited GIT_ variable and with the settings
// that keep system and user configuration, replace refs and grafts from
// changing what git answers.
func GitEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GIT_") {
			out = append(out, kv)
		}
	}
	return append(out,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_GRAFT_FILE="+os.DevNull,
	)
}

func gitCommand(root string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = GitEnv(os.Environ())
	return cmd
}

// gitBytes is git with the output kept byte for byte.
func (c *checker) gitBytes(args ...string) ([]byte, error) {
	cmd := gitCommand(c.root, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// provenBase reports why the blocks base cannot be used, or nil. The base must
// be a commit, other than HEAD itself, in the history of HEAD of a complete
// clone whose top level is the root.
func (c *checker) provenBase() error {
	base := c.o.BlocksBase
	top, err := c.git("rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	a, aerr := filepath.EvalSymlinks(top)
	b, berr := filepath.EvalSymlinks(c.root)
	if aerr != nil || berr != nil || a != b {
		return errors.New("the root is not the top level of its git work tree")
	}
	if shallow, err := c.git("rev-parse", "--is-shallow-repository"); err != nil || shallow != "false" {
		return errors.New("the clone is shallow or its depth cannot be read")
	}
	got, err := c.git("rev-parse", "--verify", "--end-of-options", base+"^{commit}")
	if err != nil || got != base {
		return errors.New("it does not name a commit of this repository")
	}
	head, err := c.git("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return err
	}
	if head == base {
		return errors.New("it is the checked-out commit itself; a tree compared with itself proves nothing")
	}
	if _, err := c.git("merge-base", "--is-ancestor", base, head); err != nil {
		return errors.New("it is not an ancestor of HEAD")
	}
	return nil
}

// readAtBase reads a regular, non-executable file of the base commit; ok is
// false when the base has no such path.
func (c *checker) readAtBase(rel string) (text string, ok bool, err error) {
	out, err := c.gitBytes("ls-tree", "-z", "--full-tree", c.o.BlocksBase, "--", rel)
	if err != nil {
		return "", false, err
	}
	if len(out) == 0 {
		return "", false, nil
	}
	meta, name, found := strings.Cut(strings.TrimSuffix(string(out), "\x00"), "\t")
	f := strings.Fields(meta)
	if !found || name != rel || len(f) != 3 || f[0] != "100644" || f[1] != "blob" {
		return "", false, fmt.Errorf("%s is not a regular file at the base commit", rel)
	}
	size, err := c.git("cat-file", "-s", f[2])
	if err != nil {
		return "", false, err
	}
	if n, err := strconv.ParseInt(size, 10, 64); err != nil || n > maxFile {
		return "", false, fmt.Errorf("%s is too large at the base commit", rel)
	}
	data, err := c.gitBytes("cat-file", "blob", f[2])
	if err != nil {
		return "", false, err
	}
	return string(data), true, nil
}

// blockOf returns the bytes between the marker lines of doc, which must hold
// exactly one marker pair.
func blockOf(doc string) (string, error) {
	if _, err := releasenotes.ReplaceBlock(doc, ""); err != nil {
		return "", err
	}
	lines := strings.Split(doc, "\n")
	begin, end := 0, 0
	for i, l := range lines {
		switch strings.TrimRight(l, " \r") {
		case releasenotes.MarkerBegin:
			begin = i
		case releasenotes.MarkerEnd:
			end = i
		}
	}
	return strings.Join(lines[begin+1:end], "\n"), nil
}

// baseBlocks holds the generated blocks the base commit has for one release.
type baseBlocks struct{ notes, changelog string }

// releaseAtBase returns the blocks of the notes file and of the CHANGELOG entry
// at the base commit. ok is false, and nothing may be accepted from the base,
// unless the base has both, each with one non-empty marker pair: a release that
// the base did not carry in full must equal its regeneration.
func (c *checker) releaseAtBase(name, version string) (b baseBlocks, ok bool) {
	if !c.baseProven {
		return b, false
	}
	var docs [2]string
	for i, rel := range []string{name, changelogPath} {
		doc, found, err := c.readAtBase(rel)
		if err != nil {
			c.fail(CodeBase, "blocks base: %v", err)
			return b, false
		}
		if !found {
			return b, false
		}
		docs[i] = doc
	}
	section, found := changelogSection(docs[1], version)
	if !found {
		return b, false
	}
	nb, nerr := blockOf(docs[0])
	cb, cerr := blockOf(section)
	if nerr != nil || cerr != nil || strings.TrimSpace(nb) == "" || strings.TrimSpace(cb) == "" {
		return b, false
	}
	return baseBlocks{notes: nb, changelog: cb}, true
}

// keptFromBase reports whether the block of head is byte for byte baseBlock,
// and records the notice when it is.
func (c *checker) keptFromBase(what, head, baseBlock string) bool {
	got, err := blockOf(head)
	if err != nil || got != baseBlock {
		return false
	}
	c.res.Notices = append(c.res.Notices, fmt.Sprintf("release-docs: %s: the generated block is STALE; accepted only because it equals the block at the base commit %s (the release and cut modes require its regeneration)", what, c.o.BlocksBase))
	return true
}

// guardBlock refuses rendered text that could change the meaning of the file
// around it: a comment or raw markup, a link, a control or invisible
// character, or a heading of the level that separates CHANGELOG entries.
func guardBlock(block string) error {
	if !utf8.ValidString(block) {
		return errors.New("it is not valid UTF-8")
	}
	for _, bad := range []string{"<!--", "](", "<"} {
		if strings.Contains(block, bad) {
			return fmt.Errorf("it contains %q", bad)
		}
	}
	for _, r := range block {
		if r != '\n' && (unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)) {
			return fmt.Errorf("it contains the control or invisible character %U", r)
		}
	}
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimLeft(l, " "), "## ") {
			return errors.New("it contains a line that starts a \"## \" heading")
		}
	}
	return nil
}
