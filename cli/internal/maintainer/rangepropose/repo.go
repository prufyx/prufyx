// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	// maxTagRefs bounds the tags of one clone.
	maxTagRefs = 50000
	// maxFileReads bounds the file reads of one clone.
	maxFileReads = 100000
)

// version is a final release version X.Y.Z.
type version struct{ major, minor, patch uint64 }

var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

func parseVersion(s string) (version, bool) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	var n [3]uint64
	for i := range n {
		v, err := strconv.ParseUint(m[i+1], 10, 32)
		if err != nil {
			return version{}, false
		}
		n[i] = v
	}
	return version{n[0], n[1], n[2]}, true
}

func (v version) less(w version) bool {
	if v.major != w.major {
		return v.major < w.major
	}
	if v.minor != w.minor {
		return v.minor < w.minor
	}
	return v.patch < w.patch
}

// line is a minor release line X.Y.
type line struct{ major, minor uint64 }

func (v version) line() line  { return line{v.major, v.minor} }
func (l line) String() string { return fmt.Sprintf("%d.%d", l.major, l.minor) }
func (l line) start() string  { return fmt.Sprintf("%d.%d.0", l.major, l.minor) }
func (l line) next() string   { return fmt.Sprintf("%d.%d.0", l.major, l.minor+1) }

func (v version) nextPatch() string { return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch+1) }

// preReleaseRE is the closed set of pre-release suffixes that may follow
// PREFIX X.Y.Z. Any other spelling that names a line refuses the rule.
var preReleaseRE = regexp.MustCompile(`^-(alpha|beta|rc)(\.?[0-9]{1,4})?$`)

var versionTokenRE = regexp.MustCompile(`[0-9]+(?:[._-][0-9]+)+`)

// namesLine reports whether any version-like token of a tag name, or the rest
// of a token after any of its "-" or "_", starts with the line's two numbers.
// So "app-2-1.5.0" names line 1.5.
func namesLine(name string, l line) bool {
	for _, token := range versionTokenRE.FindAllString(name, -1) {
		for {
			parts := strings.FieldsFunc(token, func(r rune) bool { return r == '.' || r == '_' || r == '-' })
			if len(parts) < 2 {
				break
			}
			major, err1 := strconv.ParseUint(parts[0], 10, 64)
			minor, err2 := strconv.ParseUint(parts[1], 10, 64)
			if err1 == nil && err2 == nil && major == l.major && minor == l.minor {
				return true
			}
			i := strings.IndexAny(token, "-_")
			if i < 0 {
				break
			}
			token = token[i+1:]
		}
	}
	return false
}

// releaseTag is one final release tag of a project, peeled to its commit.
type releaseTag struct {
	name    string
	version version
	commit  string
}

// repository is one local bare clone with its tags.
type repository struct {
	gitDir string
	tags   []releaseTag // final releases, sorted by version
	// other holds every tag that is neither a final release nor a closed
	// pre-release, sorted.
	other []string
	files map[string]*treeFile
}

// openRepository checks that the project path is a complete, self-contained
// local bare clone and enumerates every ref under refs/tags/. Every failure
// is a *refusal.
func openRepository(ctx context.Context, project Project) (*repository, error) {
	dir, err := filepath.Abs(project.Path)
	if err != nil {
		return nil, refuse(CodeRepoMissing, "the local clone path is invalid")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, refuse(CodeRepoMissing, "the local clone is not a directory")
	}
	// Checked before git runs: git would follow these into another directory.
	borrowed := refuse(CodeRepoAlternates, "the local clone borrows objects from another directory")
	if exists(dir, "commondir") || exists(dir, "objects/info/alternates") || exists(dir, "objects/info/http-alternates") {
		return nil, borrowed
	}
	r := &repository{gitDir: dir, files: map[string]*treeFile{}}
	out, err := r.git(ctx, "rev-parse", "--is-bare-repository", "--is-shallow-repository")
	if err != nil {
		return nil, refuse(CodeRepoMissing, "the local clone is not a git repository")
	}
	state := strings.Fields(string(out))
	if len(state) != 2 || state[0] != "true" {
		return nil, refuse(CodeRepoNotBare, "the local clone is not a bare repository")
	}
	if state[1] != "false" || exists(dir, "shallow") {
		return nil, refuse(CodeRepoShallow, "the local clone is shallow")
	}
	if exists(dir, "info/grafts") {
		return nil, refuse(CodeRepoGrafted, "the local clone has grafts")
	}
	partial := refuse(CodeRepoPartial, "the local clone is a partial clone")
	if packs, err := filepath.Glob(filepath.Join(globEscape(dir), "objects", "pack", "*.promisor")); err != nil || len(packs) != 0 {
		return nil, partial
	}
	config, err := r.git(ctx, "config", "--includes", "--name-only", "--list")
	if err != nil {
		return nil, refuse(CodeGit, "the configuration cannot be read")
	}
	for _, key := range strings.Split(strings.ToLower(string(config)), "\n") {
		if key == "extensions.partialclone" || strings.HasPrefix(key, "remote.") && (strings.HasSuffix(key, ".promisor") || strings.HasSuffix(key, ".partialclonefilter")) {
			return nil, partial
		}
	}
	// git leaves a broken ref out of the listing and only warns, so any
	// warning means the tag list may be incomplete.
	out, err = runGitSilent(ctx, r.gitDir, "for-each-ref", "--format=%(refname)", "refs/tags/")
	if err != nil {
		return nil, refuse(CodeGit, "the tags cannot be listed")
	}
	refs := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(refs) > maxTagRefs {
		return nil, refuse(CodeGit, "the clone has too many tags")
	}
	for _, ref := range refs {
		name := strings.TrimPrefix(ref, "refs/tags/")
		if name == "" {
			continue
		}
		rest, prefixed := strings.CutPrefix(name, project.TagPrefix)
		if prefixed {
			if v, ok := parseVersion(rest); ok {
				commit, err := r.git(ctx, "rev-parse", "--verify", "--quiet", "--end-of-options", ref+"^{commit}")
				id := strings.TrimSpace(string(commit))
				if err != nil || !commitRE.MatchString(id) {
					return nil, refuse(CodeTagNotCommit, "tag "+clean(name)+" does not resolve to a present commit")
				}
				r.tags = append(r.tags, releaseTag{name: name, version: v, commit: id})
				continue
			}
			if core, suffix, found := strings.Cut(rest, "-"); found {
				if _, ok := parseVersion(core); ok && preReleaseRE.MatchString("-"+suffix) {
					continue
				}
			}
		}
		r.other = append(r.other, name)
	}
	sort.Slice(r.tags, func(i, j int) bool { return r.tags[i].version.less(r.tags[j].version) })
	sort.Strings(r.other)
	return r, nil
}

func exists(dir, rel string) bool {
	_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
	// Only a clear "does not exist" counts as absent.
	return !os.IsNotExist(err)
}

func globEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`).Replace(s)
}

func (r *repository) git(ctx context.Context, args ...string) ([]byte, error) {
	return runGit(ctx, r.gitDir, args...)
}

// lineTags returns the final release tags of one line after checking them.
// The line must be complete as far as the clone can show it: no tag naming
// the line in another spelling, X.Y.0 and the anchor present, no gap in the
// patch numbers, equal to the caller's expected list when there is one, and
// no commit shared with another line.
func (r *repository) lineTags(project Project, l line, anchor version) ([]releaseTag, error) {
	for _, name := range r.other {
		if namesLine(name, l) {
			return nil, refuse(CodeTagUnrecognised, "tag "+clean(name)+" names line "+l.String()+" and is neither a final release nor a known pre-release")
		}
	}
	var tags []releaseTag
	for _, t := range r.tags {
		if t.version.line() == l {
			tags = append(tags, t)
		}
	}
	if project.Tags != nil {
		expected := map[string]string{}
		for _, e := range *project.Tags {
			v, ok := parseVersion(strings.TrimPrefix(e.Tag, project.TagPrefix))
			if ok && v.line() == l {
				expected[e.Tag] = e.Commit
			}
		}
		for _, t := range tags {
			commit, listed := expected[t.name]
			if !listed {
				return nil, refuse(CodeTagUnlisted, "tag "+t.name+" is not in the expected list")
			}
			if commit != t.commit {
				return nil, refuse(CodeTagMoved, "tag "+t.name+" is not at the expected commit")
			}
			delete(expected, t.name)
		}
		if len(expected) != 0 {
			names := make([]string, 0, len(expected))
			for name := range expected {
				names = append(names, name)
			}
			sort.Strings(names)
			return nil, refuse(CodeTagMissing, "expected tag "+clean(names[0])+" is not in the clone")
		}
	}
	if len(tags) == 0 {
		return nil, refuse(CodeNoReleaseTags, "no final release tag on line "+l.String())
	}
	// Sorted by patch, so this also requires X.Y.0.
	for i, t := range tags {
		if t.version.patch != uint64(i) {
			return nil, refuse(CodeTagGap, fmt.Sprintf("line %s has no tag for patch %d", l, i))
		}
	}
	if anchor.line() == l && anchor.patch >= uint64(len(tags)) {
		return nil, refuse(CodeAnchorTagMissing, fmt.Sprintf("the anchor release %s.%d has no tag", l, anchor.patch))
	}
	for _, t := range tags {
		for _, other := range r.tags {
			if other.commit == t.commit && other.version.line() != l {
				return nil, refuse(CodeCommitOnTwoLines, "tags "+t.name+" and "+other.name+" share one commit")
			}
		}
	}
	return tags, nil
}

// requireCommit refuses a revision that is not a commit present in the clone.
func (r *repository) requireCommit(ctx context.Context, id string) error {
	out, err := r.git(ctx, "cat-file", "-t", id)
	if err != nil || strings.TrimSpace(string(out)) != "commit" {
		return refuse(CodeObjectMissing, "commit "+id+" is not in the clone")
	}
	return nil
}

func (r *repository) file(ctx context.Context, commit, path string) (*treeFile, error) {
	key := commit + "\x00" + path
	if f, ok := r.files[key]; ok {
		return f, nil
	}
	if len(r.files) >= maxFileReads {
		return nil, refuse(CodeGit, "the file read limit is reached")
	}
	f, err := readTreeFile(ctx, r.gitDir, commit, path)
	if err != nil {
		return nil, err
	}
	r.files[key] = f
	return f, nil
}
