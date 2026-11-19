// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxScanPaths       = 20
	maxCheckoutBlob    = 8 << 20
	maxTargetInput     = 256 << 10
	maxTargetListItems = 20
	maxNoteRunes       = 300
	gitTimeout         = 30 * time.Second
)

var (
	// textRE is the charset allowlist for every declared free-text value
	// (notes, reasons, evidence, names): printable ASCII without backslash,
	// backtick, angle brackets, dollar, pipe, tilde and caret.
	textRE      = regexp.MustCompile(`^[A-Za-z0-9 .,;:!?()'"_/+=#%@&*\[\]{}-]*$`)
	nameRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,99}$`)
	componentRE = regexp.MustCompile(`^pkg:github/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	factProjRE  = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)
	repoRE      = regexp.MustCompile(`^github\.com/[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)
	asciiRE     = regexp.MustCompile(`^[\x20-\x7e]*$`)
)

// safeRepoPath reports whether p is a plain repo-relative path: allowed
// characters only, no absolute path, no empty or dot segment, no glob.
func safeRepoPath(p string) bool {
	if !buildPathRE.MatchString(p) || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ---- --checkout: evidence limited to blobs the verified snapshot holds ----

type scanPath struct{ path, class, note string }

func parseScanPaths(specs []string) ([]scanPath, error) {
	if len(specs) > maxScanPaths {
		return nil, refuse("--scan-path given %d times, more than %d", len(specs), maxScanPaths)
	}
	seen := map[string]bool{}
	var out []scanPath
	for _, s := range specs {
		parts := strings.SplitN(s, ":", 3)
		if len(parts) < 2 {
			return nil, refuse("--scan-path %q must look like PATH:CLASS[:NOTE]", s)
		}
		sp := scanPath{path: parts[0], class: parts[1]}
		if len(parts) == 3 {
			sp.note = parts[2]
		}
		if !safeRepoPath(sp.path) {
			return nil, refuse("--scan-path %q: the path must be a plain repo-relative path (no absolute path, dot segment or glob)", sp.path)
		}
		if !inSchemaEnum([]string{"$defs", "scanNotes", "properties", "entries", "items", "properties", "class", "enum"}, sp.class) {
			return nil, refuse("--scan-path %q: class %q is not in the schema allowlist", sp.path, sp.class)
		}
		if len([]rune(sp.note)) > maxNoteRunes || !textRE.MatchString(sp.note) {
			return nil, refuse("--scan-path %q: the note is over %d characters or has a character outside the allowlist", sp.path, maxNoteRunes)
		}
		if seen[sp.path] {
			return nil, refuse("--scan-path %q given twice", sp.path)
		}
		seen[sp.path] = true
		out = append(out, sp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

// scanEntries builds scan-notes entries. It reads nothing but git objects of
// the local clone, addressed by the snapshot's commit ids (never the working
// tree, never a glob, never a path the snapshot holds no blob for). A path
// qualifies only when the verified snapshot holds its blob (a changelog
// source or the licence) at the commit of a built tag; for each such tag the
// clone's blob must hash to the snapshot's digest and its tag must resolve to
// the snapshot commit. Anything else is a refusal.
func scanEntries(o BuildOptions, sv *snapView, kept []snapTag) ([]any, error) {
	if o.Checkout == "" && len(o.ScanPaths) > 0 {
		return nil, refuse("--scan-path needs --checkout")
	}
	if o.Checkout == "" {
		return []any{}, nil
	}
	sps, err := parseScanPaths(o.ScanPaths)
	if err != nil {
		return nil, err
	}
	if len(sps) == 0 {
		return nil, refuse("--checkout needs at least one --scan-path PATH:CLASS[:NOTE]; nothing is read without it")
	}
	if fi, err := os.Lstat(o.Checkout); err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, refuse("--checkout must be an existing directory and not a symbolic link")
	}
	root, err := filepath.Abs(o.Checkout)
	if err != nil {
		return nil, err
	}
	// Snapshot-held blobs: commit -> path -> digest.
	held := map[string]map[string]string{}
	add := func(s snapSource) {
		if held[s.Commit] == nil {
			held[s.Commit] = map[string]string{}
		}
		held[s.Commit][s.Path] = s.Digest
	}
	for _, s := range sv.Sources {
		add(s)
	}
	if sv.Lic != nil {
		add(*sv.Lic)
	}
	asc := make([]snapTag, len(kept))
	copy(asc, kept)
	sort.Slice(asc, func(i, j int) bool { return lessVer(asc[i], asc[j]) })

	entries := []any{}
	for _, sp := range sps {
		var ev []any
		for _, t := range asc {
			want, ok := held[t.Commit][sp.path]
			if !ok {
				continue
			}
			got, err := checkoutBlobDigest(root, t, sp.path)
			if err != nil {
				return nil, err
			}
			if got != want {
				return nil, refuse("--scan-path %s: the blob in the checkout at %s differs from the snapshot's digest", sp.path, t.Tag)
			}
			ev = append(ev, map[string]any{"tag": t.Tag, "commit": t.Commit, "sha256": got})
		}
		if len(ev) == 0 {
			return nil, refuse("--scan-path %s: the snapshot holds no blob for this path at any built tag; the checkout is read only for blobs the snapshot holds", sp.path)
		}
		entries = append(entries, map[string]any{"path": sp.path, "class": sp.class, "note": sp.note, "evidence": ev})
	}
	return entries, nil
}

// checkoutBlobDigest returns the sha256 of the blob at commit:path in the
// clone after checking that the tag resolves to the snapshot commit.
func checkoutBlobDigest(root string, t snapTag, path string) (string, error) {
	tagCommit, err := gitOutput(root, 128, "rev-parse", "--verify", "--quiet", "refs/tags/"+t.Tag+"^{commit}")
	if err != nil || strings.TrimSpace(string(tagCommit)) != t.Commit {
		return "", refuse("--checkout: tag %s does not resolve to the snapshot commit %s", t.Tag, t.Commit)
	}
	if typ, err := gitOutput(root, 16, "cat-file", "-t", t.Commit); err != nil || strings.TrimSpace(string(typ)) != "commit" {
		return "", refuse("--checkout: commit %s is not in the checkout", t.Commit)
	}
	blob, err := gitOutput(root, maxCheckoutBlob+1, "cat-file", "blob", t.Commit+":"+path)
	if err != nil {
		return "", refuse("--checkout: %s is not a file at commit %s", path, t.Commit)
	}
	if len(blob) > maxCheckoutBlob {
		return "", refuse("--checkout: %s is over %d bytes", path, maxCheckoutBlob)
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:]), nil
}

// gitOutput runs git against the clone's object database only: no config
// files, no replace refs, no discovery above the directory, no prompts. It
// returns at most limit bytes and an error when git fails or prints more.
func gitOutput(root string, limit int, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"--no-replace-objects", "--no-optional-locks"}, args...)...)
	cmd.Dir = root
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(root),
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	data, rerr := io.ReadAll(io.LimitReader(stdout, int64(limit)+1))
	if len(data) > limit {
		cancel()
		_ = cmd.Wait()
		return nil, fmt.Errorf("git output over %d bytes", limit)
	}
	if rerr != nil {
		_ = cmd.Wait()
		return nil, rerr
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return data, nil
}

// ---- --target-input: a maintainer hint that shapes the skeleton ----

type targetInput struct {
	hasName, hasComponent, hasFact bool
	name, component, factProject   string
	paths, exclude, copies         []any // validated, in input order
	pathList                       []string
	excludeList                    []exclEntry
	copyList                       []copyEntry
}

type exclEntry struct{ path, repo string }
type copyEntry struct {
	path, with string
	tags       []string
}

// loadTargetInput reads and validates FILE. Strict JSON, a closed key set and
// per-field caps and charsets frozen here (not only in the schema). Keys that
// would set status, origin, project or repo are unknown keys and refused.
func loadTargetInput(file string) (*targetInput, error) {
	fi, err := os.Lstat(file)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, refuse("--target-input must be a regular file and not a symbolic link")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, refuse("--target-input cannot be read")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxTargetInput+1))
	if err != nil {
		return nil, refuse("--target-input cannot be read")
	}
	if len(raw) > maxTargetInput {
		return nil, refuse("--target-input is over %d bytes", maxTargetInput)
	}
	doc, err := parseStrict(raw)
	if err != nil {
		return nil, refuse("--target-input: %v", err)
	}
	top, ok := doc.(map[string]any)
	if !ok {
		return nil, refuse("--target-input must be a JSON object")
	}
	allowed := map[string]bool{"name": true, "component": true, "factProject": true, "paths": true, "exclude": true, "copiesEvidence": true}
	for _, k := range sortedKeys(top) {
		if !allowed[k] {
			return nil, refuse("--target-input: key %q is not allowed (allowed: name, component, factProject, paths, exclude, copiesEvidence)", k)
		}
	}
	ti := &targetInput{}
	str := func(key string, re *regexp.Regexp, max int) (string, bool, error) {
		v, present := top[key]
		if !present {
			return "", false, nil
		}
		s, ok := v.(string)
		if !ok || len([]rune(s)) == 0 || len([]rune(s)) > max || !re.MatchString(s) {
			return "", false, refuse("--target-input: %s is not a string of at most %d characters in the allowed charset", key, max)
		}
		return s, true, nil
	}
	if ti.name, ti.hasName, err = str("name", nameRE, 100); err != nil {
		return nil, err
	}
	if ti.component, ti.hasComponent, err = str("component", componentRE, 200); err != nil {
		return nil, err
	}
	if ti.factProject, ti.hasFact, err = str("factProject", factProjRE, 63); err != nil {
		return nil, err
	}
	obj := func(label string, v any) (map[string]any, error) {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, refuse("--target-input: %s entries must be objects", label)
		}
		return m, nil
	}
	closed := func(label string, m map[string]any, req []string, opt ...string) error {
		ok := map[string]bool{}
		for _, k := range req {
			ok[k] = true
			if _, p := m[k]; !p {
				return refuse("--target-input: %s needs key %q", label, k)
			}
		}
		for _, k := range opt {
			ok[k] = true
		}
		for _, k := range sortedKeys(m) {
			if !ok[k] {
				return refuse("--target-input: %s has unknown key %q", label, k)
			}
		}
		return nil
	}
	strField := func(label string, m map[string]any, key string, re *regexp.Regexp, min, max int) (string, error) {
		s, ok := m[key].(string)
		n := len([]rune(s))
		if !ok || n < min || n > max || !re.MatchString(s) {
			return "", refuse("--target-input: %s.%s must be %d..%d characters in the allowed charset", label, key, min, max)
		}
		return s, nil
	}
	pathField := func(label string, m map[string]any, key string) (string, error) {
		s, ok := m[key].(string)
		if !ok || !safeRepoPath(s) {
			return "", refuse("--target-input: %s.%s must be a plain repo-relative path", label, key)
		}
		return s, nil
	}
	list := func(key string) ([]any, error) {
		v, present := top[key]
		if !present {
			return nil, nil
		}
		a, ok := v.([]any)
		if !ok || len(a) > maxTargetListItems {
			return nil, refuse("--target-input: %s must be an array of at most %d entries", key, maxTargetListItems)
		}
		return a, nil
	}
	pl, err := list("paths")
	if err != nil {
		return nil, err
	}
	for i, x := range pl {
		label := fmt.Sprintf("paths[%d]", i)
		m, err := obj(label, x)
		if err != nil {
			return nil, err
		}
		if err := closed(label, m, []string{"path"}, "directory", "match", "guard"); err != nil {
			return nil, err
		}
		p, err := pathField(label, m, "path")
		if err != nil {
			return nil, err
		}
		out := map[string]any{"path": p}
		if d, present := m["directory"]; present {
			b, ok := d.(bool)
			if !ok {
				return nil, refuse("--target-input: %s.directory must be true or false", label)
			}
			out["directory"] = b
		}
		for _, k := range []string{"match", "guard"} {
			if _, present := m[k]; present {
				s, err := strField(label, m, k, asciiRE, 0, 200)
				if err != nil {
					return nil, err
				}
				out[k] = s
			}
		}
		ti.paths = append(ti.paths, out)
		ti.pathList = append(ti.pathList, p)
	}
	el, err := list("exclude")
	if err != nil {
		return nil, err
	}
	for i, x := range el {
		label := fmt.Sprintf("exclude[%d]", i)
		m, err := obj(label, x)
		if err != nil {
			return nil, err
		}
		if err := closed(label, m, []string{"path", "repo", "reason", "evidence"}, "copies"); err != nil {
			return nil, err
		}
		p, err := pathField(label, m, "path")
		if err != nil {
			return nil, err
		}
		repo, err := strField(label, m, "repo", repoRE, 1, 512)
		if err != nil {
			return nil, err
		}
		reason, err := strField(label, m, "reason", textRE, 12, 300)
		if err != nil {
			return nil, err
		}
		evidence, err := strField(label, m, "evidence", textRE, 40, 800)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"path": p, "repo": repo, "reason": reason, "evidence": evidence}
		if c, present := m["copies"]; present {
			b, ok := c.(bool)
			if !ok {
				return nil, refuse("--target-input: %s.copies must be true or false", label)
			}
			out["copies"] = b
		}
		ti.exclude = append(ti.exclude, out)
		ti.excludeList = append(ti.excludeList, exclEntry{p, repo})
	}
	cl, err := list("copiesEvidence")
	if err != nil {
		return nil, err
	}
	for i, x := range cl {
		label := fmt.Sprintf("copiesEvidence[%d]", i)
		m, err := obj(label, x)
		if err != nil {
			return nil, err
		}
		if err := closed(label, m, []string{"path", "comparedWith", "tags", "note"}); err != nil {
			return nil, err
		}
		p, err := pathField(label, m, "path")
		if err != nil {
			return nil, err
		}
		with, err := pathField(label, m, "comparedWith")
		if err != nil {
			return nil, err
		}
		note, err := strField(label, m, "note", textRE, 0, maxNoteRunes)
		if err != nil {
			return nil, err
		}
		ta, ok := m["tags"].([]any)
		if !ok || len(ta) > 12 {
			return nil, refuse("--target-input: %s.tags must be an array of at most 12 tags", label)
		}
		var tags []any
		var tagList []string
		for _, tg := range ta {
			s, ok := tg.(string)
			if !ok || !buildTagRE.MatchString(s) {
				return nil, refuse("--target-input: %s.tags has a malformed tag", label)
			}
			tags = append(tags, s)
			tagList = append(tagList, s)
		}
		if tags == nil {
			tags = []any{}
		}
		ti.copies = append(ti.copies, map[string]any{"path": p, "comparedWith": with, "tags": tags, "note": note})
		ti.copyList = append(ti.copyList, copyEntry{p, with, tagList})
	}
	return ti, nil
}

// apply writes the declared values into the skeleton target-draft document.
// The status is never touched: a hint shapes the skeleton and nothing more.
func (ti *targetInput) apply(td map[string]any) {
	tg := td["target"].(map[string]any)
	if ti.hasName {
		tg["name"] = ti.name
	}
	if ti.hasComponent {
		tg["component"] = ti.component
	}
	if ti.hasFact {
		tg["factProject"] = ti.factProject
	}
	if len(ti.paths) > 0 {
		tg["paths"] = ti.paths
	}
	if len(ti.exclude) > 0 {
		tg["exclude"] = ti.exclude
	}
	if len(ti.copies) > 0 {
		td["copiesEvidence"] = ti.copies
	}
}

// ---- offline target check ----

const (
	checkPass   = "pass"
	checkFail   = "fail"
	checkNotRun = "not-run"
)

// offlineTargetCheck is a deterministic consistency check of the declared
// target against the snapshot's own data (built tags, tag prefix, lowest
// line, the changelog and licence paths it holds). It reads nothing else:
// no network, no checkout, no clock. pass means the declaration is
// self-consistent with the snapshot. It does not mean any path exists
// upstream, that the target is right, or that anything is verified upstream.
// The reasons are returned in a fixed order.
func offlineTargetCheck(ti *targetInput, repo, prefix, minFrom string, kept []snapTag, sv *snapView) (string, []string) {
	var why []string
	if !lineBuilt(kept, minFrom) {
		why = append(why, "minFrom "+minFrom+" is not a built release line")
	}
	for _, t := range kept {
		if !strings.HasPrefix(t.Tag, prefix) {
			why = append(why, "tag "+t.Tag+" does not start with tag prefix "+prefix)
		}
	}
	if len(ti.pathList) == 0 {
		why = append(why, "no paths declared")
	}
	snapFiles := map[string]bool{}
	for _, s := range sv.Sources {
		snapFiles[s.Path] = true
	}
	if sv.Lic != nil {
		snapFiles[sv.Lic.Path] = true
	}
	seen := map[string]bool{}
	for _, p := range ti.pathList {
		if seen[p] {
			why = append(why, "path "+p+" declared twice")
		}
		seen[p] = true
		if snapFiles[p] {
			why = append(why, "path "+p+" is a changelog or licence file of the snapshot, not a target path")
		}
	}
	exSeen := map[string]bool{}
	for _, e := range ti.excludeList {
		if exSeen[e.path+"\x00"+e.repo] {
			why = append(why, "exclude "+e.path+" declared twice")
		}
		exSeen[e.path+"\x00"+e.repo] = true
		if e.repo != repo {
			continue
		}
		for _, p := range ti.pathList {
			if overlaps(p, e.path) {
				why = append(why, "path "+p+" overlaps the exclusion "+e.path+" in the same repository")
			}
		}
	}
	built := map[string]bool{}
	for _, t := range kept {
		built[t.Tag] = true
	}
	declared := map[string]bool{}
	for _, p := range ti.pathList {
		declared[p] = true
	}
	for _, e := range ti.excludeList {
		declared[e.path] = true
	}
	for i, c := range ti.copyList {
		if !declared[c.path] {
			why = append(why, fmt.Sprintf("copiesEvidence[%d].path %s is neither a declared path nor an exclusion", i, c.path))
		}
		if len(c.tags) == 0 {
			why = append(why, fmt.Sprintf("copiesEvidence[%d] names no tag", i))
		}
		for _, tg := range c.tags {
			if !built[tg] {
				why = append(why, fmt.Sprintf("copiesEvidence[%d] tag %s is not a built release tag", i, tg))
			}
		}
	}
	if len(why) > 0 {
		return checkFail, why
	}
	return checkPass, nil
}

func lineBuilt(kept []snapTag, line string) bool {
	for _, t := range kept {
		if t.line == line {
			return true
		}
	}
	return false
}

// overlaps reports whether a equals b or one lies beneath the other.
func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
