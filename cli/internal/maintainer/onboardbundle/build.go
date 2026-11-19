// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/maintainer/projectonboarding"
)

const (
	maxReleaseLines = 6
	maxRelnoteRows  = 20
	// unverifiedToolCommit is written to tool.prufyxCommit when the binary
	// carries no embedded commit. The schema wants 40 hex characters, so the
	// all-zero value is the explicit "unverified" marker; it names no commit.
	unverifiedToolCommit = "0000000000000000000000000000000000000000"
)

var (
	buildPathRE   = regexp.MustCompile(`^[A-Za-z0-9._@+=,~ /-]{1,512}$`)
	buildPrefixRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._-]{0,30}[-/]|v|)$`)
	buildLineRE   = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}$`)
	buildTagRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,127}$`)
	buildSHARE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE     = regexp.MustCompile(`^\D*([0-9]{1,6})\.([0-9]{1,6})(?:\.([0-9]{1,6}))?`)
	cncfValues    = []string{"graduated", "incubating", "sandbox", "none", "unknown"}
)

const buildHelp = `usage: prufyx-maintainer onboard-bundle build [flags]

Writes a new bundle directory from a project snapshot you made with
"project init", "project sync" and "project verify", then writes the receipt
with the same function as "onboard-bundle seal". The output is the four
required files plus receipt.json; nothing is fetched, no clock is read.

What the snapshot proves: it is SELF-CONSISTENT with its own digests. It is
not verified against upstream. The import is planned to re-check tags, licence and changelog spans against upstream; today these declared values are checked only for format and by the human merge review. The receipt is an integrity record
of the file bytes only, never provenance.

target-draft.json is ALWAYS a skeleton: no paths, no exclusions, no names.
build never writes a filled target; coverage comes only from the pipeline.
build sets no origin, no review result and nothing an importer derives.

required:
  -snapshot DIR   verified snapshot directory (snapshot-<sha256>), v1 or v2
  -slug S         bundle slug; must equal the base name of -out
  -spdx ID        licence identifier, YOUR declaration (never inferred; one
                  of the schema allowlist, e.g. Apache-2.0)
  -out DIR        new directory, must not exist, e.g. contrib/onboard-bundles/<slug>
  -post-tag PATH / -no-post-tag PATH
                  for every changelog path the snapshot holds, say whether
                  the file is changed after the tag (repeat the flag per path)

optional (declared by you, never guessed):
  -cncf STATUS    graduated|incubating|sandbox|none|unknown (default none;
                  never looked up)
  -tags T1,T2     snapshot tags to use (default all; at most 6 release lines)
  -tag-prefix P   tag prefix when it cannot be derived from the tags
  -min-from L     lowest supported release line, one of the built lines
  -no-crds        mark target-draft status no-crds (your declaration)
  -checkout DIR   a local git clone (never fetched, working tree never read).
                  With -scan-path it records, per built tag, the sha256 of
                  blobs the SNAPSHOT already holds (changelog files, the
                  licence); a path the snapshot holds no blob for is refused.
                  The tag must resolve to the snapshot commit and the blob
                  must hash to the snapshot's digest.
  -scan-path P:CLASS[:NOTE]
                  repeatable (at most 20); a plain repo-relative path, a
                  schema class, an optional note (300 characters, restricted
                  charset). Needs -checkout.
  -target-input FILE
                  your hint for the target skeleton: a JSON object with only
                  name, component, factProject, paths, exclude,
                  copiesEvidence (at most 256 KiB, strict JSON, capped
                  fields). The status stays skeleton; the file can never make
                  a filled target. Not combinable with -no-crds.

With -target-input, an offline check runs on the declared target and the
snapshot's own data only (built tags, prefix, lowest line, the changelog and
licence files it holds): at least one path, no duplicates, no overlap with an
exclusion, no path that is a snapshot changelog or licence file, copies
evidence naming only declared paths and built tags. The result, pass or fail,
is written to receipt.json checks.targetCheckOffline and the reasons are
printed. A failed check still writes the bundle, for inspection, but exits 1:
fix the reasons, then run build again; a bundle with a failed check is not
ready to submit. Without -target-input it is not-run. pass means the declaration is
self-consistent with the snapshot. It does not verify anything upstream, does
not show that a path exists, and is not coverage: coverage comes only from
the pipeline.

tool.prufyxCommit is the commit embedded in this binary at build time; a
binary without one writes 0000...0000 (unverified).
`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runBuild(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("onboard-bundle build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o BuildOptions
	var tagsCSV string
	var post, noPost multiFlag
	fs.StringVar(&o.SnapshotDir, "snapshot", "", "")
	fs.StringVar(&o.Slug, "slug", "", "")
	fs.StringVar(&o.SPDX, "spdx", "", "")
	fs.StringVar(&o.Out, "out", "", "")
	fs.StringVar(&o.CNCF, "cncf", "none", "")
	fs.StringVar(&tagsCSV, "tags", "", "")
	fs.StringVar(&o.TagPrefix, "tag-prefix", "", "")
	fs.StringVar(&o.MinFrom, "min-from", "", "")
	fs.BoolVar(&o.NoCRDs, "no-crds", false, "")
	fs.StringVar(&o.Checkout, "checkout", "", "")
	fs.StringVar(&o.TargetInput, "target-input", "", "")
	var scanPaths multiFlag
	fs.Var(&scanPaths, "scan-path", "")
	fs.Var(&post, "post-tag", "")
	fs.Var(&noPost, "no-post-tag", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, buildHelp)
			return 0
		}
		fmt.Fprintf(stderr, "onboard-bundle build: %v\n", err)
		fmt.Fprint(stderr, buildHelp)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, buildHelp)
		return 2
	}
	if tagsCSV != "" {
		o.Tags = strings.Split(tagsCSV, ",")
	}
	o.ScanPaths = scanPaths
	o.PostTag = map[string]bool{}
	for _, p := range post {
		if _, dup := o.PostTag[p]; dup {
			fmt.Fprintf(stderr, "onboard-bundle build: --post-tag/--no-post-tag given twice for %q\n", p)
			return 2
		}
		o.PostTag[p] = true
	}
	for _, p := range noPost {
		if _, dup := o.PostTag[p]; dup {
			fmt.Fprintf(stderr, "onboard-bundle build: --post-tag/--no-post-tag given twice for %q\n", p)
			return 2
		}
		o.PostTag[p] = false
	}
	o.ToolCommit = buildidentity.SourceRevision
	res, err := Build(o)
	for _, line := range res.Notes {
		fmt.Fprintln(stdout, line)
	}
	if err != nil {
		fmt.Fprintf(stderr, "onboard-bundle build: %v\n", err)
		var re refusal
		if errors.As(err, &re) {
			return 1
		}
		return 2
	}
	if res.CheckFailed {
		fmt.Fprintln(stderr, "onboard-bundle build: the offline target check failed; the bundle was written for inspection with checks.targetCheckOffline=fail. Fix the reasons above, then run build again; a bundle with a failed check is not ready to submit")
		return 1
	}
	return 0
}

// BuildOptions are the inputs of Build. Every declared value comes from a
// flag; nothing is guessed from the snapshot.
type BuildOptions struct {
	SnapshotDir string
	Slug        string
	SPDX        string
	Out         string
	CNCF        string
	Tags        []string
	TagPrefix   string
	MinFrom     string
	NoCRDs      bool
	Checkout    string          // local clone; read only for blobs the snapshot holds
	ScanPaths   []string        // PATH:CLASS[:NOTE], needs Checkout
	TargetInput string          // maintainer hint file; shapes the skeleton only
	PostTag     map[string]bool // changelog path -> postTag
	ToolCommit  string          // build-embedded commit; anything but 40-hex is written as unverified
}

// BuildResult carries the lines Build reports.
type BuildResult struct {
	Notes []string
	// CheckFailed is true when the offline target check failed: the bundle
	// is written for inspection, but the command exits 1.
	CheckFailed bool
}

type snapTag struct {
	Tag, Commit string
	line        string
	ver         [3]int
}

type snapSource struct {
	Path, Commit, Digest string
	Start, End           int
}

type snapView struct {
	RepoURL    string // https://github.com/o/r
	ObservedAt string
	ReqPrefix  string // v1 request tag prefix, "" when none
	Tags       []snapTag
	Sources    []snapSource
	Lic        *snapSource
}

// Build writes a new bundle directory at o.Out from a verified snapshot. It is
// fail-closed: on any refusal no output directory exists.
func Build(o BuildOptions) (BuildResult, error) {
	var res BuildResult
	if o.SnapshotDir == "" {
		return res, usageError{errors.New("--snapshot is required")}
	}
	if o.Slug == "" {
		return res, usageError{errors.New("--slug is required")}
	}
	if o.SPDX == "" {
		return res, usageError{errors.New("--spdx is required (your licence declaration; it is never inferred)")}
	}
	if o.Out == "" {
		return res, usageError{errors.New("--out is required")}
	}
	if !slugRE.MatchString(o.Slug) {
		return res, refuse("--slug %q does not match %s", o.Slug, slugRE)
	}
	if !inSchemaEnum([]string{"$defs", "project", "properties", "licence", "properties", "spdxGuess", "enum"}, o.SPDX) {
		return res, refuse("--spdx %q is not in the schema allowlist", o.SPDX)
	}
	if !inList(cncfValues, o.CNCF) {
		return res, refuse("--cncf %q must be one of %s", o.CNCF, strings.Join(cncfValues, ", "))
	}
	if o.TagPrefix != "" && !buildPrefixRE.MatchString(o.TagPrefix) {
		return res, refuse("--tag-prefix %q is not an allowed tag prefix", o.TagPrefix)
	}
	if o.MinFrom != "" && !buildLineRE.MatchString(o.MinFrom) {
		return res, refuse("--min-from %q must look like 1.2", o.MinFrom)
	}
	out, err := filepath.Abs(o.Out)
	if err != nil {
		return res, err
	}
	if filepath.Base(out) != o.Slug {
		return res, refuse("--out base name %q must equal --slug %q", filepath.Base(out), o.Slug)
	}
	parent := filepath.Dir(out)
	if pi, err := os.Lstat(parent); err != nil || pi.Mode()&os.ModeSymlink != 0 || !pi.IsDir() {
		return res, refuse("--out parent must be an existing directory and not a symbolic link")
	}
	if _, err := os.Lstat(out); err == nil {
		return res, refuse("--out %s already exists; build never overwrites", o.Out)
	} else if !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	if si, err := os.Lstat(o.SnapshotDir); err != nil || si.Mode()&os.ModeSymlink != 0 || !si.IsDir() {
		return res, refuse("--snapshot must be a directory and not a symbolic link")
	}

	sv, err := loadSnapshotView(o.SnapshotDir)
	if err != nil {
		return res, err
	}
	docs, notes, check, err := buildDocs(o, sv)
	res.Notes = append(res.Notes, notes...)
	res.CheckFailed = check == checkFail
	if err != nil {
		return res, err
	}
	if bad := leakFindings(docs); len(bad) > 0 {
		return res, refuse("refused, %d value(s) look like a secret or an internal name:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	if _, err := os.Lstat(filepath.Join("contrib", "onboard-bundles", o.Slug)); err == nil {
		res.Notes = append(res.Notes, "notice: contrib/onboard-bundles/"+o.Slug+" already exists here; review decides")
	}

	// Write into <parent>/.build-*/<slug>, seal there, then rename to out.
	work, err := os.MkdirTemp(parent, ".build-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(work)
	stage := filepath.Join(work, o.Slug)
	if err := os.Mkdir(stage, 0o755); err != nil {
		return res, err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return res, err
	}
	for _, name := range []string{"project.json", "relnotes-sources.json", "scan-notes.json", "target-draft.json"} {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(docs[name]); err != nil {
			return res, err
		}
		if err := os.WriteFile(filepath.Join(stage, name), buf.Bytes(), 0o644); err != nil {
			return res, err
		}
	}
	tool := o.ToolCommit
	if !sealCommitRE.MatchString(tool) {
		tool = unverifiedToolCommit
	}
	if _, err := Seal(stage, SealOptions{ToolCommit: tool, GeneratedAt: sv.ObservedAt, TargetCheck: check}); err != nil {
		return res, refuse("seal failed: %v", err)
	}
	findings, err := Validate(stage)
	if err != nil {
		return res, err
	}
	if f := dirSlugFinding(stage); f != "" {
		findings = append(findings, f)
	}
	if len(findings) > 0 {
		return res, refuse("built bundle does not validate:\n  %s", strings.Join(findings, "\n  "))
	}
	if _, err := os.Lstat(out); err == nil {
		return res, refuse("--out %s appeared meanwhile; build never overwrites", o.Out)
	}
	if err := os.Rename(stage, out); err != nil {
		return res, err
	}
	if tool == unverifiedToolCommit {
		res.Notes = append(res.Notes, "tool.prufyxCommit: unverified (this binary has no embedded commit)")
	} else {
		res.Notes = append(res.Notes, "tool.prufyxCommit: embedded at build time, not verified by the importer")
	}
	res.Notes = append(res.Notes,
		"built "+o.Out+": the snapshot is self-consistent only, not verified against upstream; "+"The import is planned to re-check tags, licence and changelog spans against upstream; today these declared values are checked only for format and by the human merge review.",
		"target-draft.json is a skeleton; coverage comes only from the pipeline",
		"in the pull request text, list the fields you declared: spdxGuess, cncfStatusClaim, postTag, tagPrefix, minFrom, status")
	return res, nil
}

func inList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// inSchemaEnum reports whether v is in the enum found at path in the embedded
// schema; an unreadable schema or path means false (fail closed).
func inSchemaEnum(path []string, v string) bool {
	var cur any
	if json.Unmarshal(schemaJSON, &cur) != nil {
		return false
	}
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		if cur, ok = m[p]; !ok {
			return false
		}
	}
	arr, ok := cur.([]any)
	if !ok {
		return false
	}
	for _, x := range arr {
		if s, _ := x.(string); s == v {
			return true
		}
	}
	return false
}

func loadSnapshotView(dir string) (*snapView, error) {
	snap, objs, err := projectonboarding.VerifySnapshot(dir)
	if err != nil || snap == nil {
		return nil, refuse("--snapshot is not a verified snapshot (it must pass \"project verify\": no changed, missing or extra content)")
	}
	if err := checkSnapshotTree(dir, objs); err != nil {
		return nil, err
	}
	review, _ := snap["review"].(map[string]any)
	if review["state"] != "NOT_REVIEWED" || review["admissionState"] != "NOT_ADMITTED" {
		return nil, refuse("snapshot review state must be NOT_REVIEWED / NOT_ADMITTED")
	}
	sv := &snapView{}
	repo, _ := snap["repository"].(map[string]any)
	sv.RepoURL, _ = repo["canonicalRepositoryURL"].(string)
	if !strings.HasPrefix(sv.RepoURL, "https://github.com/") {
		return nil, refuse("snapshot repository is not a public GitHub URL")
	}
	sv.ObservedAt, _ = snap["observedAt"].(string)
	if !sealTimeRE.MatchString(sv.ObservedAt) {
		return nil, refuse("snapshot observedAt %q is not YYYY-MM-DDTHH:MM:SSZ", sv.ObservedAt)
	}
	switch snap["schema"] {
	case projectonboarding.SnapshotSchema:
		req, _ := snap["request"].(map[string]any)
		disc, _ := req["discovery"].(map[string]any)
		sv.ReqPrefix, _ = disc["tagPrefix"].(string)
		rels, _ := snap["releases"].([]any)
		for _, x := range rels {
			m, _ := x.(map[string]any)
			t, _ := m["tag"].(string)
			c, _ := m["commit"].(string)
			sv.Tags = append(sv.Tags, snapTag{Tag: t, Commit: c})
		}
	case projectonboarding.ExactTagSnapshotSchema:
		obs, _ := snap["tagObservations"].([]any)
		for _, x := range obs {
			m, _ := x.(map[string]any)
			t, _ := m["tag"].(string)
			c, _ := m["peeledCommit"].(string)
			sv.Tags = append(sv.Tags, snapTag{Tag: t, Commit: c})
		}
	default:
		return nil, refuse("unknown snapshot schema")
	}
	srcs, _ := snap["sources"].([]any)
	for _, x := range srcs {
		m, _ := x.(map[string]any)
		s, err := sourceOf(m, sv.RepoURL, true)
		if err != nil {
			return nil, err
		}
		sv.Sources = append(sv.Sources, s)
	}
	if lic, ok := snap["license"].(map[string]any); ok {
		s, err := sourceOf(lic, sv.RepoURL, false)
		if err != nil {
			return nil, err
		}
		sv.Lic = &s
	}
	return sv, nil
}

func sourceOf(m map[string]any, repoURL string, spans bool) (snapSource, error) {
	var s snapSource
	imm, _ := m["immutableURL"].(string)
	s.Commit, _ = m["commit"].(string)
	dig, _ := m["fileDigest"].(string)
	pre := repoURL + "/blob/" + s.Commit + "/"
	if !strings.HasPrefix(imm, pre) || !sealCommitRE.MatchString(s.Commit) {
		return s, refuse("snapshot source has an unexpected immutable URL")
	}
	s.Path = strings.TrimPrefix(imm, pre)
	if !buildPathRE.MatchString(s.Path) || strings.HasPrefix(s.Path, "/") || strings.Contains(s.Path, "//") {
		return s, refuse("snapshot source path %q is outside the allowed characters", s.Path)
	}
	for _, seg := range strings.Split(s.Path, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return s, refuse("snapshot source path %q has a dot segment", s.Path)
		}
	}
	s.Digest = strings.TrimPrefix(dig, "sha256:")
	if !strings.HasPrefix(dig, "sha256:") || !buildSHARE.MatchString(s.Digest) {
		return s, refuse("snapshot source digest is malformed")
	}
	if spans {
		sp, _ := m["spans"].([]any)
		if len(sp) != 1 {
			return s, refuse("snapshot source %s has %d spans, expected 1", s.Path, len(sp))
		}
		sm, _ := sp[0].(map[string]any)
		a, aok := sm["startLine"].(int64)
		b, bok := sm["endLine"].(int64)
		if !aok || !bok || a < 1 || b < a || b > 10000000 {
			return s, refuse("snapshot source %s has a malformed span", s.Path)
		}
		s.Start, s.End = int(a), int(b)
	}
	return s, nil
}

func parseVersion(tag string) (line string, ver [3]int, ok bool) {
	m := versionRE.FindStringSubmatch(tag)
	if m == nil {
		return "", ver, false
	}
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			ver[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return m[1] + "." + m[2], ver, true
}

func lessVer(a, b snapTag) bool {
	for i := 0; i < 3; i++ {
		if a.ver[i] != b.ver[i] {
			return a.ver[i] < b.ver[i]
		}
	}
	return a.Tag < b.Tag
}

func buildDocs(o BuildOptions, sv *snapView) (map[string]any, []string, string, error) {
	var notes []string
	check := checkNotRun
	if sv.Lic == nil {
		return nil, notes, check, refuse("snapshot has no licence file; nothing is written")
	}
	// Select tags.
	byTag := map[string]snapTag{}
	for _, t := range sv.Tags {
		if !buildTagRE.MatchString(t.Tag) || !sealCommitRE.MatchString(t.Commit) {
			return nil, notes, check, refuse("snapshot tag %q is malformed", t.Tag)
		}
		if _, dup := byTag[t.Tag]; dup {
			return nil, notes, check, refuse("snapshot lists tag %q twice", t.Tag)
		}
		byTag[t.Tag] = t
	}
	var sel []snapTag
	var ignoredNote string // set when --tag-prefix drops tags; recorded in scan-notes
	if len(o.Tags) == 0 {
		for _, t := range sv.Tags {
			sel = append(sel, t)
		}
	} else {
		seen := map[string]bool{}
		for _, name := range o.Tags {
			t, ok := byTag[name]
			if !ok {
				return nil, notes, check, refuse("--tags: %q is not a tag in the snapshot (no lookup is made)", name)
			}
			if seen[name] {
				return nil, notes, check, refuse("--tags: %q given twice", name)
			}
			seen[name] = true
			sel = append(sel, t)
		}
	}
	if o.TagPrefix != "" && len(o.Tags) == 0 {
		// The default window takes every tag; with a prefix, the tags
		// outside it (for example chart-release tags) are ignored.
		var pre []snapTag
		var ignored []string
		for _, t := range sel {
			if strings.HasPrefix(t.Tag, o.TagPrefix) {
				pre = append(pre, t)
			} else {
				ignored = append(ignored, t.Tag)
			}
		}
		if len(ignored) > 0 {
			sort.Strings(ignored)
			listed := ignored
			if len(listed) > 5 {
				listed = listed[:5]
			}
			ignoredNote = ignoredTagsNote(len(ignored), o.TagPrefix, listed)
			notes = append(notes, "note: "+ignoredNote)
		}
		sel = pre
		if len(sel) == 0 {
			return nil, notes, check, refuse("--tag-prefix %q matches no tag in the snapshot", o.TagPrefix)
		}
	}
	if len(sel) == 0 {
		return nil, notes, check, refuse("snapshot has no release tags")
	}
	commits := map[string]string{}
	for i := range sel {
		line, ver, ok := parseVersion(sel[i].Tag)
		if !ok {
			return nil, notes, check, refuse("cannot derive a release line (MAJOR.MINOR) from tag %q", sel[i].Tag)
		}
		sel[i].line, sel[i].ver = line, ver
		if other, dup := commits[sel[i].Commit]; dup {
			return nil, notes, check, refuse("tags %q and %q point at the same commit", other, sel[i].Tag)
		}
		commits[sel[i].Commit] = sel[i].Tag
	}
	// Newest first; keep the first tag of each line.
	sort.Slice(sel, func(i, j int) bool { return lessVer(sel[j], sel[i]) })
	var kept []snapTag
	lines := map[string]bool{}
	for _, t := range sel {
		if lines[t.line] {
			notes = append(notes, fmt.Sprintf("note: tag %s not used, line %s already has a newer tag", t.Tag, t.line))
			continue
		}
		lines[t.line] = true
		kept = append(kept, t)
	}
	if len(kept) > maxReleaseLines {
		return nil, notes, check, refuse("%d release lines, more than %d; choose with --tags", len(kept), maxReleaseLines)
	}
	// Tag prefix.
	prefix := o.TagPrefix
	if prefix != "" {
		for _, t := range kept {
			if !strings.HasPrefix(t.Tag, prefix) {
				return nil, notes, check, refuse("--tag-prefix %q is not a prefix of tag %q; drop that tag from --tags or change the prefix", prefix, t.Tag)
			}
		}
	} else {
		prefix = sv.ReqPrefix
		if prefix == "" {
			cand := leadingNonDigits(kept[0].Tag)
			for _, t := range kept {
				if leadingNonDigits(t.Tag) != cand {
					cand = "\x00"
					break
				}
			}
			if cand == "\x00" || !buildPrefixRE.MatchString(cand) {
				return nil, notes, check, refuse("tag prefix cannot be derived from the tags; give --tag-prefix")
			}
			prefix = cand
		}
		if !buildPrefixRE.MatchString(prefix) {
			return nil, notes, check, refuse("snapshot tag prefix %q is not allowed; give --tag-prefix", prefix)
		}
		for _, t := range kept {
			if !strings.HasPrefix(t.Tag, prefix) {
				return nil, notes, check, refuse("tag %q does not start with prefix %q; give --tag-prefix", t.Tag, prefix)
			}
		}
	}
	// minFrom: lowest built line.
	asc := make([]snapTag, len(kept))
	copy(asc, kept)
	sort.Slice(asc, func(i, j int) bool { return lessVer(asc[i], asc[j]) })
	minFrom := asc[0].line
	if o.MinFrom != "" {
		if !lines[o.MinFrom] {
			return nil, notes, check, refuse("--min-from %q is not one of the release lines built (%s)", o.MinFrom, strings.Join(lineList(kept), ", "))
		}
		minFrom = o.MinFrom
	}
	// Release notes rows: path -> pairs, from consecutive kept tags.
	bySource := map[string]map[string]snapSource{} // commit -> path -> source
	for _, s := range sv.Sources {
		if bySource[s.Commit] == nil {
			bySource[s.Commit] = map[string]snapSource{}
		}
		bySource[s.Commit][s.Path] = s
	}
	rows := map[string][]any{}
	for i := 1; i < len(asc); i++ {
		for p, s := range bySource[asc[i].Commit] {
			rows[p] = append(rows[p], map[string]any{
				"fromTag": asc[i-1].Tag, "toTag": asc[i].Tag, "present": true,
				"commit": s.Commit, "fileSha256": s.Digest, "startLine": s.Start, "endLine": s.End,
			})
		}
	}
	paths := make([]string, 0, len(rows))
	for p := range rows {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) > maxRelnoteRows {
		return nil, notes, check, refuse("%d changelog paths, more than %d", len(paths), maxRelnoteRows)
	}
	relRows := []any{}
	for _, p := range paths {
		pt, ok := o.PostTag[p]
		if !ok {
			return nil, notes, check, refuse("--post-tag or --no-post-tag is required for changelog path %s (it cannot be seen from the snapshot)", p)
		}
		relRows = append(relRows, map[string]any{"path": p, "form": "changelog", "postTag": pt, "pairs": rows[p]})
	}
	for _, p := range sortedKeys(o.PostTag) {
		if _, ok := rows[p]; !ok {
			return nil, notes, check, refuse("--post-tag/--no-post-tag names %q, which is not a changelog path of this bundle", p)
		}
	}
	if len(relRows) == 0 {
		notes = append(notes, "no changelog bytes in snapshot; relnotes-sources.json has no rows")
	}

	relLines := make([]any, 0, len(kept))
	for _, t := range kept {
		relLines = append(relLines, map[string]any{"line": t.line, "tag": t.Tag, "commit": t.Commit})
	}
	repo := strings.TrimPrefix(sv.RepoURL, "https://")
	status := "skeleton"
	if o.NoCRDs {
		status = "no-crds"
	}
	scan, err := scanEntries(o, sv, kept)
	if err != nil {
		return nil, notes, check, err
	}
	if ignoredNote != "" {
		// A typed "other" entry: the closed scan-notes schema has no other
		// place for a bundle-level note, and the receipt is not widened.
		scan = append(scan, map[string]any{"path": "tags-outside-tag-prefix", "class": "other", "note": ignoredNote, "evidence": []any{}})
	}
	var ti *targetInput
	if o.TargetInput != "" {
		if o.NoCRDs {
			return nil, notes, check, refuse("--target-input and --no-crds contradict each other")
		}
		if ti, err = loadTargetInput(o.TargetInput); err != nil {
			return nil, notes, check, err
		}
	}
	if !o.NoCRDs && (ti == nil || len(ti.paths) == 0) {
		return nil, notes, check, refuse("no CRD paths found: pass --no-crds if the project ships no CustomResourceDefinitions, or --target-input with its CRD paths")
	}
	docs := map[string]any{
		"project.json": map[string]any{
			"schema": "prufyx.io/onboard-bundle/v1", "kind": "project",
			"repo": repo, "slug": o.Slug,
			"licence": map[string]any{
				"path": sv.Lic.Path, "commit": sv.Lic.Commit, "sha256": sv.Lic.Digest, "spdxGuess": o.SPDX,
			},
			"tagPrefix": prefix, "releaseLines": relLines, "cncfStatusClaim": o.CNCF,
		},
		"relnotes-sources.json": map[string]any{
			"schema": "prufyx.io/onboard-bundle/v1", "kind": "relnotes-sources", "rows": relRows,
		},
		"scan-notes.json": map[string]any{
			"schema": "prufyx.io/onboard-bundle/v1", "kind": "scan-notes", "entries": scan,
		},
		"target-draft.json": map[string]any{
			"schema": "prufyx.io/onboard-bundle/v1", "kind": "target-draft", "status": status,
			"target": map[string]any{
				"project": o.Slug, "repo": repo, "tagPrefixes": []any{prefix}, "minFrom": minFrom,
				"paths": []any{}, "exclude": []any{},
			},
		},
	}
	if ti != nil {
		// The input only shapes the skeleton; status stays "skeleton".
		ti.apply(docs["target-draft.json"].(map[string]any))
		var why []string
		check, why = offlineTargetCheck(ti, repo, prefix, minFrom, kept, sv)
		if check == checkPass {
			notes = append(notes, "offline target check: pass (the declared target is consistent with the snapshot's tags and files; no path is verified to exist upstream; status stays skeleton)")
		} else {
			notes = append(notes, "offline target check: fail")
			for _, w := range why {
				notes = append(notes, "  - "+w)
			}
		}
	}
	return docs, notes, check, nil
}

// ignoredTagsNote builds the scan note for tags dropped by --tag-prefix. It
// drops listed names while more than one remains, then clips the final string
// itself to the schema note length (rune-safe), so a very long tag or prefix
// can never push it over the limit.
func ignoredTagsNote(n int, prefix string, listed []string) string {
	var note string
	for {
		note = fmt.Sprintf("%d tags outside --tag-prefix %q ignored (first: %s)", n, prefix, strings.Join(listed, ", "))
		if utf8.RuneCountInString(note) <= maxNoteRunes || len(listed) <= 1 {
			break
		}
		listed = listed[:len(listed)-1]
	}
	if r := []rune(note); len(r) > maxNoteRunes {
		note = string(r[:maxNoteRunes])
	}
	return note
}

func lineList(ts []snapTag) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.line)
	}
	return out
}

func leadingNonDigits(tag string) string {
	for i, r := range tag {
		if r >= '0' && r <= '9' {
			return tag[:i]
		}
	}
	return tag
}

// leakFindings runs the validator's secret and internal-name scans over every
// string before anything is written, so the refusal names the field.
func leakFindings(docs map[string]any) []string {
	var out []string
	for _, rel := range sortedKeys(docs) {
		var strs []pathString
		walkStrings(docs[rel], rel, &strs)
		for _, ps := range strs {
			for _, rx := range secretRE {
				if rx.MatchString(ps.val) {
					out = append(out, ps.path+": secret-shaped value")
				}
			}
			for _, rx := range internalRE {
				if rx.MatchString(ps.val) {
					out = append(out, ps.path+": internal/owner-environment name")
				}
			}
		}
	}
	return out
}

var snapshotTopFiles = map[string]bool{
	"PROJECT-ONBOARDING-SNAPSHOT.json": true,
	"SYNC-RECEIPT.json":                true,
	"SOURCE-CORPUS-MANIFEST.json":      true,
}

// checkSnapshotTree refuses a snapshot directory that holds anything the
// verified snapshot does not reference: an extra top-level entry, an extra
// object, or a non-regular file. VerifySnapshot checks what it reads; this
// closes the "extra file" case.
func checkSnapshotTree(dir string, referenced map[string][]byte) error {
	bad := func(what string) error {
		return refuse("--snapshot has %s; it must be exactly the output of \"project sync\"", what)
	}
	top, err := os.ReadDir(dir)
	if err != nil {
		return bad("an unreadable directory")
	}
	for _, e := range top {
		switch {
		case e.Name() == "objects" && e.IsDir():
		case snapshotTopFiles[e.Name()] && e.Type().IsRegular():
		default:
			return bad("an unexpected entry " + strconv.Quote(e.Name()))
		}
	}
	root := filepath.Join(dir, "objects")
	level, err := os.ReadDir(root)
	if err != nil {
		return bad("no objects directory")
	}
	for _, e := range level {
		if e.Name() != "sha256" || !e.IsDir() {
			return bad("an unexpected entry in objects/")
		}
	}
	objs, err := os.ReadDir(filepath.Join(root, "sha256"))
	if err != nil {
		return bad("no objects/sha256 directory")
	}
	for _, e := range objs {
		if !e.Type().IsRegular() || referenced["sha256:"+e.Name()] == nil {
			return bad("an object that no snapshot field references (" + strconv.Quote(e.Name()) + ")")
		}
	}
	return nil
}
