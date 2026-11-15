// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// verify-pr: report-only regenerate check of a data PR. It reads the PR head
// and base as exported directories, never executes anything from them, never
// uses the network, and decides nothing: it reports whether the head files
// are exactly what the generator in THIS build produces from the recipe and
// the fact bundle the PR carries. It does not verify that the bundle comes
// from the real upstream repository; its output says so and never names a PR
// auto-merge eligible.

const (
	// RecipeSchema identifies the recipe document.
	RecipeSchema = "prufyx.io/target-recipe/v1"
	// RecipesRoot is the only tree a data PR may touch for this check.
	RecipesRoot = "cli/knowledge/target-recipes/"
	// MaxRecipeBytes bounds recipe.json and rules.json.
	MaxRecipeBytes = 256 << 10
	maxOutputBytes = 4 << 20
	maxChangedList = 4 << 20
	maxChangedPath = 1000

	upstreamBindingLine = "upstream binding: not verified (consistency check only; it does not show the facts come from the upstream repository)"
)

// Recipe holds everything the generator takes as flags. Nothing comes from
// the workflow or the PR text.
type Recipe struct {
	Schema              string         `json:"schema"`
	Slug                string         `json:"slug"`
	Name                string         `json:"name"`
	Repo                string         `json:"repo"`
	Catalog             string         `json:"catalog,omitempty"`
	Component           string         `json:"component,omitempty"`
	FactProject         string         `json:"factProject,omitempty"`
	Tags                []string       `json:"tags"`
	RangeCheckTags      []string       `json:"rangeCheckTags"`
	StrictWindow        bool           `json:"strictWindow"`
	CollapseDirectories bool           `json:"collapseDirectories"`
	Rules               string         `json:"rules"`
	Half                string         `json:"half"`
	Exclude             []string       `json:"exclude"`
	Commits             []recipeCommit `json:"commits"`
	FactBundleDigest    string         `json:"factBundleDigest"`
}

type recipeCommit struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

// VerifyFailure is a typed reason. Harness failures (unreadable input,
// usage) are exit 2; assertion failures are exit 1.
type VerifyFailure struct {
	Code    string
	Detail  string
	Harness bool
}

func (f *VerifyFailure) Error() string { return f.Code + ": " + f.Detail }

func fail(code, format string, a ...any) *VerifyFailure {
	return &VerifyFailure{Code: code, Detail: clip(fmt.Sprintf(format, a...))}
}

func harness(code, format string, a ...any) *VerifyFailure {
	f := fail(code, format, a...)
	f.Harness = true
	return f
}

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 300 {
		s = strings.ToValidUTF8(s[:300], "") + "..."
	}
	return s
}

// VerifyInput is one check: the exported base and head trees and the raw
// output of: git diff --raw -z --no-abbrev --no-renames BASE HEAD.
type VerifyInput struct {
	BaseDir    string
	HeadDir    string
	ChangedRaw []byte
}

// VerifyResult is the report of a passing run. AutoMerge is always false:
// this check never makes a PR eligible.
type VerifyResult struct {
	Slug         string
	Half         string
	RecipeChange string // new | unchanged | changed
	Checks       []string
	AutoMerge    bool
	Reasons      []string
}

type verifyEnv struct {
	generate func(Input) (*Result, error)
	compare  func(generated, reviewed []byte) ([]string, error)
}

func defaultVerifyEnv() verifyEnv {
	return verifyEnv{generate: Generate, compare: compareReviewed}
}

// parseChanged decodes the raw diff. Only added or modified regular files
// (mode 100644) are accepted; deletes, renames, copies, type and mode
// changes, links and submodules, and any malformed record fail.
func parseChanged(raw []byte) ([]string, *VerifyFailure) {
	if len(raw) == 0 {
		return nil, fail("no-changes", "the changed-path list is empty")
	}
	if len(raw) > maxChangedList {
		return nil, fail("changed-list-too-large", "over %d bytes", maxChangedList)
	}
	var paths []string
	seen := map[string]bool{}
	rest := raw
	for len(rest) > 0 {
		meta, r, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return nil, fail("changed-list-malformed", "record without terminator")
		}
		p, r2, ok := bytes.Cut(r, []byte{0})
		if !ok {
			return nil, fail("changed-list-malformed", "path without terminator")
		}
		rest = r2
		f := strings.Fields(string(meta))
		if len(f) != 5 || !strings.HasPrefix(f[0], ":") || len(f[2]) != 40 || len(f[3]) != 40 {
			return nil, fail("changed-list-malformed", "unexpected record %q", string(meta))
		}
		oldMode, newMode, status := f[0][1:], f[1], f[4]
		okAdd := status == "A" && oldMode == "000000" && newMode == "100644"
		okMod := status == "M" && oldMode == "100644" && newMode == "100644"
		if !okAdd && !okMod {
			return nil, fail("path-status", "%q: only added or modified regular files (100644) are accepted, got status %s modes %s->%s", string(p), status, oldMode, newMode)
		}
		if !utf8.Valid(p) {
			return nil, fail("path-not-allowed", "path is not valid UTF-8")
		}
		sp := string(p)
		if seen[sp] {
			return nil, fail("changed-list-malformed", "duplicate path %q", sp)
		}
		seen[sp] = true
		paths = append(paths, sp)
		if len(paths) > maxChangedPath {
			return nil, fail("changed-list-too-large", "over %d paths", maxChangedPath)
		}
	}
	return paths, nil
}

func allowedFiles(slug string) map[string]bool {
	return map[string]bool{
		"recipe.json": true, "rules.json": true, "facts.bundle": true,
		"report.json": true, "table-row.json": true, "changelog.md": true,
		"target-" + slug + ".json": true,
	}
}

// checkAllowlist derives the one slug from the changed paths. Anything
// outside RecipesRoot/<slug>/<known file> fails, as does more than one slug.
func checkAllowlist(paths []string) (string, *VerifyFailure) {
	slug := ""
	for _, p := range paths {
		rest, ok := strings.CutPrefix(p, RecipesRoot)
		if !ok {
			return "", fail("path-not-allowed", "%q is outside %s", p, RecipesRoot)
		}
		parts := strings.Split(rest, "/")
		if len(parts) != 2 || !slugRE.MatchString(parts[0]) {
			return "", fail("path-not-allowed", "%q is not %s<slug>/<file>", p, RecipesRoot)
		}
		if !allowedFiles(parts[0])[parts[1]] {
			return "", fail("path-not-allowed", "%q is not a known recipe file", p)
		}
		if slug != "" && slug != parts[0] {
			return "", fail("multiple-slugs", "more than one slug changed (%s, %s)", slug, parts[0])
		}
		slug = parts[0]
	}
	if slug == "" {
		return "", fail("no-changes", "no changed path")
	}
	return slug, nil
}

// lstatRegular fails unless every component below root is a real directory
// (never a link) and the last is a regular file (or a directory when dir).
func lstatPath(root, rel string, wantDir bool) (os.FileInfo, error) {
	cur := root
	var st os.FileInfo
	for _, c := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, c)
		var err error
		st, err = os.Lstat(cur)
		if err != nil {
			return nil, err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symbolic link", rel)
		}
	}
	if wantDir && !st.IsDir() || !wantDir && !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not the expected file type", rel)
	}
	return st, nil
}

func readLimited(root, rel string, limit int64) ([]byte, error) {
	st, err := lstatPath(root, rel, false)
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is over %d bytes", rel, limit)
	}
	f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", rel, limit)
	}
	return b, nil
}

// ParseRecipe reads a recipe strictly.
func ParseRecipe(raw []byte) (*Recipe, error) {
	if len(raw) > MaxRecipeBytes {
		return nil, fmt.Errorf("recipe is over %d bytes", MaxRecipeBytes)
	}
	var r Recipe
	if err := strictDecode(raw, &r); err != nil {
		return nil, fmt.Errorf("recipe: %w", err)
	}
	if r.Schema != RecipeSchema {
		return nil, fmt.Errorf("recipe: schema %q is not %s", r.Schema, RecipeSchema)
	}
	if !slugRE.MatchString(r.Slug) || r.Name == "" {
		return nil, errors.New("recipe: slug or name is malformed")
	}
	if len(r.Tags) == 0 {
		return nil, errors.New("recipe: no tags")
	}
	want := map[string]bool{}
	for _, t := range append(append([]string(nil), r.Tags...), r.RangeCheckTags...) {
		if !tagNameRE.MatchString(t) {
			return nil, fmt.Errorf("recipe: tag %q is malformed", t)
		}
		// A tag in both lists is allowed; a tag twice in one list is not.
		want[t] = true
	}
	for _, l := range [][]string{r.Tags, r.RangeCheckTags} {
		seen := map[string]bool{}
		for _, t := range l {
			if seen[t] {
				return nil, fmt.Errorf("recipe: tag %q is listed twice", t)
			}
			seen[t] = true
		}
	}
	if len(want) > MaxBundleTags {
		return nil, fmt.Errorf("recipe: more than %d tags", MaxBundleTags)
	}
	if r.Rules != "" && r.Rules != "rules.json" {
		return nil, errors.New(`recipe: rules must be "" or "rules.json"`)
	}
	if r.Half != "A" && r.Half != "B" {
		return nil, errors.New(`recipe: half must be "A" or "B"`)
	}
	if len(r.Exclude) != 0 {
		return nil, errors.New("recipe: exclude must be empty (exclusions are judgment and need human review)")
	}
	if len(r.Commits) != len(want) {
		return nil, errors.New("recipe: commits must name exactly the tags and rangeCheckTags")
	}
	for i, c := range r.Commits {
		if !want[c.Tag] || !sha1HexRE.MatchString(c.Commit) {
			return nil, fmt.Errorf("recipe: commit entry for %q is malformed", c.Tag)
		}
		if i > 0 && r.Commits[i-1].Tag >= c.Tag {
			return nil, errors.New("recipe: commits are not sorted and unique by tag")
		}
	}
	if !sha256HexRE.MatchString(r.FactBundleDigest) {
		return nil, errors.New("recipe: factBundleDigest is malformed")
	}
	return &r, nil
}

func sha256Of(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// VerifyPR runs the report-only regenerate check.
func VerifyPR(in VerifyInput) (*VerifyResult, *VerifyFailure) {
	return verifyPR(in, defaultVerifyEnv())
}

func readHead(root, rel string, limit int64) ([]byte, *VerifyFailure) {
	b, err := readLimited(root, rel, limit)
	if err == nil {
		return b, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fail("file-missing", "%s", rel)
	}
	return nil, fail("file-unreadable", "%s: %v", rel, err)
}

func verifyPR(in VerifyInput, env verifyEnv) (*VerifyResult, *VerifyFailure) {
	paths, f := parseChanged(in.ChangedRaw)
	if f != nil {
		return nil, f
	}
	slug, f := checkAllowlist(paths)
	if f != nil {
		return nil, f
	}
	res := &VerifyResult{Slug: slug, Reasons: []string{"upstream binding: not verified"}}
	res.Checks = append(res.Checks, "changed paths inside the recipe directory, one slug, added or modified regular files only")

	dirRel := strings.TrimSuffix(RecipesRoot, "/") + "/" + slug
	if _, err := lstatPath(in.HeadDir, dirRel, true); err != nil {
		return nil, fail("file-missing", "recipe directory: %v", err)
	}
	ents, err := os.ReadDir(filepath.Join(in.HeadDir, filepath.FromSlash(dirRel)))
	if err != nil {
		return nil, harness("file-unreadable", "%v", err)
	}
	allowed := allowedFiles(slug)
	for _, e := range ents {
		if !allowed[e.Name()] || !e.Type().IsRegular() {
			return nil, fail("path-not-allowed", "head recipe directory holds %q, which is not an allowed regular file", e.Name())
		}
	}

	recipeRaw, f := readHead(in.HeadDir, dirRel+"/recipe.json", MaxRecipeBytes)
	if f != nil {
		return nil, f
	}
	rc, err := ParseRecipe(recipeRaw)
	if err != nil {
		return nil, fail("recipe-invalid", "%v", err)
	}
	if rc.Slug != slug {
		return nil, fail("recipe-slug-mismatch", "recipe names %q, path names %q", rc.Slug, slug)
	}
	var rules *Rules
	var rulesRaw []byte
	_, rulesPresent := lstatPath(in.HeadDir, dirRel+"/rules.json", false)
	if (rc.Rules == "rules.json") != (rulesPresent == nil) {
		return nil, fail("recipe-invalid", "rules.json and the recipe's rules field disagree")
	}
	if rc.Rules != "" {
		if rulesRaw, f = readHead(in.HeadDir, dirRel+"/rules.json", MaxRecipeBytes); f != nil {
			return nil, f
		}
		if rules, err = ParseRules(rulesRaw); err != nil {
			return nil, fail("rules-invalid", "%v", err)
		}
		if len(rules.Exclusions) != 0 {
			return nil, fail("exclusion-present", "rules carry %d exclusion(s); exclusions need human review", len(rules.Exclusions))
		}
	}
	res.Checks = append(res.Checks, "recipe and rules parse strictly; no exclusions")

	bundleRaw, f := readHead(in.HeadDir, dirRel+"/facts.bundle", MaxBundleBytes)
	if f != nil {
		return nil, f
	}
	if sha256Of(bundleRaw) != rc.FactBundleDigest {
		return nil, fail("bundle-digest", "facts.bundle does not match the recipe's factBundleDigest")
	}
	bundle, err := ParseBundle(bundleRaw)
	if err != nil {
		return nil, fail("bundle-invalid", "%v", err)
	}
	bt := bundle.Tags()
	if len(bt) != len(rc.Commits) {
		return nil, fail("bundle-tags", "bundle holds %d tags, recipe names %d", len(bt), len(rc.Commits))
	}
	for _, c := range rc.Commits {
		got, ok := bundle.Commit(c.Tag)
		if !ok || got != c.Commit {
			return nil, fail("bundle-commit", "tag %s: recipe commit is not the bundle's commit", c.Tag)
		}
	}
	res.Checks = append(res.Checks, "bundle digest, every object hash, commit and tree chains, and the recipe's per-tag commits")

	claimed, f := readHead(in.HeadDir, dirRel+"/target-"+slug+".json", maxOutputBytes)
	if f != nil {
		return nil, f
	}
	claimedReport, f := readHead(in.HeadDir, dirRel+"/report.json", maxOutputBytes)
	if f != nil {
		return nil, f
	}
	claimedRow, f := readHead(in.HeadDir, dirRel+"/table-row.json", maxOutputBytes)
	if f != nil {
		return nil, f
	}
	claimedLog, f := readHead(in.HeadDir, dirRel+"/changelog.md", maxOutputBytes)
	if f != nil {
		return nil, f
	}
	doc, err := decodeDoc(claimed)
	if err != nil {
		return nil, fail("target-invalid", "%v", err)
	}
	if len(doc.Target.Exclude) != 0 {
		return nil, fail("exclusion-present", "the target carries %d exclusion(s)", len(doc.Target.Exclude))
	}

	mk := func() Input {
		return Input{Slug: rc.Slug, Name: rc.Name, Repo: rc.Repo, Component: rc.Component, FactProject: rc.FactProject, Catalog: rc.Catalog,
			Tags: append([]string(nil), rc.Tags...), RangeCheckTags: append([]string(nil), rc.RangeCheckTags...),
			Source: FactSource{B: bundle}, Rules: rules, StrictWindow: rc.StrictWindow, CollapseDirectories: rc.CollapseDirectories}
	}
	run := func() (r *Result, rep []byte, f *VerifyFailure) {
		defer func() {
			if p := recover(); p != nil {
				f = fail("generator-panic", "%v", p)
			}
		}()
		out, err := env.generate(mk())
		if err != nil {
			var se *StopError
			if errors.As(err, &se) {
				codes := make([]string, 0, len(se.Stops))
				for _, s := range se.Stops {
					codes = append(codes, s.Code)
				}
				return nil, nil, fail("typed-stop", "%d typed stop(s): %s", len(se.Stops), strings.Join(codes, ","))
			}
			return nil, nil, fail("generate-error", "%v", err)
		}
		rb, err := marshal(out.Report)
		if err != nil {
			return nil, nil, harness("report-marshal", "%v", err)
		}
		return out, rb, nil
	}
	r1, rep1, f := run()
	if f != nil {
		return nil, f
	}
	r2, rep2, f := run()
	if f != nil {
		return nil, f
	}
	if !bytes.Equal(r1.A, r2.A) || !bytes.Equal(r1.B, r2.B) || !bytes.Equal(r1.TableRow, r2.TableRow) || !bytes.Equal(r1.Changelog, r2.Changelog) || !bytes.Equal(rep1, rep2) {
		return nil, fail("non-deterministic", "two regenerations differ")
	}
	res.Checks = append(res.Checks, "regeneration from the bundle has zero typed stops and is byte-identical on a second run")

	for _, t := range r1.Report.Tags {
		var want string
		for _, c := range rc.Commits {
			if c.Tag == t.Tag {
				want = c.Commit
			}
		}
		if want != t.Commit {
			return nil, fail("report-commit", "tag %s: generated commit differs from the recipe", t.Tag)
		}
	}
	gen := r1.A
	if rc.Half == "B" {
		gen = r1.B
	}
	if gd, err := decodeDoc(gen); err != nil || len(gd.Target.Exclude) != 0 {
		return nil, fail("exclusion-present", "the regenerated target is unreadable or carries exclusions")
	}
	if !bytes.Equal(claimed, gen) {
		diffs, derr := env.compare(gen, claimed)
		if derr != nil {
			diffs = []string{derr.Error()}
		}
		if len(diffs) > 3 {
			diffs = diffs[:3]
		}
		return nil, fail("target-differs", "target-%s.json is not the regenerated half %s byte for byte (%s)", slug, rc.Half, strings.Join(diffs, "; "))
	}
	if !bytes.Equal(claimedReport, rep1) {
		return nil, fail("report-differs", "report.json is not the regenerated report byte for byte")
	}
	if !bytes.Equal(claimedRow, r1.TableRow) {
		return nil, fail("table-row-differs", "table-row.json is not the regenerated row byte for byte")
	}
	if !bytes.Equal(claimedLog, r1.Changelog) {
		return nil, fail("changelog-differs", "changelog.md is not the regenerated changelog byte for byte")
	}
	res.Checks = append(res.Checks, "target, report, table row and changelog are byte-identical to the regeneration")

	for _, kind := range []string{"path", "min-from", "attest"} {
		wrong, err := seedExpected(btSeed{Kind: kind}, claimed, nil)
		if err != nil {
			return nil, harness("seed-cannot-run", "seed %s: %v", kind, err)
		}
		if bytes.Equal(wrong, claimed) {
			return nil, harness("seed-cannot-run", "seed %s did not change the target", kind)
		}
		diffs, err := env.compare(gen, wrong)
		if err != nil {
			return nil, harness("seed-cannot-run", "seed %s: the comparison failed", kind)
		}
		if len(diffs) == 0 {
			return nil, fail("seed-reproduced", "the wrong target of seed %s reproduced; the comparison is vacuous here", kind)
		}
	}
	res.Checks = append(res.Checks, "wrong-target seeds (path, min-from, attest) are rejected by the same comparison")

	res.RecipeChange = "new"
	if b, err := readLimited(in.BaseDir, dirRel+"/recipe.json", MaxRecipeBytes); err == nil {
		res.RecipeChange = "unchanged"
		if !bytes.Equal(b, recipeRaw) {
			res.RecipeChange = "changed"
		}
		br, err := readLimited(in.BaseDir, dirRel+"/rules.json", MaxRecipeBytes)
		switch {
		case err == nil && !bytes.Equal(br, rulesRaw), errors.Is(err, os.ErrNotExist) && rulesRaw != nil:
			res.RecipeChange = "changed"
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return nil, harness("base-unreadable", "%v", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, harness("base-unreadable", "%v", err)
	}
	if res.RecipeChange != "unchanged" {
		res.Reasons = append(res.Reasons, "recipe is "+res.RecipeChange+" against base (judgment; human review)")
	}
	res.Half = rc.Half
	return res, nil
}

const verifyUsage = "usage: prufyx-maintainer target-draft verify-pr --base DIR --head DIR --changed-paths FILE\n" +
	"report only: DIR are exported trees of the PR base and head; FILE is the output of: git diff --raw -z --no-abbrev --no-renames BASE HEAD. Exit 0 assertions held, 1 an assertion failed (typed reason), 2 usage or I/O error. Offline. It never names a PR auto-merge eligible and says: upstream binding not verified."

func runVerifyPR(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("target-draft verify-pr", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var base, head, changed string
	fl.StringVar(&base, "base", "", "")
	fl.StringVar(&head, "head", "", "")
	fl.StringVar(&changed, "changed-paths", "", "")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || base == "" || head == "" || changed == "" {
		fmt.Fprintln(stderr, verifyUsage)
		return 2
	}
	raw, err := os.ReadFile(changed)
	if err != nil {
		fmt.Fprintf(stderr, "verify-pr: %v\n", err)
		return 2
	}
	res, f := VerifyPR(VerifyInput{BaseDir: base, HeadDir: head, ChangedRaw: raw})
	fmt.Fprintln(stdout, upstreamBindingLine)
	if f != nil {
		fmt.Fprintf(stdout, "FAIL %s: %s\n", f.Code, f.Detail)
		fmt.Fprintln(stdout, "auto-merge: not eligible")
		if f.Harness {
			return 2
		}
		return 1
	}
	sort.Strings(res.Reasons[1:])
	for _, c := range res.Checks {
		fmt.Fprintf(stdout, "ok: %s\n", c)
	}
	fmt.Fprintf(stdout, "slug %s, half %s, recipe %s against base\n", res.Slug, res.Half, res.RecipeChange)
	fmt.Fprintf(stdout, "auto-merge: not eligible: %s\n", strings.Join(res.Reasons, "; "))
	fmt.Fprintln(stdout, "verify-pr: report-only; assertions held")
	return 0
}
