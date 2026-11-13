// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Diff compares a generated target with a reviewed one and lists every
// difference (empty when they are equal apart from whitespace). It is the
// comparison that catches a seeded wrong target: a path, an exclusion or a
// scalar field that differs is named.
func Diff(generated, reviewed []byte) ([]string, error) {
	g, err := decodeDoc(generated)
	if err != nil {
		return nil, fmt.Errorf("generated: %w", err)
	}
	r, err := decodeDoc(reviewed)
	if err != nil {
		return nil, fmt.Errorf("reviewed: %w", err)
	}
	var out []string
	scalar := func(name, a, b string) {
		if a != b {
			out = append(out, fmt.Sprintf("field %s: generated %q, reviewed %q", name, a, b))
		}
	}
	gt, rt := g.Target, r.Target
	scalar("schema", g.Schema, r.Schema)
	scalar("project", gt.Project, rt.Project)
	scalar("catalog", gt.Catalog, rt.Catalog)
	scalar("name", gt.Name, rt.Name)
	scalar("repo", gt.Repo, rt.Repo)
	scalar("component", gt.Component, rt.Component)
	scalar("factProject", gt.FactProject, rt.FactProject)
	scalar("tagPrefixes", strings.Join(gt.TagPrefixes, ","), strings.Join(rt.TagPrefixes, ","))
	scalar("minFrom", gt.MinFrom, rt.MinFrom)
	scalar("attest", fmt.Sprint(gt.Attest), fmt.Sprint(rt.Attest))
	gp, rp := []string{}, []string{}
	for _, p := range gt.Paths {
		gp = append(gp, p.Path)
	}
	for _, p := range rt.Paths {
		rp = append(rp, p.Path)
	}
	out = append(out, setDiff("path", gp, rp)...)
	if len(out) == 0 && strings.Join(gp, "\n") != strings.Join(rp, "\n") {
		out = append(out, "paths: same set in a different order")
	}
	ge, re := map[string]exclOut{}, map[string]exclOut{}
	var gk, rk []string
	for _, e := range gt.Exclude {
		ge[e.Path] = e
		gk = append(gk, e.Path)
	}
	for _, e := range rt.Exclude {
		re[e.Path] = e
		rk = append(rk, e.Path)
	}
	out = append(out, setDiff("exclude", gk, rk)...)
	for _, k := range gk {
		if x, ok := re[k]; ok && x != ge[k] {
			out = append(out, "exclude "+k+": text differs")
		}
	}
	sort.Strings(out)
	return out, nil
}

func decodeDoc(raw []byte) (targetDoc, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d targetDoc
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return d, errors.New("trailing data")
	}
	return d, nil
}

func setDiff(label string, generated, reviewed []string) []string {
	gs, rs := map[string]bool{}, map[string]bool{}
	for _, s := range generated {
		gs[s] = true
	}
	for _, s := range reviewed {
		rs[s] = true
	}
	var out []string
	for s := range rs {
		if !gs[s] {
			out = append(out, label+" missing from generated: "+s)
		}
	}
	for s := range gs {
		if !rs[s] {
			out = append(out, label+" extra in generated: "+s)
		}
	}
	return out
}

const usage = "usage: prufyx-maintainer target-draft generate --dir CHECKOUT --slug SLUG --name NAME --repo github.com/OWNER/NAME --tags TAG[,TAG...] --out DIR [--catalog cncf|community] [--component PURL] [--fact-project ID] [--rules FILE] [--compare-a FILE] [--compare-b FILE] [--compare-report FILE] [--strict-window]\n" +
	"the targets are embedded in the extractor and covered by its code digest, so a reviewed target equals the draft only when the bytes are equal; --compare-a and --compare-b report any byte difference (a whitespace-only one too) and --compare-report compares the facts digest of a reviewed report.json; an optional installPaths list in the rules file names the only source files or directories (path ending in /) of the target, each with a reason and evidence; every other definition file is reported as a non-install-copy in report.json (path, groups, count) and is not read, an entry that matches no definition file at a tag is the stop install-path-matches-nothing, an optional pathFilter list (anchored globs with only * inside one path segment, each with a reason, evidence and a required expectFiles, the exact number of files the entry matches at every tag, a positive integer the rules author pins from reviewed evidence; it needs installPaths) removes matching files under installPaths from the install surface and reports each in report.json as a filtered-copy (path, groups, tags); a filter that matches nothing at a tag is the stop path-filter-matches-nothing, a different file count than expectFiles is path-filter-count-mismatch, a filter never hides an unreadable file; a filtered file is allowed only when every group it defines is a reserved or Kubernetes group or has a known other owner in the ownership index, a group the target reads or the index lists for this project is the stop filter-hides-owned-group and a group with no single known owner is filter-hides-unowned-group; an installPaths entry may carry optional:true (an exact definition file, never a directory) with absentTags naming the tags of the window where its absence is proven: at such a tag the entry is tolerated only on verified true absence from the full local git tree (lazy fetch disabled), a symbolic link, submodule, unreadable or opaque tree entry or a file as parent directory is a stop (optional-path-link, optional-path-unverifiable), a file present at a listed tag is optional-path-present-at-absent-tag, and absence at the newest tag is optional-absent-at-newest; report.json lists per tag whether each optional entry was read or verified-absent and the facts digest covers it; a rules file without installPaths behaves as before; a shrunk window (older tags withheld) is a WARNING window-shrunk and exit 0, a typed stop window-shortened with --strict-window"

// Run implements "target-draft generate". Exit codes: 0 drafts written (and
// every given reviewed file equal), 1 typed stop or a difference from a
// reviewed file, 2 usage or I/O error. It never uses the network.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, func(dir string) Source { return GitSource{Dir: dir} })
}

func run(args []string, stdout, stderr io.Writer, open func(dir string) Source) int {
	if len(args) == 0 || args[0] != "generate" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	fl := flag.NewFlagSet("target-draft generate", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var dir, slug, name, repo, tags, out, catalog, component, fact, rulesPath, cmpA, cmpB, cmpRep string
	var strict bool
	fl.StringVar(&dir, "dir", "", "")
	fl.StringVar(&slug, "slug", "", "")
	fl.StringVar(&name, "name", "", "")
	fl.StringVar(&repo, "repo", "", "")
	fl.StringVar(&tags, "tags", "", "")
	fl.StringVar(&out, "out", "", "")
	fl.StringVar(&catalog, "catalog", "", "")
	fl.StringVar(&component, "component", "", "")
	fl.StringVar(&fact, "fact-project", "", "")
	fl.StringVar(&rulesPath, "rules", "", "")
	fl.StringVar(&cmpA, "compare-a", "", "")
	fl.StringVar(&cmpB, "compare-b", "", "")
	fl.StringVar(&cmpRep, "compare-report", "", "")
	fl.BoolVar(&strict, "strict-window", false, "")
	if err := fl.Parse(args[1:]); err != nil || fl.NArg() != 0 || dir == "" || slug == "" || name == "" || repo == "" || tags == "" || out == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var rules *Rules
	if rulesPath != "" {
		raw, err := readBounded(rulesPath)
		if err == nil {
			rules, err = ParseRules(raw)
		}
		if err != nil {
			fmt.Fprintf(stderr, "target-draft: %v\n", err)
			return 2
		}
	}
	if st, err := os.Stat(out); err == nil {
		if !st.IsDir() {
			fmt.Fprintln(stderr, "target-draft: --out exists and is not a directory")
			return 2
		}
		ents, err := os.ReadDir(out)
		if err != nil || len(ents) > 0 {
			fmt.Fprintln(stderr, "target-draft: --out must be an empty directory")
			return 2
		}
	}
	res, err := Generate(Input{Slug: slug, Name: name, Repo: repo, Component: component, FactProject: fact, Catalog: catalog,
		Tags: strings.Split(tags, ","), Source: open(dir), Rules: rules, StrictWindow: strict})
	if err != nil {
		var se *StopError
		if errors.As(err, &se) {
			fmt.Fprintln(stdout, se.Error())
			fmt.Fprintf(stdout, "target-draft: %d typed stop(s); no draft written\n", len(se.Stops))
			return 1
		}
		fmt.Fprintf(stderr, "target-draft: %v\n", err)
		return 2
	}
	rep, err := marshal(res.Report)
	if err != nil {
		fmt.Fprintf(stderr, "target-draft: %v\n", err)
		return 2
	}
	files := map[string][]byte{
		"a/target-" + slug + ".json": res.A,
		"a/table-row.json":           res.TableRow,
		"b/target-" + slug + ".json": res.B,
		"b/changelog.md":             res.Changelog,
		"report.json":                rep,
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	// Compare first, then write everything into a temporary directory next
	// to --out and rename it, so a failed run leaves --out absent or empty.
	status := 0
	for _, c := range []struct {
		label, file string
		got         []byte
	}{{"A", cmpA, res.A}, {"B", cmpB, res.B}} {
		if c.file == "" {
			continue
		}
		raw, err := readBounded(c.file)
		if err != nil {
			fmt.Fprintf(stderr, "target-draft: %v\n", err)
			return 2
		}
		diffs, err := Diff(c.got, raw)
		if err != nil {
			fmt.Fprintf(stderr, "target-draft: %v\n", err)
			return 2
		}
		if len(diffs) == 0 && !bytes.Equal(c.got, raw) {
			diffs = []string{"bytes differ although the structure is equal (whitespace or order); the embedded file would get another code digest"}
		}
		for _, d := range diffs {
			fmt.Fprintf(stdout, "DIFF %s: %s\n", c.label, d)
		}
		if len(diffs) > 0 {
			status = 1
		}
	}
	if cmpRep != "" {
		raw, err := readBounded(cmpRep)
		var rr struct {
			FactsDigest string `json:"factsDigest"`
		}
		if err == nil {
			err = json.Unmarshal(raw, &rr)
		}
		if err != nil || rr.FactsDigest == "" {
			fmt.Fprintf(stderr, "target-draft: --compare-report: need a report.json with a factsDigest (%v)\n", err)
			return 2
		}
		if rr.FactsDigest != res.Report.FactsDigest {
			fmt.Fprintf(stdout, "DIFF facts: generated %s, reviewed %s\n", res.Report.FactsDigest, rr.FactsDigest)
			status = 1
		}
	}
	if status != 0 {
		fmt.Fprintln(stdout, "target-draft: differs from the reviewed files; no draft written")
		return status
	}
	if err := writeAtomic(out, names, files); err != nil {
		fmt.Fprintf(stderr, "target-draft: %v\n", err)
		return 2
	}
	for _, n := range names {
		fmt.Fprintf(stdout, "wrote %s\n", filepath.Join(out, filepath.FromSlash(n)))
	}
	if len(res.Report.Dropped) > 0 {
		fmt.Fprintf(stdout, "WARNING window-shrunk: %d older tag(s) withheld, minFrom is %s (see droppedTags in report.json)\n", len(res.Report.Dropped), res.Report.MinFrom)
	}
	fmt.Fprintf(stdout, "target-draft: %s: %d CRDs in %d groups, minFrom %s, %d tags in the window\n", slug, res.Report.CRDCount, len(res.Report.Groups), res.Report.MinFrom, len(res.Report.Tags))
	return 0
}

// writeAtomic writes every file below a temporary directory beside out and
// renames it to out (an existing empty out is replaced). On any error the
// temporary directory is removed and out is left as it was.
func writeAtomic(out string, names []string, files map[string][]byte) error {
	parent := filepath.Dir(filepath.Clean(out))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".target-draft-")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	for _, n := range names {
		p := filepath.Join(tmp, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, files[n], 0o644); err != nil {
			return err
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if st, err := os.Stat(out); err == nil && st.IsDir() {
		if err := os.Remove(out); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, out); err != nil {
		return err
	}
	ok = true
	return nil
}

func readBounded(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 4<<20 {
		return nil, fmt.Errorf("%s: over 4 MiB", p)
	}
	return b, nil
}
