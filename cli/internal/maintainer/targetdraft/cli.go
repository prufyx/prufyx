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

const usage = "usage: prufyx-maintainer target-draft generate --dir CHECKOUT --slug SLUG --name NAME --repo github.com/OWNER/NAME --tags TAG[,TAG...] --out DIR [--catalog cncf|community] [--component PURL] [--fact-project ID] [--rules FILE] [--compare-a FILE] [--compare-b FILE]"

// Run implements "target-draft generate". Exit codes: 0 drafts written (and
// every given reviewed file equal), 1 typed stop or a difference from a
// reviewed file, 2 usage or I/O error. It never uses the network.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "generate" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	fl := flag.NewFlagSet("target-draft generate", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var dir, slug, name, repo, tags, out, catalog, component, fact, rulesPath, cmpA, cmpB string
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
		Tags: strings.Split(tags, ","), Source: GitSource{Dir: dir}, Rules: rules})
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
	for _, n := range names {
		p := filepath.Join(out, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			fmt.Fprintf(stderr, "target-draft: %v\n", err)
			return 2
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, err = f.Write(files[n])
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "target-draft: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "wrote %s\n", p)
	}
	status := 0
	for _, c := range []struct{ label, file string; got []byte }{{"A", cmpA, res.A}, {"B", cmpB, res.B}} {
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
		for _, d := range diffs {
			fmt.Fprintf(stdout, "DIFF %s: %s\n", c.label, d)
		}
		if len(diffs) > 0 {
			status = 1
		}
	}
	fmt.Fprintf(stdout, "target-draft: %s: %d CRDs in %d groups, minFrom %s, %d tags in the window\n", slug, res.Report.CRDCount, len(res.Report.Groups), res.Report.MinFrom, len(res.Report.Tags))
	return status
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
