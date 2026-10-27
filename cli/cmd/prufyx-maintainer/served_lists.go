// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/extract/safefs"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/servedlists"
)

const servedListsUsage = "served-lists build: usage: prufyx-maintainer served-lists build --pack FILE --lines 1.19-1.37|1.30,1.31 --now RFC3339 [--source github|fixture:DIR] [--timeout DURATION]"

// Bounds of the build command.
const (
	maxServedBuildLines = 64
	maxServedPackBytes  = 64 << 20
	// servedBuildRESTCap bounds the api.github.com requests of one run: a
	// line costs a few (commit and tree lookups), so 19 lines stay far
	// below it, and a run that loops cannot burn the rate limit.
	servedBuildRESTCap = 400
	servedSchemaLevels = 12
)

// servedSource is the upstream a build reads: the repository's tags and
// pinned bytes.
type servedSource interface {
	extract.PinnedReader
	extract.TagSource
}

// servedListsDeps are the seams of the command; tests replace them.
type servedListsDeps struct {
	// source returns the upstream named by --source.
	source func(spec string) (servedSource, error)
	// admit admits the rendered pack with the engine loader of its family.
	admit func(packPath string, raw []byte) error
}

func runServedLists(args []string, stdout, stderr io.Writer) error {
	return runServedListsWith(args, stdout, servedListsDeps{source: servedListsSource, admit: extractpack.AdmitFiles})
}

// servedListsSource is --source: github reads straight from GitHub (an
// optional GITHUB_TOKEN or GH_TOKEN only raises the rate limit), fixture:DIR
// reads an offline tree in the layout of extract.FixtureReader.
func servedListsSource(spec string) (servedSource, error) {
	switch {
	case spec == "github":
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}
		return &knowledgegate.GitHubSource{Token: token, MaxRESTRequests: servedBuildRESTCap}, nil
	case strings.HasPrefix(spec, "fixture:") && len(spec) > len("fixture:"):
		return extract.FixtureReader{Root: strings.TrimPrefix(spec, "fixture:")}, nil
	}
	return nil, errors.New("--source must be github or fixture:DIR")
}

// onceTags answers the tag list from one read: every line of a run resolves
// its release tag from the same list.
type onceTags struct {
	src  extract.TagSource
	tags []extract.Tag
	err  error
	done bool
}

func (o *onceTags) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	if !o.done {
		o.tags, o.err = o.src.Tags(repo)
		o.done = true
	}
	return o.tags, o.err
}

func runServedListsWith(args []string, stdout io.Writer, deps servedListsDeps) error {
	if len(args) == 0 || args[0] != "build" {
		return &commandError{code: 2, message: servedListsUsage}
	}
	flags := flag.NewFlagSet("served-lists build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packPath := flags.String("pack", "", "CNCF rule pack file to update (required)")
	linesText := flags.String("lines", "", "lines to build: a range 1.19-1.37 or exact lines 1.30,1.31 (required)")
	nowText := flags.String("now", "", "derivation time, RFC 3339 whole seconds (required)")
	source := flags.String("source", "github", "upstream: github or fixture:DIR")
	timeout := flags.Duration("timeout", 15*time.Minute, "overall time limit")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *packPath == "" || *linesText == "" || *nowText == "" || *timeout <= 0 {
		return &commandError{code: 2, message: servedListsUsage, err: err}
	}
	now, err := time.Parse(time.RFC3339, *nowText)
	if err != nil || !now.Equal(now.Truncate(time.Second)) {
		return &commandError{code: 2, message: "served-lists build: --now must be RFC 3339 in whole seconds", err: err}
	}
	now = now.UTC()
	raw, err := readServedPack(*packPath)
	if err != nil {
		return &commandError{code: 2, message: "served-lists build: " + err.Error(), err: err}
	}
	pack, err := extractpack.ParsePack(raw)
	if err != nil {
		return &commandError{code: 2, message: "served-lists build: " + err.Error(), err: err}
	}
	covered, err := coveredKubernetesLines(pack)
	if err != nil {
		return &commandError{code: 2, message: "served-lists build: " + err.Error(), err: err}
	}
	lines, err := parseServedLines(*linesText, covered)
	if err != nil {
		return &commandError{code: 2, message: "served-lists build: " + err.Error(), err: err}
	}
	src, err := deps.source(*source)
	if err != nil {
		return &commandError{code: 2, message: "served-lists build: " + err.Error(), err: err}
	}
	if c, ok := src.(io.Closer); ok {
		defer c.Close() // removes the git reader's scratch directory
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	// Sequential, and the first failure stops the run: nothing is written
	// unless every requested line was derived.
	tags := &onceTags{src: src}
	built := make([]servedapis.Record, 0, len(lines))
	for _, line := range lines {
		rec, err := servedlists.Build(ctx, tags, src, line, now)
		if err != nil {
			return &commandError{code: 1, message: fmt.Sprintf("served-lists build: line %s: %v", line, err), err: err}
		}
		built = append(built, rec)
	}
	out, schemaFrom, schemaTo, err := renderServedPack(pack, raw, built, *packPath, deps.admit)
	if err != nil {
		return &commandError{code: 1, message: "served-lists build: " + err.Error(), err: err}
	}
	if !bytes.Equal(out, raw) {
		mode := os.FileMode(0o644)
		if info, err := os.Lstat(*packPath); err == nil {
			mode = info.Mode().Perm()
		}
		if err := safefs.WriteFile(*packPath, out, mode); err != nil {
			return &commandError{code: 1, message: "served-lists build: cannot write the pack", err: err}
		}
	}
	for _, rec := range built {
		fmt.Fprintf(stdout, "%s %s pairs=%d commit=%s\n", rec.Component, rec.Line, len(rec.APIs), rec.Evidence.Sources[0].Revision)
	}
	fmt.Fprintf(stdout, "schema %s -> %s; %d lists; pack %s\n", schemaFrom, schemaTo, len(built), map[bool]string{true: "unchanged", false: "written"}[bytes.Equal(out, raw)])
	return nil
}

func readServedPack(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the pack: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxServedPackBytes {
		return nil, errors.New("the pack must be a regular file of at most 64 MiB")
	}
	return os.ReadFile(filepath.Clean(path))
}

// renderServedPack puts the built records into the pack's servedAPIs member
// (a record of a requested line replaces the pack's own, every other list is
// kept), sets the schema to the lowest level the loader admits and renders
// the pack. It refuses a pack that is not already in canonical form, so no
// byte outside the member and the schema line can change.
func renderServedPack(pack *extractpack.Pack, raw []byte, built []servedapis.Record, packPath string, admit func(string, []byte) error) (out []byte, from, to string, err error) {
	if canonical, err := pack.Render(); err != nil || !bytes.Equal(canonical, raw) {
		return nil, "", "", errors.New("the pack is not in canonical form; rewriting it would change bytes outside the served lists")
	}
	var schema string
	if err := json.Unmarshal(pack.Members["schema"], &schema); err != nil {
		return nil, "", "", errors.New("the pack has no schema")
	}
	family, level, ok := splitSchemaLevel(schema)
	if !ok || family != cncfPackSchemaFamily {
		return nil, "", "", fmt.Errorf("the pack schema %q is not a CNCF rule pack schema", schema)
	}
	var records []servedapis.Record
	if section, present := pack.Members[servedapis.PackMember]; present {
		if records, err = servedapis.Parse(section); err != nil {
			return nil, "", "", fmt.Errorf("the pack's served lists: %w", err)
		}
	}
	replaced := map[string]bool{}
	for _, rec := range built {
		replaced[rec.Component+" "+rec.Line] = true
	}
	merged := make([]servedapis.Record, 0, len(records)+len(built))
	for _, rec := range records {
		if !replaced[rec.Component+" "+rec.Line] {
			merged = append(merged, rec)
		}
	}
	merged = append(merged, built...)
	servedapis.Sort(merged)
	if err := servedapis.Validate(merged); err != nil {
		return nil, "", "", err
	}
	section, err := servedapis.Marshal(merged)
	if err != nil {
		return nil, "", "", err
	}
	head := &extractpack.Pack{Members: map[string]json.RawMessage{}, Entries: pack.Entries}
	for k, v := range pack.Members {
		head.Members[k] = v
	}
	head.Members[servedapis.PackMember] = section
	// A pack carries exactly the schema of the highest-level feature it
	// uses, so the first level the loader admits is the right one.
	// When no level is admitted the cause is the first refusal (the pack's
	// own level): a later level only adds "unknown schema" on top of it.
	var firstErr error
	for l := level; l <= level+servedSchemaLevels; l++ {
		newSchema, _ := json.Marshal(cncfPackSchemaFamily + strconv.Itoa(l))
		head.Members["schema"] = newSchema
		rendered, err := head.Render()
		if err != nil {
			return nil, "", "", err
		}
		admitErr := admit(packPath, rendered)
		if admitErr == nil {
			return rendered, schema, cncfPackSchemaFamily + strconv.Itoa(l), nil
		}
		if firstErr == nil {
			firstErr = admitErr
		}
	}
	return nil, "", "", fmt.Errorf("the engine loader refuses the pack with the served lists at its schema and the next %d levels: %w", servedSchemaLevels, firstErr)
}

const cncfPackSchemaFamily = "prufyx.io/cncf-source-rule-pack/v1alpha"

var schemaLevelRE = regexp.MustCompile(`^(.*/v1alpha)([0-9]{1,3})$`)

func splitSchemaLevel(schema string) (family string, level int, ok bool) {
	m := schemaLevelRE.FindStringSubmatch(schema)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(m[2])
	return m[1], n, err == nil
}

var servedLineRE = regexp.MustCompile(`^1\.(0|[1-9][0-9]{0,3})$`)

// coveredKubernetesLines is the span of Kubernetes minor lines the pack's
// Kubernetes rules and line attestations cover: the lowest and highest line
// of any rule's from and to versions and of any attestation (an attestation
// of line L also reads line L-1, its from side).
func coveredKubernetesLines(pack *extractpack.Pack) (span [2]int, err error) {
	lo, hi := -1, -1
	note := func(line string) {
		if m := servedLineRE.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			if lo < 0 || n < lo {
				lo = n
			}
			if n > hi {
				hi = n
			}
		}
	}
	for _, e := range pack.Entries {
		var v struct {
			Rule struct {
				Subject struct {
					Component string `json:"component"`
					From      string `json:"from"`
					To        string `json:"to"`
				} `json:"subject"`
			} `json:"rule"`
		}
		if json.Unmarshal(e, &v) != nil || v.Rule.Subject.Component != servedapis.KubernetesComponent {
			continue
		}
		for _, version := range []string{v.Rule.Subject.From, v.Rule.Subject.To} {
			if line, ok := lineattest.LineOf(version); ok {
				note(line)
			}
		}
	}
	if section, present := pack.Members[lineattest.PackMember]; present {
		atts, err := lineattest.Parse(section)
		if err != nil {
			return span, fmt.Errorf("the pack's line attestations: %w", err)
		}
		for _, a := range atts {
			if a.Component != servedapis.KubernetesComponent {
				continue
			}
			note(a.Line)
			if m := servedLineRE.FindStringSubmatch(a.Line); m != nil {
				if n, _ := strconv.Atoi(m[1]); n > 0 {
					note("1." + strconv.Itoa(n-1))
				}
			}
		}
	}
	if lo < 0 {
		return span, errors.New("the pack has no Kubernetes rule or line attestation to take the covered lines from")
	}
	return [2]int{lo, hi}, nil
}

// parseServedLines reads --lines: comma-separated items, each a range
// "1.19-1.37" or one line "1.30". A range must lie inside the span the
// pack's Kubernetes rules cover; a line outside it is accepted only when it
// is the only item of the list, exactly. The result is ascending and has no repeat.
func parseServedLines(text string, covered [2]int) ([]string, error) {
	minor := func(s string) (int, error) {
		m := servedLineRE.FindStringSubmatch(s)
		if m == nil {
			return 0, fmt.Errorf("%q is not a Kubernetes 1.N line", s)
		}
		return strconv.Atoi(m[1])
	}
	set := map[int]bool{}
	items := strings.Split(text, ",")
	for _, item := range items {
		from, to, isRange := strings.Cut(item, "-")
		a, err := minor(from)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = minor(to); err != nil {
				return nil, err
			}
			if b < a {
				return nil, fmt.Errorf("range %q runs backwards", item)
			}
			if a < covered[0] || b > covered[1] {
				return nil, fmt.Errorf("range %q is outside the lines the pack's Kubernetes rules cover (1.%d-1.%d); name an uncovered line alone to build it", item, covered[0], covered[1])
			}
		} else if (a < covered[0] || a > covered[1]) && len(items) != 1 {
			return nil, fmt.Errorf("line %q is outside the lines the pack's Kubernetes rules cover (1.%d-1.%d); an uncovered line is built only as the single item of --lines", item, covered[0], covered[1])
		}
		for n := a; n <= b; n++ {
			set[n] = true
			if len(set) > maxServedBuildLines {
				return nil, fmt.Errorf("more than %d lines", maxServedBuildLines)
			}
		}
	}
	minors := make([]int, 0, len(set))
	for n := range set {
		minors = append(minors, n)
	}
	sort.Ints(minors)
	lines := make([]string, len(minors))
	for i, n := range minors {
		lines[i] = "1." + strconv.Itoa(n)
	}
	return lines, nil
}
