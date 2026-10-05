// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

// Usage is the consensus command usage.
const Usage = `usage:
  prufyx-maintainer consensus normalise (--mirror-state DIR | --fixture DIR) --repo R --commit SHA --path P --section VERSION --out DIR [--wants-out FILE]
  prufyx-maintainer consensus verify --claims FILE (--mirror-state DIR | --fixture DIR) --out FILE [--wants-out FILE]`

// Exit codes.
const (
	ExitOK          = 0
	ExitMisuse      = 2
	ExitIncomplete  = 3
	ExitNotVerified = 4
)

// Main runs a consensus subcommand and returns its exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, Usage)
		return ExitMisuse
	}
	var code int
	var err error
	switch args[0] {
	case "normalise":
		code, err = cmdNormalise(args[1:], stdout, stderr)
	case "verify":
		code, err = cmdVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, Usage)
		return ExitOK
	default:
		fmt.Fprintln(stderr, Usage)
		return ExitMisuse
	}
	if err != nil {
		fmt.Fprintln(stderr, "consensus "+args[0]+": "+err.Error())
	}
	return code
}

type sourceFlags struct {
	mirror, fixture, wantsOut string
}

func (s *sourceFlags) register(f *flag.FlagSet) {
	f.StringVar(&s.mirror, "mirror-state", "", "factory mirror state directory")
	f.StringVar(&s.fixture, "fixture", "", "fixture tree directory")
	f.StringVar(&s.wantsOut, "wants-out", "", "write the files the mirror does not hold here")
}

// openSource opens the chosen source; tests replace it.
var openSource = defaultOpenSource

func defaultOpenSource(s *sourceFlags) (extract.PinnedReader, extract.TagSource, History, error) {
	switch {
	case s.mirror != "" && s.fixture == "":
		r, err := factorymirror.OpenReader(s.mirror)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open mirror: %w", err)
		}
		m := extract.MirrorReader{R: r}
		return m, m, MirrorHistory{State: s.mirror}, nil
	case s.fixture != "" && s.mirror == "":
		f := extract.FixtureReader{Root: s.fixture}
		return f, f, FixtureHistory{Root: s.fixture}, nil
	}
	return nil, nil, nil, errors.New("give exactly one of --mirror-state and --fixture")
}

// open returns the reader, tag source and history of the chosen source,
// the reader wrapped so that files the mirror does not hold are recorded.
func (s *sourceFlags) open() (*wantsReader, extract.TagSource, History, error) {
	r, tags, history, err := openSource(s)
	if err != nil {
		return nil, nil, nil, err
	}
	return newWantsReader(r), tags, history, nil
}

func newFlags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

func misuse() (int, error) { return ExitMisuse, errors.New("command rejected\n" + Usage) }

func parseRepoArg(s string) (extract.RepoRef, error) {
	if strings.Count(s, "/") == 1 {
		s = "github.com/" + s
	}
	return extract.ParseRepo(s)
}

// incomplete reports missing files: it writes the wants file when asked
// and returns exit code 3.
func incomplete(w *wantsReader, wantsOut string, stderr io.Writer) (int, error) {
	n := w.count()
	if wantsOut != "" {
		if _, err := w.write(wantsOut); err != nil {
			return ExitMisuse, fmt.Errorf("write wants: %w", err)
		}
	}
	fmt.Fprintf(stderr, "incomplete: %d file(s) are not held locally\n", n)
	return ExitIncomplete, nil
}

func cmdNormalise(args []string, stdout, stderr io.Writer) (int, error) {
	f := newFlags("consensus normalise")
	var src sourceFlags
	src.register(f)
	var repoArg, commit, path, section, out string
	f.StringVar(&repoArg, "repo", "", "repository")
	f.StringVar(&commit, "commit", "", "full commit SHA")
	f.StringVar(&path, "path", "", "release notes path")
	f.StringVar(&section, "section", "", "release, e.g. v1.31.0")
	f.StringVar(&out, "out", "", "output directory")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || repoArg == "" || commit == "" || path == "" || section == "" || out == "" {
		return misuse()
	}
	repo, err := parseRepoArg(repoArg)
	if err != nil {
		return ExitMisuse, err
	}
	if !extract.IsCommitSHA(commit) {
		return ExitMisuse, errors.New("--commit must be a full lowercase 40-character SHA")
	}
	reader, _, _, err := src.open()
	if err != nil {
		return ExitMisuse, err
	}
	raw, err := reader.Read(repo, commit, path)
	if reader.count() > 0 {
		return incomplete(reader, src.wantsOut, stderr)
	}
	if err != nil {
		return ExitMisuse, fmt.Errorf("read %s at %s: %w", path, commit, err)
	}
	spec := SectionSpec{Repo: repo.Key, Path: path, Version: section}
	norm, err := Normalise(raw, spec)
	if err != nil {
		return ExitMisuse, fmt.Errorf("normalisation refused: %w", err)
	}
	source := Source{
		Repo: repo.Key, Commit: commit, Path: path, FileSHA256: FileDigest(raw), Section: section,
		NormaliserVersion: NormaliserVersion, NormalisedSHA256: norm.Digest(),
	}
	sourceJSON, err := extract.Canonical(source)
	if err != nil {
		return ExitMisuse, err
	}
	lineMap, err := LineMapJSON(norm)
	if err != nil {
		return ExitMisuse, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return ExitMisuse, err
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"normalised.txt", norm.Text()}, {"linemap.json", lineMap}, {"source.json", sourceJSON}} {
		if err := writeAtomic(filepath.Join(out, file.name), file.data); err != nil {
			return ExitMisuse, err
		}
	}
	fmt.Fprintf(stdout, "normalised %s %s: %d lines, %d outside the line grammar, sha256 %s\n", path, section, len(norm.Lines), len(norm.Problems), norm.Digest())
	return ExitOK, nil
}

// LineMap is the line map document the normalise command writes.
type LineMap struct {
	NormaliserVersion string `json:"normaliserVersion"`
	Section           string `json:"section"`
	// Problems lists the lines outside the line grammar; a section with
	// any is not citable.
	Problems []Problem `json:"problems"`
	// Barriers lists the places in the release section that can hide
	// what follows them; no citation at or after one is verified.
	Barriers []Problem     `json:"barriers"`
	Lines    []LineMapLine `json:"lines"`
}

// LineMapLine maps one normalised line to its original line.
type LineMapLine struct {
	Normalised int      `json:"normalised"`
	Original   int      `json:"original"`
	Flags      []string `json:"flags,omitempty"`
	Problem    string   `json:"problem,omitempty"`
}

// LineMapJSON renders the line map of a normalised section as canonical
// JSON.
func LineMapJSON(n Normalised) ([]byte, error) {
	m := LineMap{NormaliserVersion: NormaliserVersion, Section: n.Section, Problems: append([]Problem{}, n.Problems...), Barriers: append([]Problem{}, n.Barriers...), Lines: make([]LineMapLine, len(n.Lines))}
	for i, l := range n.Lines {
		m.Lines[i] = LineMapLine{Normalised: i + 1, Original: l.Original, Flags: l.Flags, Problem: l.Problem}
	}
	return extract.Canonical(m)
}

func cmdVerify(args []string, stdout, stderr io.Writer) (int, error) {
	f := newFlags("consensus verify")
	var src sourceFlags
	src.register(f)
	var claims, out string
	f.StringVar(&claims, "claims", "", "claims bundle")
	f.StringVar(&out, "out", "", "report file")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || claims == "" || out == "" {
		return misuse()
	}
	raw, err := readBounded(claims, MaxBundleBytes)
	if err != nil {
		return ExitMisuse, err
	}
	bundle, err := DecodeBundle(raw)
	if err != nil {
		return ExitMisuse, err
	}
	reader, tags, history, err := src.open()
	if err != nil {
		return ExitMisuse, err
	}
	rep, err := Verify(context.Background(), bundle, Inputs{
		Reader: reader, Tags: tags, History: history, Inventory: &ExtractorInventories{Reader: reader},
	})
	if reader.count() > 0 {
		// A missing file can surface as an incomplete inventory; no
		// report is written either way.
		return incomplete(reader, src.wantsOut, stderr)
	}
	if errors.Is(err, ErrInputsIncomplete) {
		fmt.Fprintln(stderr, err.Error())
		return ExitIncomplete, nil
	}
	if err != nil {
		return ExitMisuse, err
	}
	doc, err := rep.Canonical()
	if err != nil {
		return ExitMisuse, err
	}
	if err := writeAtomic(out, doc); err != nil {
		return ExitMisuse, err
	}
	fmt.Fprintf(stdout, "%d verified, %d lead, %d dropped\n", rep.Summary.Verified, rep.Summary.Lead, rep.Summary.Dropped)
	if !rep.AllVerified() {
		return ExitNotVerified, nil
	}
	return ExitOK, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return raw, nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".consensus-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

type wantKey struct{ repo, commit, path string }

// wantsReader records the files a read needs that the mirror does not
// hold. It answers such a read with empty bytes so the work goes on and
// finds every other missing file; a command that recorded anything writes
// no result, so the stand-in bytes never reach an output.
type wantsReader struct {
	inner   extract.PinnedReader
	mu      sync.Mutex
	missing map[wantKey]bool
}

func newWantsReader(inner extract.PinnedReader) *wantsReader {
	return &wantsReader{inner: inner, missing: map[wantKey]bool{}}
}

func (w *wantsReader) Read(repo extract.RepoRef, commit, path string) ([]byte, error) {
	data, err := w.inner.Read(repo, commit, path)
	if errors.Is(err, factorymirror.ErrBlobNotLocal) {
		w.mu.Lock()
		w.missing[wantKey{repo.Key, commit, path}] = true
		w.mu.Unlock()
		return []byte{}, nil
	}
	return data, err
}

func (w *wantsReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	return w.inner.List(repo, commit, dir)
}

func (w *wantsReader) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.missing)
}

// write renders the wants as the document "factory mirror --wants" reads,
// grouped by repository and commit, sorted.
func (w *wantsReader) write(path string) (int, error) {
	w.mu.Lock()
	type group struct{ repo, commit string }
	byGroup := map[group][]string{}
	for k := range w.missing {
		g := group{k.repo, k.commit}
		byGroup[g] = append(byGroup[g], k.path)
	}
	w.mu.Unlock()
	groups := make([]group, 0, len(byGroup))
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].repo != groups[j].repo {
			return groups[i].repo < groups[j].repo
		}
		return groups[i].commit < groups[j].commit
	})
	wants := make([]factorymirror.Want, 0, len(groups))
	n := 0
	for _, g := range groups {
		paths := byGroup[g]
		sort.Strings(paths)
		n += len(paths)
		wants = append(wants, factorymirror.Want{Repo: g.repo, Commit: g.commit, Paths: paths})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"wants": wants}); err != nil {
		return 0, err
	}
	return n, writeAtomic(path, buf.Bytes())
}
