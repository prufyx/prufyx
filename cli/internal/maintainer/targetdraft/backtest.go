// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// BacktestSchema is the schema of a backtest manifest.
const BacktestSchema = "prufyx.io/target-draft-backtest/v1"

// Result classes of one project in a backtest.
const (
	ClassReproduced         = "reproduced"
	ClassReproducedCircular = "reproduced-circular"
	// ClassReproducedOracle: equal, but the install paths were copied from the
	// reviewed target itself. It proves only that the generator compiles a given
	// path set deterministically; it is never counted as inferred.
	ClassReproducedOracle = "reproduced-oracle"
	ClassDiffers          = "differs"
	ClassTypedStop        = "typed-stop"
	ClassHarnessError     = "harness-error"
)

// Causes of a difference.
const (
	CauseFormatGap = "format-gap" // the reviewed file holds fields the generator cannot emit
	CauseWindow    = "window"     // only the tag window (minFrom, prefixes) differs
	CauseInference = "inference"  // the install surface or another field differs
)

// StopMirrorMissing is the harness's own typed stop: the pinned local mirror
// is absent. It is never counted as reproduced.
const StopMirrorMissing = "mirror-missing"

type btEntry struct {
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Repo        string   `json:"repo"`
	Catalog     string   `json:"catalog,omitempty"`
	Component   string   `json:"component,omitempty"`
	FactProject string   `json:"factProject,omitempty"`
	Tags        []string `json:"tags"`
	Mirror      string   `json:"mirror"`                // directory name below --mirrors
	Rules       string   `json:"rules,omitempty"`       // rules file, relative to the manifest
	Expected    string   `json:"expected"`              // reviewed target file, relative to the manifest
	Half        string   `json:"half"`                  // "A" or "B"
	MultiPrefix bool     `json:"multiPrefix,omitempty"` // tags of two prefixes; see Input.MultiPrefix
	// CollapseDirectories, DeriveDuplicateSources: the generator flags of the same
	// names (--collapse-directories, --derive-duplicate-sources). Default off.
	CollapseDirectories    bool `json:"collapseDirectories,omitempty"`
	DeriveDuplicateSources bool `json:"deriveDuplicateSources,omitempty"`
	// OraclePaths feeds the reviewed target's own paths to the generator as
	// installPaths. The result is labelled oracle and never counted as strict.
	OraclePaths bool `json:"oraclePaths,omitempty"`
}

type btSeed struct {
	Entry string `json:"entry"`
	Kind  string `json:"kind"` // swap | path | min-from | attest | drop-exclusion
	Other string `json:"other,omitempty"`
}

type btManifest struct {
	Schema  string    `json:"schema"`
	Count   int       `json:"count"`
	Entries []btEntry `json:"entries"`
	Seeds   []btSeed  `json:"seeds"`
}

// BacktestResult is the record of one project.
type BacktestResult struct {
	Slug   string   `json:"slug"`
	Class  string   `json:"class"`
	Oracle bool     `json:"oracle,omitempty"` // the install paths came from the reviewed target
	Cause  string   `json:"cause,omitempty"`
	Fields []string `json:"fields,omitempty"`
	Stops  []string `json:"stops,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// SeedResult is the record of one wrong-target seed. Outcome "failed" is the
// wanted one (the wrong target was rejected); "passed" and "not-run" make the
// command exit non-zero.
type SeedResult struct {
	Entry   string `json:"entry"`
	Kind    string `json:"kind"`
	Other   string `json:"other,omitempty"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// BacktestReport is the content of backtest.json.
type BacktestReport struct {
	Schema         string           `json:"schema"`
	ManifestDigest string           `json:"manifestDigest"`
	N              int              `json:"n"`
	Reproduced     int              `json:"reproduced"`
	Circular       int              `json:"reproducedCircular"`
	OracleRepro    int              `json:"reproducedOracle"`
	Differs        int              `json:"differs"`
	FormatGap      int              `json:"formatGap"`
	TypedStops     int              `json:"typedStops"`
	Errors         int              `json:"harnessErrors"`
	Seeds          int              `json:"seeds"`
	SeedsFailed    int              `json:"seedsFailed"`
	Results        []BacktestResult `json:"results"`
	SeedResults    []SeedResult     `json:"seedResults"`
}

const backtestUsage = "usage: prufyx-maintainer target-draft backtest --manifest FILE --mirrors DIR --out DIR\n" +
	"report only: re-generates every manifest entry from its local mirror, compares it with the reviewed target and prints strict reproduced/N. Exit 0 only when every wrong-target seed was rejected and no harness error occurred; 1 when a seed reproduced; 2 on usage, I/O or harness errors. Offline; never fetches."

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func localPath(base, rel, what string) (string, error) {
	if rel == "" || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%s %q must be a relative path inside the manifest directory", what, rel)
	}
	return filepath.Join(base, rel), nil
}

// readRel reads a manifest-relative file; its errors name only the relative
// path, so the report does not depend on where the checkout lives.
func readRel(abs, rel string) ([]byte, error) {
	b, err := readBounded(abs)
	if err == nil {
		return b, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: not found", rel)
	}
	if strings.Contains(err.Error(), "over 4 MiB") {
		return nil, fmt.Errorf("%s: over 4 MiB", rel)
	}
	return nil, fmt.Errorf("%s: unreadable", rel)
}

func parseBacktestManifest(raw []byte) (*btManifest, error) {
	var m btManifest
	if err := strictDecode(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != BacktestSchema {
		return nil, fmt.Errorf("manifest: schema must be %s", BacktestSchema)
	}
	if m.Count != len(m.Entries) || len(m.Entries) == 0 {
		return nil, fmt.Errorf("manifest: count %d does not match %d entries", m.Count, len(m.Entries))
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if !slugRE.MatchString(e.Slug) || seen[e.Slug] {
			return nil, fmt.Errorf("manifest: slug %q is malformed or duplicated", e.Slug)
		}
		seen[e.Slug] = true
		if e.Half != "A" && e.Half != "B" {
			return nil, fmt.Errorf("manifest: %s: half must be A or B", e.Slug)
		}
		if e.Mirror == "" || e.Mirror != filepath.Base(e.Mirror) || e.Mirror == "." || e.Mirror == ".." || len(e.Tags) == 0 || e.Expected == "" {
			return nil, fmt.Errorf("manifest: %s: mirror (one directory name), tags and expected are required", e.Slug)
		}
	}
	if len(m.Seeds) == 0 {
		return nil, errors.New("manifest: at least one wrong-target seed is required")
	}
	for _, s := range m.Seeds {
		switch s.Kind {
		case "swap":
			if !seen[s.Other] || s.Other == s.Entry {
				return nil, fmt.Errorf("manifest: seed %s/swap: other must be a different entry", s.Entry)
			}
		case "path", "min-from", "attest", "drop-exclusion", "swap-prefixes", "drop-prefix", "extra-prefix":
			if s.Other != "" {
				return nil, fmt.Errorf("manifest: seed %s/%s: other is only for swap", s.Entry, s.Kind)
			}
		default:
			return nil, fmt.Errorf("manifest: seed %s: unknown kind %q", s.Entry, s.Kind)
		}
		if !seen[s.Entry] {
			return nil, fmt.Errorf("manifest: seed names unknown entry %q", s.Entry)
		}
	}
	return &m, nil
}

var knownTargetKeys = map[string]bool{"project": true, "catalog": true, "name": true, "repo": true, "component": true,
	"factProject": true, "tagPrefixes": true, "minFrom": true, "attest": true, "paths": true, "exclude": true}

// dirEntryDefault reports whether one reviewed paths entry is a directory
// entry with exactly the keys path, directory, match, guard and the one
// default match and guard pair the generator emits.
func dirEntryDefault(p map[string]json.RawMessage) bool {
	if len(p) != 4 {
		return false
	}
	var path, match, guard string
	var dir bool
	for k, v := range p {
		var err error
		switch k {
		case "path":
			err = json.Unmarshal(v, &path)
		case "directory":
			err = json.Unmarshal(v, &dir)
		case "match":
			err = json.Unmarshal(v, &match)
		case "guard":
			err = json.Unmarshal(v, &guard)
		default:
			return false
		}
		if err != nil {
			return false
		}
	}
	return path != "" && dir && match == DefaultDirMatch && guard == DefaultDirGuard
}

func rawPaths(raw []byte) ([]map[string]json.RawMessage, error) {
	var doc struct {
		Target map[string]json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var paths []map[string]json.RawMessage
	if p, ok := doc.Target["paths"]; ok {
		if err := json.Unmarshal(p, &paths); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

// formatGaps lists the fields of a reviewed target that the generator cannot
// emit (optional paths, non-default directory entries, extra target fields).
// A directory entry with the one default match and guard is not a gap: the
// generator emits it under --collapse-directories and its bytes are compared.
// The list is sorted and empty for a generator-shaped file.
func formatGaps(raw []byte) ([]string, error) {
	var doc struct {
		Target map[string]json.RawMessage `json:"target"`
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	gaps := map[string]bool{}
	for k := range doc.Target {
		if !knownTargetKeys[k] {
			gaps["target."+k] = true
		}
	}
	paths, err := rawPaths(raw)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		if dirEntryDefault(p) {
			continue
		}
		for k := range p {
			if k != "path" {
				gaps["paths."+k] = true
			}
		}
	}
	var out []string
	for k := range gaps {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// dirShapeMismatch lists the directory entries of the reviewed target that the
// generated target does not emit as directory entries (an exact-file list
// against a shipped directory entry is a difference, never a reproduction).
func dirShapeMismatch(generated, reviewed []byte) ([]string, error) {
	want, err := rawPaths(reviewed)
	if err != nil {
		return nil, err
	}
	have, err := rawPaths(generated)
	if err != nil {
		return nil, err
	}
	emitted := map[string]bool{}
	for _, p := range have {
		if dirEntryDefault(p) {
			var path string
			_ = json.Unmarshal(p["path"], &path)
			emitted[path] = true
		}
	}
	var out []string
	for _, p := range want {
		if !dirEntryDefault(p) {
			continue
		}
		var path string
		_ = json.Unmarshal(p["path"], &path)
		if !emitted[path] {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out, nil
}

// oracleRules builds the rules of an oracle run: the reviewed target's own
// paths as installPaths (a directory entry as "dir/"), on top of the entry's
// rules file. An entry whose rules already name installPaths or an install
// surface is refused, not merged.
func oracleRules(rules *Rules, reviewed []byte) (*Rules, error) {
	if rules != nil && (len(rules.InstallPaths) > 0 || len(rules.InstallSurface) > 0) {
		return nil, errors.New("oraclePaths cannot be combined with rules that carry installPaths or installSurface")
	}
	paths, err := rawPaths(reviewed)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("oraclePaths: the reviewed target has no paths")
	}
	out := Rules{Schema: RulesSchema, InstallSurface: []SurfaceRule{}, Exclusions: []ExclusionRule{}}
	if rules != nil {
		out.Upstream, out.Exclusions, out.PathFilter = rules.Upstream, rules.Exclusions, rules.PathFilter
	}
	for _, p := range paths {
		var path string
		if v, ok := p["path"]; !ok || json.Unmarshal(v, &path) != nil || path == "" {
			return nil, errors.New("oraclePaths: a reviewed path entry has no path")
		}
		if dirEntryDefault(p) {
			path = strings.TrimSuffix(path, "/") + "/"
		}
		out.InstallPaths = append(out.InstallPaths, InstallPathRule{Path: path,
			Reason:   "oracle: path copied from the reviewed target (backtest only)",
			Evidence: "oracle: reviewed target file"})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return ParseRules(b)
}

// compareReviewed lists the differences between a generated and a reviewed
// target; an empty list means equal bytes. A structural diff that is empty
// while the bytes differ is still a difference.
func compareReviewed(generated, reviewed []byte) ([]string, error) {
	diffs, err := Diff(generated, reviewed)
	if err != nil {
		return nil, err
	}
	if len(diffs) == 0 && !bytes.Equal(generated, reviewed) {
		diffs = []string{"bytes differ although the structure is equal"}
	}
	return diffs, nil
}

func diffFields(diffs []string) []string {
	set := map[string]bool{}
	for _, d := range diffs {
		switch {
		case strings.HasPrefix(d, "field "):
			set[strings.SplitN(strings.TrimPrefix(d, "field "), ":", 2)[0]] = true
		case strings.HasPrefix(d, "path "):
			set["paths"] = true
		default:
			set["bytes"] = true
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// generate is the generator entry point; tests replace it.
var generate = Generate

type btRun struct {
	res      BacktestResult
	gen      []byte // generated half, nil unless generation succeeded
	expected []byte
	circular bool
}

func runEntry(e btEntry, base, mirrors string, open func(string) Source) btRun {
	r := btRun{res: BacktestResult{Slug: e.Slug}}
	fail := func(format string, a ...any) btRun {
		r.res.Class, r.res.Error = ClassHarnessError, fmt.Sprintf(format, a...)
		return r
	}
	expPath, err := localPath(base, e.Expected, "expected")
	if err != nil {
		return fail("%v", err)
	}
	if r.expected, err = readRel(expPath, e.Expected); err != nil {
		return fail("expected: %v", err)
	}
	var rules *Rules
	if e.Rules != "" {
		rp, err := localPath(base, e.Rules, "rules")
		if err != nil {
			return fail("%v", err)
		}
		raw, err := readRel(rp, e.Rules)
		if err == nil {
			rules, err = ParseRules(raw)
		}
		if err != nil {
			return fail("rules: %v", err)
		}
		r.circular = len(rules.Exclusions) > 0
	}
	if e.OraclePaths {
		var err error
		if rules, err = oracleRules(rules, r.expected); err != nil {
			return fail("%v", err)
		}
		r.res.Oracle = true
	}
	mdir := filepath.Join(mirrors, e.Mirror)
	if st, err := os.Stat(mdir); err != nil || !st.IsDir() {
		r.res.Class, r.res.Stops = ClassTypedStop, []string{StopMirrorMissing}
		return r
	}
	gen, err := generate(Input{Slug: e.Slug, Name: e.Name, Repo: e.Repo, Component: e.Component, FactProject: e.FactProject,
		Catalog: e.Catalog, Tags: e.Tags, Source: open(mdir), Rules: rules, MultiPrefix: e.MultiPrefix,
		CollapseDirectories: e.CollapseDirectories, DeriveDuplicates: e.DeriveDuplicateSources})
	if err != nil {
		var se *StopError
		if !errors.As(err, &se) {
			return fail("generate: %v", err)
		}
		for _, s := range se.Stops {
			if _, known := nextAction[s.Code]; !known {
				return fail("unknown stop code %q", s.Code)
			}
			r.res.Stops = append(r.res.Stops, s.Code)
		}
		sort.Strings(r.res.Stops)
		r.res.Class = ClassTypedStop
		return r
	}
	r.gen = gen.A
	if e.Half == "B" {
		r.gen = gen.B
	}
	gaps, err := formatGaps(r.expected)
	if err != nil {
		return fail("expected: %v", err)
	}
	if len(gaps) > 0 {
		r.res.Class, r.res.Cause, r.res.Fields = ClassDiffers, CauseFormatGap, gaps
		return r
	}
	if miss, err := dirShapeMismatch(r.gen, r.expected); err != nil {
		return fail("compare: %v", err)
	} else if len(miss) > 0 {
		r.res.Class, r.res.Cause, r.res.Fields = ClassDiffers, CauseInference, []string{"paths"}
		return r
	}
	diffs, err := compareReviewed(r.gen, r.expected)
	if err != nil {
		return fail("compare: %v", err)
	}
	switch {
	case len(diffs) == 0 && r.res.Oracle:
		r.res.Class = ClassReproducedOracle
	case len(diffs) == 0 && r.circular:
		r.res.Class = ClassReproducedCircular
	case len(diffs) == 0:
		r.res.Class = ClassReproduced
	default:
		r.res.Class, r.res.Fields = ClassDiffers, diffFields(diffs)
		r.res.Cause = CauseInference
		if onlyWindow(r.res.Fields) {
			r.res.Cause = CauseWindow
		}
	}
	return r
}

func onlyWindow(fields []string) bool {
	for _, f := range fields {
		if f != "minFrom" && f != "tagPrefixes" {
			return false
		}
	}
	return len(fields) > 0
}

// seedExpected builds the wrong target of a seed from the reviewed bytes of
// the entry (or of the other entry for a swap).
func seedExpected(s btSeed, own, other []byte) ([]byte, error) {
	if s.Kind == "swap" {
		return other, nil
	}
	d, err := decodeDoc(own)
	if err != nil {
		return nil, err
	}
	t := &d.Target
	switch s.Kind {
	case "path":
		if len(t.Paths) == 0 {
			return nil, errors.New("no path to flip")
		}
		t.Paths = append([]pathOut(nil), t.Paths...)
		t.Paths[0].Path += ".seed"
	case "min-from":
		t.MinFrom += "0"
	case "attest":
		t.Attest = !t.Attest
	case "swap-prefixes":
		if len(t.TagPrefixes) != 2 {
			return nil, errors.New("no two prefixes to swap")
		}
		t.TagPrefixes = []string{t.TagPrefixes[1], t.TagPrefixes[0]}
	case "drop-prefix":
		if len(t.TagPrefixes) != 2 {
			return nil, errors.New("no second prefix to drop")
		}
		t.TagPrefixes = t.TagPrefixes[:1]
	case "extra-prefix":
		if len(t.TagPrefixes) == 0 || len(t.TagPrefixes) > 2 {
			return nil, errors.New("no prefix list to extend")
		}
		t.TagPrefixes = append(append([]string(nil), t.TagPrefixes...), "seed-extra-")
	case "drop-exclusion":
		if len(t.Exclude) == 0 {
			return nil, errors.New("no exclusion to drop")
		}
		t.Exclude = nil
	}
	return marshalTarget(d)
}

func runSeed(s btSeed, runs map[string]btRun) SeedResult {
	out := SeedResult{Entry: s.Entry, Kind: s.Kind, Other: s.Other, Outcome: "not-run"}
	base := runs[s.Entry]
	if base.res.Class != ClassReproduced && base.res.Class != ClassReproducedCircular && base.res.Class != ClassReproducedOracle {
		out.Detail = "entry did not reproduce, so a seed on it proves nothing"
		return out
	}
	var other []byte
	if s.Kind == "swap" {
		other = runs[s.Other].expected
		if other == nil {
			out.Detail = "other entry has no reviewed file"
			return out
		}
	}
	wrong, err := seedExpected(s, base.expected, other)
	if err != nil {
		out.Detail = err.Error()
		return out
	}
	if bytes.Equal(wrong, base.expected) && s.Kind != "swap" {
		out.Detail = "seed did not change the reviewed file"
		return out
	}
	diffs, err := compareReviewed(base.gen, wrong)
	if err != nil {
		out.Detail = "the comparison failed: seed not counted as rejected"
		return out
	}
	if len(diffs) > 0 {
		out.Outcome = "failed"
		return out
	}
	out.Outcome = "passed"
	out.Detail = "the wrong target reproduced"
	return out
}

// Backtest runs every entry and the seeds and returns the report.
func Backtest(m *btManifest, manifestDigest, base, mirrors string, open func(string) Source) BacktestReport {
	rep := BacktestReport{Schema: BacktestSchema, ManifestDigest: manifestDigest, N: len(m.Entries)}
	runs := map[string]btRun{}
	for _, e := range m.Entries {
		r := runEntry(e, base, mirrors, open)
		runs[e.Slug] = r
		rep.Results = append(rep.Results, r.res)
		switch r.res.Class {
		case ClassReproduced:
			rep.Reproduced++
		case ClassReproducedCircular:
			rep.Circular++
		case ClassReproducedOracle:
			rep.OracleRepro++
		case ClassDiffers:
			rep.Differs++
			if r.res.Cause == CauseFormatGap {
				rep.FormatGap++
			}
		case ClassTypedStop:
			rep.TypedStops++
		default:
			rep.Errors++
		}
	}
	sort.Slice(rep.Results, func(i, j int) bool { return rep.Results[i].Slug < rep.Results[j].Slug })
	for _, s := range m.Seeds {
		sr := runSeed(s, runs)
		rep.SeedResults = append(rep.SeedResults, sr)
		rep.Seeds++
		if sr.Outcome == "failed" {
			rep.SeedsFailed++
		}
	}
	return rep
}

// RunBacktest implements "target-draft backtest".
func RunBacktest(args []string, stdout, stderr io.Writer) int {
	return runBacktest(args, stdout, stderr, func(dir string) Source { return GitSource{Dir: dir} })
}

func runBacktest(args []string, stdout, stderr io.Writer, open func(string) Source) int {
	fl := flag.NewFlagSet("target-draft backtest", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var manifest, mirrors, out string
	fl.StringVar(&manifest, "manifest", "", "")
	fl.StringVar(&mirrors, "mirrors", "", "")
	fl.StringVar(&out, "out", "", "")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || manifest == "" || mirrors == "" || out == "" {
		fmt.Fprintln(stderr, backtestUsage)
		return 2
	}
	die := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "target-draft backtest: "+format+"\n", a...)
		return 2
	}
	if st, err := os.Stat(out); err == nil {
		ents, rerr := os.ReadDir(out)
		if !st.IsDir() || rerr != nil || len(ents) > 0 {
			return die("--out must be absent or an empty directory")
		}
	}
	raw, err := readBounded(manifest)
	if err != nil {
		return die("%v", err)
	}
	m, err := parseBacktestManifest(raw)
	if err != nil {
		return die("%v", err)
	}
	sum := sha256.Sum256(raw)
	base := filepath.Dir(manifest)
	rep := Backtest(m, hex.EncodeToString(sum[:]), base, mirrors, open)
	body, err := marshal(rep)
	if err != nil {
		return die("%v", err)
	}
	again, err := marshal(Backtest(m, hex.EncodeToString(sum[:]), base, mirrors, open))
	if err != nil || !bytes.Equal(body, again) {
		return die("two runs gave different results; the mirrors or the generator are not deterministic")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return die("%v", err)
	}
	if err := os.WriteFile(filepath.Join(out, "backtest.json"), body, 0o644); err != nil {
		return die("%v", err)
	}
	for _, r := range rep.Results {
		line := r.Slug + " " + r.Class
		if r.Cause != "" {
			line += " cause=" + r.Cause
		}
		if len(r.Fields) > 0 {
			line += " fields=" + strings.Join(r.Fields, ",")
		}
		if len(r.Stops) > 0 {
			line += " stops=" + strings.Join(r.Stops, ",")
		}
		if r.Error != "" {
			line += " error=" + r.Error
		}
		fmt.Fprintln(stdout, line)
	}
	for _, s := range rep.SeedResults {
		fmt.Fprintf(stdout, "SEED %s/%s%s %s %s\n", s.Entry, s.Kind, map[bool]string{true: "->" + s.Other}[s.Other != ""], s.Outcome, s.Detail)
	}
	sd := sha256.Sum256(body)
	fmt.Fprintf(stdout, "BACKTEST strict=%d/%d reachable=%d/%d circular=%d oracle=%d stops=%d differs=%d errors=%d seeds=%d/%d-failed digest=%s\n",
		rep.Reproduced, rep.N, rep.Reproduced, rep.N-rep.FormatGap, rep.Circular, rep.OracleRepro, rep.TypedStops, rep.Differs, rep.Errors,
		rep.SeedsFailed, rep.Seeds, hex.EncodeToString(sd[:]))
	return backtestExit(rep, stderr)
}

// backtestExit maps a report to the exit code: 2 for a harness error or a seed
// that did not run, 1 for a wrong-target seed that reproduced, else 0.
func backtestExit(rep BacktestReport, stderr io.Writer) int {
	notRun, passed := 0, 0
	for _, s := range rep.SeedResults {
		switch s.Outcome {
		case "passed":
			passed++
		case "not-run":
			notRun++
		}
	}
	switch {
	case rep.Errors > 0 || notRun > 0:
		fmt.Fprintf(stderr, "target-draft backtest: %d harness error(s), %d seed(s) not run\n", rep.Errors, notRun)
		return 2
	case passed > 0:
		fmt.Fprintf(stderr, "target-draft backtest: %d wrong-target seed(s) reproduced; the comparison is not trustworthy\n", passed)
		return 1
	}
	return 0
}
