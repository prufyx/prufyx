// SPDX-License-Identifier: AGPL-3.0-only

// Package extractcli wires the "extract" maintainer subcommands: run an
// extractor over the offline mirror (or a fixture tree), verify a recorded
// run by re-deriving it byte for byte, and compare a run with an expected
// list of results.
package extractcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/prufyx/prufyx/cli/internal/extract/safefs"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sfeaturegates"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

const usage = `usage:
  prufyx-maintainer extract run    --extractor ID (--mirror-state DIR | --fixture DIR) --out DIR [--derived-at RFC3339] [--lease-days N] [--concurrency N] [--wants-out FILE]
  prufyx-maintainer extract verify --extractor ID (--mirror-state DIR | --fixture DIR) --out DIR [--concurrency N]
  prufyx-maintainer extract apply  --out DIR --pack FILE [--withdraw | --rules-only]   (exit 3: the run does not supersede a rule it would withdraw)
  prufyx-maintainer extract supersede --out DIR --pack FILE   (replaces the reviewed rules the run covers; exit 3: refused, nothing written)
  prufyx-maintainer extract inventory --extractor ID (--mirror-state DIR | --fixture DIR) --repo OWNER/NAME --commit SHA
  prufyx-maintainer extract oracle --extractor ID --out DIR --expected FILE
  prufyx-maintainer extract list`

// Spec is one registered extractor.
type Spec struct {
	ID   string
	Repo string
	New  func(concurrency int) extract.Extractor
	// Oracle compares a recorded run with an expected-results file; it
	// returns the disagreements, one per line.
	Oracle func(outDir string, expected []byte) ([]string, error)
}

// Catalog lists the registered extractors by id. The CRD version-removal
// extractor is registered once per reviewed project, as
// crd.version-removal.<project>, because a run reads one repository.
func Catalog() map[string]Spec {
	out := map[string]Spec{
		k8sfeaturegates.ID: {
			ID:     k8sfeaturegates.ID,
			Repo:   k8sfeaturegates.Repo,
			New:    func(c int) extract.Extractor { return k8sfeaturegates.New(c) },
			Oracle: k8sfeaturegates.Oracle,
		},
		k8sservedapis.ID: {
			ID:     k8sservedapis.ID,
			Repo:   k8sservedapis.Repo,
			New:    func(c int) extract.Extractor { return k8sservedapis.New(c) },
			Oracle: k8sservedapis.Oracle,
		},
	}
	for _, t := range crdversions.Targets {
		t := t
		out[t.ExtractorID()] = Spec{
			ID:     t.ExtractorID(),
			Repo:   t.Repo,
			New:    func(c int) extract.Extractor { return crdversions.NewConcurrent(t, c) },
			Oracle: crdversions.Oracle,
		}
	}
	return out
}

// Main runs an "extract" subcommand (args exclude the word "extract").
// existingRules are published pack files whose rule ids candidates must not
// reuse. It returns 0 on success, 1 when verification or the oracle found
// differences, 2 on rejected input or a failed run, and 3 when a run needs
// blobs or commits the mirror does not hold (run --wants-out), an inventory
// that cannot be established completely (inventory), or a withdrawal the run
// is too old or too different to justify (apply --withdraw).
func Main(args []string, existingRules []string, now func() time.Time, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var code int
	var err error
	switch args[0] {
	case "run":
		code, err = cmdRun(args[1:], existingRules, now, stdout)
	case "verify":
		code, err = cmdVerify(args[1:], existingRules, stdout)
	case "oracle":
		code, err = cmdOracle(args[1:], stdout)
	case "apply":
		code, err = cmdApply(args[1:], existingRules, stdout, stderr)
	case "supersede":
		code, err = cmdSupersede(args[1:], existingRules, stdout, stderr)
	case "inventory":
		code, err = cmdInventory(args[1:], stdout, stderr)
	case "list":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		ids := make([]string, 0)
		for id := range Catalog() {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(stdout, "%s\t%s\n", id, Catalog()[id].Repo)
		}
		return 0
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "extract: %v\n", err)
		return 2
	}
	return code
}

type common struct {
	extractor   string
	mirror      string
	fixture     string
	out         string
	concurrency int
}

func flags(name string, c *common, source bool) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&c.extractor, "extractor", "", "extractor id")
	f.StringVar(&c.out, "out", "", "output directory")
	if source {
		f.StringVar(&c.mirror, "mirror-state", "", "factory mirror state directory")
		f.StringVar(&c.fixture, "fixture", "", "fixture tree directory")
		f.IntVar(&c.concurrency, "concurrency", 0, "concurrent reads")
	}
	return f
}

type source interface {
	extract.PinnedReader
	extract.TagSource
}

func (c common) open() (Spec, extract.Extractor, source, extract.RepoRef, error) {
	spec, ok := Catalog()[c.extractor]
	if !ok {
		return Spec{}, nil, nil, extract.RepoRef{}, fmt.Errorf("unknown extractor %q", c.extractor)
	}
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		return Spec{}, nil, nil, extract.RepoRef{}, err
	}
	var src source
	switch {
	case c.mirror != "" && c.fixture == "":
		r, err := factorymirror.OpenReader(c.mirror)
		if err != nil {
			return Spec{}, nil, nil, extract.RepoRef{}, fmt.Errorf("open mirror: %w", err)
		}
		src = extract.MirrorReader{R: r}
	case c.fixture != "" && c.mirror == "":
		src = extract.FixtureReader{Root: c.fixture}
	default:
		return Spec{}, nil, nil, extract.RepoRef{}, errors.New("give exactly one of --mirror-state and --fixture")
	}
	if c.concurrency < 0 || c.concurrency > 64 {
		return Spec{}, nil, nil, extract.RepoRef{}, errors.New("--concurrency must be 0-64")
	}
	return spec, spec.New(c.concurrency), src, repo, nil
}

func cmdRun(args []string, existing []string, now func() time.Time, stdout io.Writer) (int, error) {
	var c common
	var derivedAt string
	f := flags("extract run", &c, true)
	f.StringVar(&derivedAt, "derived-at", "", "derivation time, RFC 3339 UTC (default now)")
	var leaseDays int
	f.IntVar(&leaseDays, "lease-days", 0, "validity window in days, 1-365 (default 90)")
	var wantsOut string
	f.StringVar(&wantsOut, "wants-out", "", "write the pinned files the mirror does not hold here (exit 3) instead of deriving")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || c.extractor == "" || c.out == "" {
		return 2, errors.New("command rejected\n" + usage)
	}
	leaseSet := false
	f.Visit(func(fl *flag.Flag) { leaseSet = leaseSet || fl.Name == "lease-days" })
	if leaseSet && (leaseDays < 1 || leaseDays > 365) {
		return 2, errors.New("--lease-days must be 1-365")
	}
	_, ex, src, repo, err := c.open()
	if err != nil {
		return 2, err
	}
	at := now().UTC().Truncate(time.Second)
	if derivedAt != "" {
		if at, err = time.Parse(time.RFC3339, derivedAt); err != nil || !strings.HasSuffix(derivedAt, "Z") {
			return 2, errors.New("--derived-at must be RFC 3339 UTC, e.g. 2026-10-02T00:00:00Z")
		}
	}
	if items, err := os.ReadDir(c.out); err == nil && len(items) > 0 {
		return 2, fmt.Errorf("output directory %s is not empty", c.out)
	}
	ctx, stop := signalContext()
	defer stop()
	var reader extract.PinnedReader = src
	var wants *wantsReader
	if wantsOut != "" {
		wants = &wantsReader{inner: src, missing: map[wantKey]bool{}, absent: map[string]bool{}, listed: map[string][]string{}}
		reader = wants
	}
	out, err := extract.Run(ctx, ex, src, reader, extract.Options{Repo: repo, DerivedAt: at, Lease: time.Duration(leaseDays) * 24 * time.Hour, ExistingRules: existing})
	if wants != nil && len(wants.missing) > 0 {
		// Whatever the run did next, it read stand-in bytes for the
		// missing files: nothing it derived is written.
		n, err := wants.write(wantsOut)
		if err != nil {
			return 2, err
		}
		fmt.Fprintf(stdout, "needs %d files the mirror does not hold; wants written to %s (nothing derived)\n", n, wantsOut)
		return 3, nil
	}
	if wants != nil && len(wants.absent) > 0 {
		// A commit or repository the mirror does not have is cured by
		// "factory mirror" without --wants, not by a wants file.
		for _, a := range wants.absentList() {
			fmt.Fprintf(stdout, "needs commit %s\n", a)
		}
		fmt.Fprintln(stdout, "the mirror lacks commits the run needs; run factory mirror, then run again (nothing derived)")
		return 3, nil
	}
	if err != nil {
		return 2, err
	}
	files, err := out.Files()
	if err != nil {
		return 2, err
	}
	if err := safefs.WriteTree(c.out, files); err != nil {
		return 2, err
	}
	t := out.Manifest.Totals
	fmt.Fprintf(stdout, "%s %s %s: %d pairs (%d derived, %d withheld), %d rules, %d vectors -> %s\n", out.Manifest.Extractor.ID, out.Manifest.Extractor.Version, out.Manifest.Extractor.CodeDigest, t.Pairs, t.Derived, t.Withheld, t.Rules, t.Vectors, c.out)
	for _, p := range out.Manifest.Pairs {
		if p.Status == extract.PairWithheld {
			fmt.Fprintf(stdout, "withheld %s -> %s: %s\n", p.FromTag, p.ToTag, p.Reason)
		}
	}
	return 0, nil
}

func cmdVerify(args []string, existing []string, stdout io.Writer) (int, error) {
	var c common
	f := flags("extract verify", &c, true)
	if err := f.Parse(args); err != nil || f.NArg() != 0 || c.extractor == "" || c.out == "" {
		return 2, errors.New("command rejected\n" + usage)
	}
	_, ex, src, _, err := c.open()
	if err != nil {
		return 2, err
	}
	ctx, stop := signalContext()
	defer stop()
	problems, err := extract.Verify(ctx, ex, src, src, c.out, existing)
	if err != nil {
		return 2, err
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(stdout, "DIFFERS "+p)
		}
		return 1, nil
	}
	fmt.Fprintln(stdout, "verified: re-derivation is byte-identical")
	return 0, nil
}

func cmdOracle(args []string, stdout io.Writer) (int, error) {
	var c common
	var expected string
	f := flags("extract oracle", &c, false)
	f.StringVar(&expected, "expected", "", "expected results file")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || c.extractor == "" || c.out == "" || expected == "" {
		return 2, errors.New("command rejected\n" + usage)
	}
	spec, ok := Catalog()[c.extractor]
	if !ok || spec.Oracle == nil {
		return 2, fmt.Errorf("extractor %q has no oracle", c.extractor)
	}
	raw, err := os.ReadFile(expected)
	if err != nil {
		return 2, err
	}
	diffs, err := spec.Oracle(c.out, raw)
	if err != nil {
		return 2, err
	}
	for _, d := range diffs {
		fmt.Fprintln(stdout, d)
	}
	if len(diffs) > 0 {
		return 1, nil
	}
	fmt.Fprintln(stdout, "oracle: no disagreement")
	return 0, nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
