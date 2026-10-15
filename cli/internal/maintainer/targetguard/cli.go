// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

const usage = "usage: prufyx-maintainer target-check <offline [--base-ref <git-ref>] | citations [--out <report.json>] [--concurrency n] [--timeout d]>"

// maxBaseBytes bounds the base revision's files read from git.
const maxBaseBytes = 32 << 20

// Run implements `prufyx-maintainer target-check`. root is the cli module
// root. It returns 0 when every check passes, 1 on any finding, 2 on a usage
// or I/O error (never a pass).
func Run(args []string, root string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "offline":
		return runOffline(args[1:], root, stdout, stderr)
	case "citations":
		return runCitations(args[1:], root, stdout, stderr, nil)
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
}

func runOffline(args []string, root string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("target-check offline", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	baseRef := flags.String("base-ref", "", "git revision to compare with: a removed row, a removed target or a narrowed target needs a new entry in "+GuardPath)
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	head, err := Load(os.DirFS(root), false)
	if err != nil {
		fmt.Fprintf(stderr, "target-check: %v\n", err)
		return 2
	}
	findings := Structure(head)
	if *baseRef != "" {
		base, err := loadBase(context.Background(), root, *baseRef)
		if err != nil {
			fmt.Fprintf(stderr, "target-check: base %q: %v\n", *baseRef, err)
			return 2
		}
		findings = append(findings, CheckRemovals(base, head)...)
	}
	for _, f := range findings {
		fmt.Fprintf(stderr, "FAIL %s\n", f)
	}
	compared := "no base revision (removal guard not run)"
	if *baseRef != "" {
		compared = "compared with " + *baseRef
	}
	fmt.Fprintf(stdout, "target-check offline: %d projects, %d targets, %d findings, %s\n", len(head.Projects), len(head.Targets), len(findings), compared)
	if len(findings) > 0 {
		return 1
	}
	return 0
}

type citationDeps struct {
	resolver rulecheck.RevisionResolver
	fetcher  rulecheck.Fetcher
}

func runCitations(args []string, root string, stdout, stderr io.Writer, deps *citationDeps) int {
	flags := flag.NewFlagSet("target-check citations", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outPath := flags.String("out", "", "write the JSON report to this file (default: stdout)")
	concurrency := flags.Int("concurrency", 4, "parallel source checks")
	timeout := flags.Duration("timeout", rulecheck.DefaultCitationTimeout, "overall deadline of the run")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *concurrency < 1 || *concurrency > 16 || *timeout <= 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	head, err := Load(os.DirFS(root), false)
	if err != nil {
		fmt.Fprintf(stderr, "target-check: %v\n", err)
		return 2
	}
	// The same structure the offline check demands: a source that is not a
	// pinned blob URL must fail here too, not just be skipped.
	if structural := Structure(head); len(structural) > 0 {
		for _, f := range structural {
			fmt.Fprintf(stderr, "FAIL %s\n", f)
		}
		fmt.Fprintf(stderr, "target-check citations: %d structural findings; no source was fetched\n", len(structural))
		return 1
	}
	verifier := &rulecheck.CitationVerifier{Concurrency: *concurrency, Timeout: *timeout}
	if deps != nil {
		verifier.Resolver, verifier.Fetcher = deps.resolver, deps.fetcher
	} else {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}
		verifier.Resolver = rulecheck.NewGitHubObjects(token)
		verifier.Fetcher = rulecheck.HTTPFetcher{}
	}
	report, err := verifier.VerifyPinnedFiles(context.Background(), PinnedFiles(head))
	if err != nil {
		fmt.Fprintf(stderr, "target-check: %v\n", err)
		return 2
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "target-check: could not encode report: %v\n", err)
		return 2
	}
	encoded = append(encoded, '\n')
	if *outPath != "" {
		if err := os.WriteFile(*outPath, encoded, 0o644); err != nil {
			fmt.Fprintf(stderr, "target-check: could not write %s: %v\n", *outPath, err)
			return 2
		}
	} else if _, err := stdout.Write(encoded); err != nil {
		fmt.Fprintf(stderr, "target-check: could not write the report: %v\n", err)
		return 2
	}
	for _, f := range report.Findings {
		fmt.Fprintf(stderr, "FAIL [%s] %s: %s\n", f.Check, f.RuleID, f.Message)
	}
	fmt.Fprintf(stderr, "target-check citations: %d sources, %d findings\n", report.SourcesChecked, len(report.Findings))
	if !report.Pass {
		return 1
	}
	return 0
}

// loadBase reads the checked files as they are at a git revision, through
// `git archive` into a private directory. A revision git cannot resolve, or
// files that do not load, are errors: the guard never skips a comparison.
func loadBase(ctx context.Context, root, ref string) (Inputs, error) {
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, "\x00\n") {
		return Inputs{}, errors.New("not a usable git revision")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", root, "archive", "--format=tar", ref+"^{tree}", "--", path.Dir(TablePath), TargetDir)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return Inputs{}, fmt.Errorf("git archive: %v: %s", err, strings.TrimSpace(errOut.String()))
	}
	dir, err := os.MkdirTemp("", "targetguard-base-")
	if err != nil {
		return Inputs{}, err
	}
	defer os.RemoveAll(dir)
	if err := extract(&out, dir); err != nil {
		return Inputs{}, err
	}
	return Load(os.DirFS(dir), true)
}

func extract(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe path %q in the archive", h.Name)
		}
		total += h.Size
		if total > maxBaseBytes {
			return errors.New("the base revision's files are too large")
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, h.Size))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
}
