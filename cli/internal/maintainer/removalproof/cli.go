// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

const usage = "usage: prufyx-maintainer flag-removal-verify --request FILE --repo CLONE --pins FILE --lines FILE --modcache DIR [--out FILE]"

const maxInputBytes = 32 << 20

// Main runs the report-only check. The exit code is 0 only when every name
// passed the source checks, 1 when any name is refused and 2 when there is no
// report.
func Main(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("flag-removal-verify", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	request := f.String("request", "", "")
	repo := f.String("repo", "", "")
	pinsFile := f.String("pins", "", "")
	linesFile := f.String("lines", "", "")
	modcache := f.String("modcache", "", "")
	out := f.String("out", "", "")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *request == "" || *repo == "" || *pinsFile == "" || *linesFile == "" || *modcache == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	rep, err := func() (*Report, error) {
		raw, err := readInput(*request)
		if err != nil {
			return nil, err
		}
		q, err := ParseRequest(raw)
		if err != nil {
			return nil, err
		}
		if raw, err = readInput(*pinsFile); err != nil {
			return nil, err
		}
		pins, err := ParsePins(raw)
		if err != nil {
			return nil, err
		}
		if raw, err = readInput(*linesFile); err != nil {
			return nil, err
		}
		lines, err := coveragereport.ParseLines(raw)
		if err != nil {
			return nil, err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		ref, err := extract.ParseRepo(q.Repository)
		if err != nil {
			return nil, err
		}
		src := &gitSource{ctx: ctx, dir: *repo, repo: ref}
		defer src.Close()
		return Verify(ctx, Inputs{Source: src, Pins: pins, Lines: lines, Modules: ModuleCache{Dir: *modcache}}, q)
	}()
	if err != nil {
		fmt.Fprintf(stderr, "flag-removal-verify: %v\n", err)
		return 2
	}
	if *out != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err == nil {
			err = os.WriteFile(*out, append(data, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintf(stderr, "flag-removal-verify: %v\n", err)
			return 2
		}
	}
	summarize(stdout, rep)
	if !rep.Passed() {
		return 1
	}
	return 0
}

func readInput(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err == nil && len(data) > maxInputBytes {
		err = fmt.Errorf("%s: input too large", p)
	}
	return data, err
}

func summarize(w io.Writer, r *Report) {
	fmt.Fprintf(w, "report-only %s %s>%s binary %s: %d+%d releases\n", r.Request.Project, r.Request.FromLine, r.Request.ToLine, r.Request.Binary, len(r.From), len(r.To))
	line := func(indent string, x Reason) {
		first := ""
		if len(x.Tags) > 0 {
			first = " first " + x.Tags[0]
		}
		fmt.Fprintf(w, "%s%s %s (%d tags%s) %s\n", indent, x.Side, x.Code, len(x.Tags), first, strings.TrimSpace(x.Detail))
	}
	for _, x := range r.PairReasons {
		line("  pair ", x)
	}
	for _, n := range r.Names {
		fmt.Fprintf(w, "name %s: %s\n", n.Name, n.Verdict)
		for _, x := range n.Reasons {
			line("  ", x)
		}
	}
	fmt.Fprintf(w, "not performed: %s\n", strings.Join(r.Outstanding, "; "))
}
