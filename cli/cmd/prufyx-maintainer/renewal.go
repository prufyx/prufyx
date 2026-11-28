// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rederiverenew"
)

const renewalUsage = `renewal: usage: prufyx-maintainer renewal <plan|compare|assemble>
  plan      --pack FILE --at RFC3339 --max N                         (prints the plan as one line of JSON)
  compare   --a DIR --b DIR                                          (prints the digest of two byte-identical runs)
  assemble  --base FILE --applied FILE --plan FILE --max N --outputs FILE --run-id N --run-attempt N
            --commit SHA --workflow-sha SHA --out FILE --origin FILE (writes the base pack with only the planned renewals)`

// runRenewal wires the checks of the scheduled renewal workflow. It reads
// and writes local files only.
func runRenewal(args []string, stdout io.Writer) error {
	if err := renewalCommand(args, time.Now, stdout); err != nil {
		return &commandError{code: 2, message: "renewal: " + err.Error(), err: err}
	}
	return nil
}

func renewalCommand(args []string, now func() time.Time, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(renewalUsage)
	}
	f := flag.NewFlagSet("renewal "+args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	parse := func(required ...*string) error {
		if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 {
			return errors.New(renewalUsage)
		}
		for _, v := range required {
			if *v == "" {
				return errors.New(renewalUsage)
			}
		}
		return nil
	}
	switch args[0] {
	case "plan":
		var pack, at string
		var max int
		f.StringVar(&pack, "pack", "", "")
		f.StringVar(&at, "at", "", "")
		f.IntVar(&max, "max", -1, "")
		if err := parse(&pack, &at); err != nil {
			return err
		}
		raw, err := os.ReadFile(pack)
		if err != nil {
			return err
		}
		plan, err := rederiverenew.MakePlan(raw, at, now().UTC(), max, func(id string) (string, bool) {
			spec, ok := extractcli.Catalog()[id]
			return spec.Repo, ok
		})
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(plan)
	case "compare":
		var a, b string
		f.StringVar(&a, "a", "", "")
		f.StringVar(&b, "b", "", "")
		if err := parse(&a, &b); err != nil {
			return err
		}
		digest, err := rederiverenew.Compare(a, b)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, digest)
		return err
	case "assemble":
		var base, applied, planFile, outputs, out, origin string
		var run rederiverenew.Run
		var max int
		f.StringVar(&base, "base", "", "")
		f.StringVar(&applied, "applied", "", "")
		f.StringVar(&planFile, "plan", "", "")
		f.StringVar(&outputs, "outputs", "", "")
		f.StringVar(&out, "out", "", "")
		f.StringVar(&origin, "origin", "", "")
		f.StringVar(&run.ID, "run-id", "", "")
		f.StringVar(&run.Attempt, "run-attempt", "", "")
		f.StringVar(&run.Commit, "commit", "", "")
		f.StringVar(&run.WorkflowSHA, "workflow-sha", "", "")
		f.IntVar(&max, "max", 0, "")
		if err := parse(&base, &applied, &planFile, &outputs, &out, &origin); err != nil {
			return err
		}
		files := map[string][]byte{}
		for _, p := range []string{base, applied, planFile, outputs} {
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			files[p] = raw
		}
		var plan rederiverenew.Plan
		dec := json.NewDecoder(bytes.NewReader(files[planFile]))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&plan); err != nil {
			return fmt.Errorf("plan: %w", err)
		}
		// One "<extractor> <digest>" line per compared run.
		digests := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(files[outputs])), "\n") {
			id, digest, ok := strings.Cut(line, " ")
			if !ok || digests[id] != "" {
				return errors.New("the outputs file is not one line per extractor")
			}
			digests[id] = digest
		}
		head, res, err := rederiverenew.Assemble(files[base], files[applied], plan, now().UTC(), max)
		if err != nil {
			return err
		}
		block, err := rederiverenew.Origin(run, plan, res, digests)
		if err != nil {
			return err
		}
		if err := os.WriteFile(out, head, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(origin, []byte(block), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "renewed %d record(s); %d planned left unchanged; %d other difference(s) left for the ordinary intake\n", len(res.Renewed), len(res.NotRenewed), res.LeftOut)
		for _, id := range res.NotRenewed {
			fmt.Fprintln(stdout, "not renewed "+id)
		}
		return nil
	}
	return errors.New(renewalUsage)
}
