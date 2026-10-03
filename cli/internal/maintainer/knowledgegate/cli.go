// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const usage = `usage:
  prufyx-maintainer gate classify --base DIR --head DIR [--json]
  prufyx-maintainer gate limits   --base DIR --head DIR [--max-loosening N] [--json]
  prufyx-maintainer gate verify   --base DIR --head DIR [--source github|fixture:DIR]
                                  [--author LOGIN] [--bot-login LOGIN] [--max-loosening N]
                                  [--trust-root-digest sha256:...] [--rerun-worklist FILE]
                                  [--rederive-all] [--concurrency N] [--now RFC3339]
                                  [--report FILE] [--summary FILE]`

// Main runs a "gate" subcommand (args exclude the word "gate"). getenv
// supplies GITHUB_TOKEN or GH_TOKEN for the GitHub source. It returns 0
// when the gate passes, 1 when it fails, 2 on rejected input or an error.
func Main(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	return mainWith(args, getenv, stdout, stderr, DefaultLayout())
}

func mainWith(args []string, getenv func(string) string, stdout, stderr io.Writer, layout Layout) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var code int
	var err error
	switch args[0] {
	case "classify":
		code, err = cmdClassify(args[1:], layout, stdout)
	case "limits":
		code, err = cmdLimits(args[1:], layout, stdout)
	case "verify":
		code, err = cmdVerify(args[1:], layout, getenv, stdout)
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 2
	}
	return code
}

type treeFlags struct {
	base, head string
	asJSON     bool
}

func newFlags(name string, t *treeFlags) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&t.base, "base", "", "checkout the change is proposed against")
	f.StringVar(&t.head, "head", "", "proposed checkout")
	f.BoolVar(&t.asJSON, "json", false, "print JSON")
	return f
}

func (t treeFlags) trees() (Tree, Tree, error) {
	if t.base == "" || t.head == "" {
		return Tree{}, Tree{}, errors.New("--base and --head are required\n" + usage)
	}
	var out [2]Tree
	for i, dir := range []string{t.base, t.head} {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return Tree{}, Tree{}, err
		}
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			return Tree{}, Tree{}, fmt.Errorf("%s is not a directory", dir)
		}
		out[i] = Tree{Root: abs}
	}
	return out[0], out[1], nil
}

func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		return errors.New("command rejected\n" + usage)
	}
	return nil
}

// ClassifyOutput is the JSON form of "gate classify".
type ClassifyOutput struct {
	Schema        string    `json:"schema"`
	Paused        bool      `json:"paused"`
	Totals        Totals    `json:"totals"`
	ChainsChanged []string  `json:"chainsChanged"`
	Changes       []*Change `json:"changes"`
}

func cmdClassify(args []string, layout Layout, stdout io.Writer) (int, error) {
	var t treeFlags
	f := newFlags("gate classify", &t)
	if err := parse(f, args); err != nil {
		return 2, err
	}
	base, head, err := t.trees()
	if err != nil {
		return 2, err
	}
	cls, err := Classify(layout, base, head)
	if err != nil {
		return 2, err
	}
	tight, loose := cls.Counts()
	if t.asJSON {
		changes := cls.Changes
		if changes == nil {
			changes = []*Change{}
		}
		out := ClassifyOutput{Schema: "prufyx.io/knowledge-gate-classification/v1", Paused: cls.Paused, Totals: Totals{tight, loose}, ChainsChanged: append([]string{}, cls.ChainsChanged...), Changes: changes}
		return 0, writeJSON(stdout, out)
	}
	for _, c := range cls.Changes {
		fmt.Fprintf(stdout, "%-10s %s %s [%s] basis=%s\n", c.Class, c.Pack, c.RuleID, strings.Join(c.Kinds, ","), c.Basis)
	}
	for _, p := range cls.ChainsChanged {
		fmt.Fprintf(stdout, "chain      %s reattestation statement chain changed\n", p)
	}
	fmt.Fprintf(stdout, "%d tightening, %d loosening; kill switch %s\n", tight, loose, onOff(cls.Paused))
	return 0, nil
}

func onOff(b bool) string {
	if b {
		return "set"
	}
	return "not set"
}

func cmdLimits(args []string, layout Layout, stdout io.Writer) (int, error) {
	var t treeFlags
	var max int
	f := newFlags("gate limits", &t)
	f.IntVar(&max, "max-loosening", DefaultMaxLoosening, "cap on loosening changes")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if max < 1 {
		return 2, errors.New("--max-loosening must be at least 1")
	}
	base, head, err := t.trees()
	if err != nil {
		return 2, err
	}
	r, err := Limits(Options{Layout: layout, Base: base, Head: head, MaxLoosening: max})
	if err != nil {
		return 2, err
	}
	if t.asJSON {
		if err := writeJSON(stdout, r); err != nil {
			return 2, err
		}
	} else {
		printChecks(stdout, r)
	}
	return exitFor(r), nil
}

func exitFor(r *Report) int {
	if r.Passed() {
		return 0
	}
	return 1
}

func cmdVerify(args []string, layout Layout, getenv func(string) string, stdout io.Writer) (int, error) {
	var t treeFlags
	var source, author, bot, digest, rerun, now, report, summary string
	var max, concurrency int
	var all bool
	f := newFlags("gate verify", &t)
	f.StringVar(&source, "source", "", "upstream source for re-derivation: github or fixture:DIR")
	f.StringVar(&author, "author", "", "the change's author login")
	f.StringVar(&bot, "bot-login", DefaultBotLogin, "the automation account's login")
	f.IntVar(&max, "max-loosening", DefaultMaxLoosening, "cap on loosening changes")
	f.StringVar(&digest, "trust-root-digest", "", "pinned digest of the reattestation trust root")
	f.StringVar(&rerun, "rerun-worklist", "", "worklist from this job's own evidence repin run")
	f.BoolVar(&all, "rederive-all", false, "re-derive every active mechanical rule")
	f.IntVar(&concurrency, "concurrency", 0, "concurrent upstream reads for re-derivation")
	f.StringVar(&now, "now", "", "the gate's clock, RFC 3339 UTC (default: now)")
	f.StringVar(&report, "report", "", "write the JSON report to this file")
	f.StringVar(&summary, "summary", "", "append a Markdown summary to this file")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	base, head, err := t.trees()
	if err != nil {
		return 2, err
	}
	if max < 1 || concurrency < 0 || concurrency > 64 {
		return 2, errors.New("--max-loosening must be at least 1 and --concurrency 0-64")
	}
	opts := Options{Layout: layout, Base: base, Head: head, Author: author, BotLogin: bot, MaxLoosening: max, TrustRootDigest: digest, RederiveAll: all, Concurrency: concurrency}
	if now != "" {
		if opts.Now, err = time.Parse(time.RFC3339, now); err != nil || !strings.HasSuffix(now, "Z") {
			return 2, errors.New("--now must be RFC 3339 UTC")
		}
	}
	switch {
	case source == "":
	case source == "github":
		token := getenv("GITHUB_TOKEN")
		if token == "" {
			token = getenv("GH_TOKEN")
		}
		opts.Source = &GitHubSource{Token: token}
	case strings.HasPrefix(source, "fixture:") && len(source) > len("fixture:"):
		opts.Source = extract.FixtureReader{Root: strings.TrimPrefix(source, "fixture:")}
	default:
		return 2, errors.New("--source must be github or fixture:DIR")
	}
	if rerun != "" {
		if opts.RerunWorklist, err = os.ReadFile(rerun); err != nil {
			return 2, err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, err := Verify(ctx, opts)
	if err != nil {
		return 2, err
	}
	if report != "" {
		raw, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(report, append(raw, '\n'), 0o644); err != nil {
			return 2, err
		}
	}
	if summary != "" {
		sf, err := os.OpenFile(summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return 2, err
		}
		writeSummary(sf, r)
		if err := sf.Close(); err != nil {
			return 2, err
		}
	}
	if t.asJSON {
		if err := writeJSON(stdout, r); err != nil {
			return 2, err
		}
	} else {
		printChecks(stdout, r)
	}
	return exitFor(r), nil
}

func writeJSON(w io.Writer, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

func mark(ok bool) string {
	if ok {
		return "ok  "
	}
	return "FAIL"
}

func printChecks(w io.Writer, r *Report) {
	for _, c := range r.Changes {
		detail := c.Proof
		if !c.OK {
			detail = c.Detail
		}
		fmt.Fprintf(w, "%s %-10s %s %s [%s] basis=%s: %s\n", mark(c.OK), c.Class, c.Pack, c.RuleID, strings.Join(c.Kinds, ","), c.Basis, detail)
	}
	for _, c := range r.Checks {
		fmt.Fprintf(w, "%s check %s: %s\n", mark(c.OK), c.Name, c.Detail)
	}
	for _, a := range r.Alarms {
		fmt.Fprintf(w, "ALARM %s\n", a)
	}
	fmt.Fprintf(w, "gate: %s (%d tightening, %d loosening; kill switch %s)\n", strings.ToUpper(r.Result), r.Totals.Tightening, r.Totals.Loosening, onOff(r.Paused))
	if r.AutoMerge.Eligible {
		fmt.Fprintln(w, "auto-merge: eligible")
	} else if r.Schema != "" && r.AutoMerge.Reasons != nil {
		fmt.Fprintf(w, "auto-merge: not eligible (%s)\n", strings.Join(r.AutoMerge.Reasons, "; "))
	}
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}

func writeSummary(w io.Writer, r *Report) {
	fmt.Fprintf(w, "## Knowledge gate: %s\n\n", strings.ToUpper(r.Result))
	fmt.Fprintf(w, "%d tightening, %d loosening (cap %d); kill switch %s.\n\n", r.Totals.Tightening, r.Totals.Loosening, r.Limits.MaxLoosening, onOff(r.Paused))
	if len(r.Changes) > 0 {
		fmt.Fprintln(w, "| | Class | Pack | Rule | Kinds | Basis | Proof or reason |\n|---|---|---|---|---|---|---|")
		for _, c := range r.Changes {
			detail := c.Proof
			if !c.OK {
				detail = c.Detail
			}
			fmt.Fprintf(w, "| %s | %s | %s | `%s` | %s | %s | %s |\n", strings.TrimSpace(mark(c.OK)), c.Class, c.Pack, mdEscape(c.RuleID), strings.Join(c.Kinds, ", "), c.Basis, mdEscape(detail))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "| | Check | Detail |\n|---|---|---|")
	for _, c := range r.Checks {
		fmt.Fprintf(w, "| %s | %s | %s |\n", strings.TrimSpace(mark(c.OK)), c.Name, mdEscape(c.Detail))
	}
	fmt.Fprintln(w)
	for _, a := range r.Alarms {
		fmt.Fprintf(w, "- Alarm: %s\n", mdEscape(a))
	}
	if r.AutoMerge.Eligible {
		fmt.Fprintln(w, "\nAutomatic merge: eligible.")
	} else {
		fmt.Fprintf(w, "\nAutomatic merge: not eligible (%s).\n", mdEscape(strings.Join(r.AutoMerge.Reasons, "; ")))
	}
}
