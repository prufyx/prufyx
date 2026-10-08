// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

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
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

const usage = `usage:
  prufyx-maintainer gate export   --git-dir DIR --commit SHA --out DIR
  prufyx-maintainer gate classify --base DIR --head DIR [--json]
  prufyx-maintainer gate daily-count --git-dir DIR --commits FILE [--bot-login LOGIN]
  prufyx-maintainer gate limits   --base DIR --head DIR [--max-loosening N] [--json]
                                  [--max-withdraw-percent N] [--max-withdraw-project N]
                                  [--daily-loosening-count N] [--max-daily-loosening N]
  prufyx-maintainer gate verify   --base DIR --head DIR [--source github|fixture:DIR]
                                  [--author LOGIN] [--sender LOGIN] [--owner-login LOGIN] [--bot-login LOGIN]
                                  [--head-sha SHA] [--commits FILE] [--max-loosening N]
                                  [--trust-root-digest sha256:...] [--approval-keys-digest sha256:...]
                                  [--rerun-worklist FILE]
                                  [--rederive-all] [--concurrency N] [--now RFC3339]
                                  [--max-withdraw-percent N] [--max-withdraw-project N]
                                  [--daily-loosening-count N] [--max-daily-loosening N] [--shadow]
                                  [--report FILE] [--summary FILE]
                                  [--metrics FILE] [--alarms FILE] [--alarms-markdown FILE]`

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
	case "export":
		code, err = cmdExport(args[1:])
	case "classify":
		code, err = cmdClassify(args[1:], layout, stdout)
	case "daily-count":
		code, err = cmdDailyCount(args[1:], layout, stdout)
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
		fmt.Fprintf(stderr, "gate: %s\n", logSafe(err.Error()))
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

func cmdExport(args []string) (int, error) {
	var o ExportOptions
	f := flag.NewFlagSet("gate export", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.GitDir, "git-dir", "", "repository holding the commit")
	f.StringVar(&o.Commit, "commit", "", "full commit id to export")
	f.StringVar(&o.Out, "out", "", "directory to create")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if o.GitDir == "" || o.Commit == "" || o.Out == "" {
		return 2, errors.New("--git-dir, --commit and --out are required\n" + usage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := Export(ctx, o); err != nil {
		return 2, err
	}
	return 0, nil
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
		fmt.Fprintf(stdout, "%-10s %s %s [%s] basis=%s\n", c.Class, c.Pack, c.subject(), strings.Join(c.Kinds, ","), logSafe(c.Basis))
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
	var m monitorFlags
	f := newFlags("gate limits", &t)
	f.IntVar(&max, "max-loosening", DefaultMaxLoosening, "cap on loosening changes")
	m.register(f)
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if max < 1 {
		return 2, errors.New("--max-loosening must be at least 1")
	}
	if err := m.validate(); err != nil {
		return 2, err
	}
	base, head, err := t.trees()
	if err != nil {
		return 2, err
	}
	opts := Options{Layout: layout, Base: base, Head: head, MaxLoosening: max}
	m.apply(&opts)
	r, err := Limits(opts)
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
	var source, author, sender, owner, bot, headSHA, commits, digest, keysDigest, rerun, now, report, summary string
	var max, concurrency int
	var citeTimeout time.Duration
	var all, shadow bool
	var metricsFile, alarmsFile, alarmsMD string
	var m monitorFlags
	f := newFlags("gate verify", &t)
	m.register(f)
	f.BoolVar(&shadow, "shadow", false, "shadow mode: compute everything, never be eligible for automatic merging")
	f.StringVar(&metricsFile, "metrics", "", "write the metrics JSON to this file")
	f.StringVar(&alarmsFile, "alarms", "", "write the alarms JSON to this file")
	f.StringVar(&alarmsMD, "alarms-markdown", "", "write the alarms as a Markdown list to this file")
	f.StringVar(&source, "source", "", "upstream source for re-derivation: github or fixture:DIR")
	f.StringVar(&author, "author", "", "the change's author login")
	f.StringVar(&sender, "sender", "", "the login of the account whose action triggered this run")
	f.StringVar(&headSHA, "head-sha", "", "the head commit being checked")
	f.StringVar(&commits, "commits", "", "the change's commit list (GitHub compare API JSON)")
	f.StringVar(&keysDigest, "approval-keys-digest", "", "pinned digest of the owner approval key file")
	f.StringVar(&owner, "owner-login", DefaultOwnerLogin, "the repository owner's login; only the owner's change may supersede a reviewed rule")
	f.StringVar(&bot, "bot-login", DefaultBotLogin, "the automation account's login")
	f.IntVar(&max, "max-loosening", DefaultMaxLoosening, "cap on loosening changes")
	f.StringVar(&digest, "trust-root-digest", "", "pinned digest of the reattestation trust root")
	f.StringVar(&rerun, "rerun-worklist", "", "worklist from this job's own evidence repin run")
	f.BoolVar(&all, "rederive-all", false, "re-derive every active mechanical rule and mechanical line attestation")
	f.IntVar(&concurrency, "concurrency", 0, "concurrent upstream reads for re-derivation")
	f.DurationVar(&citeTimeout, "citations-timeout", rulecheck.DefaultCitationTimeout, "overall deadline of the citation verification; a run that does not finish in time fails the citations check")
	f.StringVar(&now, "now", "", "the gate's clock, RFC 3339 UTC (default: now)")
	f.StringVar(&report, "report", "", "write the JSON report to this file")
	f.StringVar(&summary, "summary", "", "append a Markdown summary to this file")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if err := m.validate(); err != nil {
		return 2, err
	}
	base, head, err := t.trees()
	if err != nil {
		return 2, err
	}
	if max < 1 || concurrency < 0 || concurrency > 64 || citeTimeout <= 0 {
		return 2, errors.New("--max-loosening must be at least 1, --concurrency 0-64 and --citations-timeout positive")
	}
	opts := Options{Layout: layout, Base: base, Head: head, Author: author, Sender: sender, Owner: owner, BotLogin: bot, HeadSHA: headSHA, MaxLoosening: max, TrustRootDigest: digest, ApprovalKeysDigest: keysDigest, RederiveAll: all, Concurrency: concurrency, Shadow: shadow}
	m.apply(&opts)
	if commits != "" {
		raw, err := readBoundedFile(commits, maxCommitListBytes)
		if err != nil {
			return 2, err
		}
		if opts.Commits, err = ParseCommitList(raw); err != nil {
			return 2, err
		}
	}
	if now != "" {
		if opts.Now, err = time.Parse(time.RFC3339, now); err != nil || !strings.HasSuffix(now, "Z") {
			return 2, errors.New("--now must be RFC 3339 UTC")
		}
	}
	if opts.Source, opts.Citations, err = sourceFlag(source, citeTimeout, getenv); err != nil {
		return 2, err
	}
	if rerun != "" {
		if opts.RerunWorklist, err = readBoundedFile(rerun, MaxFileBytes); err != nil {
			return 2, err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	started := time.Now()
	r, err := Verify(ctx, opts)
	if err != nil {
		return 2, err
	}
	if metricsFile != "" {
		raw, err := marshalFile(NewMetrics(r, time.Since(started)))
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(metricsFile, raw, 0o644); err != nil {
			return 2, err
		}
	}
	if alarmsFile != "" || alarmsMD != "" {
		doc := NewAlarmsDocument(r)
		if alarmsFile != "" {
			raw, err := marshalFile(doc)
			if err != nil {
				return 2, err
			}
			if err := os.WriteFile(alarmsFile, raw, 0o644); err != nil {
				return 2, err
			}
		}
		if alarmsMD != "" {
			var b bytes.Buffer
			WriteAlarmsMarkdown(&b, doc)
			if err := os.WriteFile(alarmsMD, b.Bytes(), 0o644); err != nil {
				return 2, err
			}
		}
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

// readBoundedFile reads a file this job produced, up to limit bytes.
func readBoundedFile(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return raw, nil
}

func writeJSON(w io.Writer, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// subject names what a change concerns, safe to print.
func (c *Change) subject() string {
	if c.Member != "" {
		return "member:" + logSafe(c.Member)
	}
	if c.Section != "" {
		return logSafe(c.Section) + ":" + logSafe(c.RuleID)
	}
	return logSafe(c.RuleID)
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
		fmt.Fprintf(w, "%s %-10s %s %s [%s] basis=%s: %s\n", mark(c.OK), c.Class, c.Pack, c.subject(), strings.Join(c.Kinds, ","), logSafe(c.Basis), logSafe(detail))
	}
	for _, c := range r.Checks {
		fmt.Fprintf(w, "%s check %s: %s\n", mark(c.OK), c.Name, logSafe(c.Detail))
	}
	for _, p := range r.Supersedes {
		fmt.Fprintf(w, "%s supersede %s: %s -> %s\n", mark(p.OK), p.Pack, logSafe(p.Old), logSafe(p.New))
	}
	for _, a := range r.Alarms {
		fmt.Fprintf(w, "ALARM %s\n", logSafe(a))
	}
	fmt.Fprintf(w, "gate: %s (%d tightening, %d loosening; kill switch %s; mode %s)\n", strings.ToUpper(r.Result), r.Totals.Tightening, r.Totals.Loosening, onOff(r.Paused), r.Mode)
	if r.AutoMerge.Eligible {
		fmt.Fprintln(w, "auto-merge: eligible")
	} else if r.Schema != "" && r.AutoMerge.Reasons != nil {
		fmt.Fprintf(w, "auto-merge: not eligible (%s)\n", logSafe(strings.Join(r.AutoMerge.Reasons, "; ")))
	}
}

func mdEscape(s string) string {
	// Pipes, HTML, code spans, line breaks, and link or image syntax from
	// the proposed change are neutralised.
	return strings.NewReplacer("&", "&amp;", "|", "\\|", "<", "&lt;", ">", "&gt;", "`", "'", "\n", " ", "\r", " ",
		"[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "!", "\\!").Replace(s)
}

func writeSummary(w io.Writer, r *Report) {
	fmt.Fprintf(w, "## Knowledge gate: %s\n\n", strings.ToUpper(r.Result))
	if r.Mode == ModeShadow {
		fmt.Fprint(w, "Shadow mode: this change is never eligible for automatic merging.\n\n")
	}
	fmt.Fprintf(w, "%d tightening, %d loosening (cap %d); kill switch %s.\n\n", r.Totals.Tightening, r.Totals.Loosening, r.Limits.MaxLoosening, onOff(r.Paused))
	if len(r.Changes) > 0 {
		fmt.Fprintln(w, "| | Class | Pack | Rule | Kinds | Basis | Proof or reason |\n|---|---|---|---|---|---|---|")
		for _, c := range r.Changes {
			detail := c.Proof
			if !c.OK {
				detail = c.Detail
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s |\n", strings.TrimSpace(mark(c.OK)), c.Class, c.Pack, mdEscape(c.subject()), strings.Join(c.Kinds, ", "), mdEscape(c.Basis), mdEscape(detail))
		}
		fmt.Fprintln(w)
	}
	if len(r.Supersedes) > 0 {
		fmt.Fprintln(w, "| | Superseded rule | Replaced by |\n|---|---|---|")
		for _, p := range r.Supersedes {
			fmt.Fprintf(w, "| %s | %s | %s |\n", strings.TrimSpace(mark(p.OK)), mdEscape(p.Pack+"/"+p.Old), mdEscape(p.New))
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

// maxLogField bounds one proposed-change string in the gate's text output.
const maxLogField = 512

// logSafe makes a string from the proposed change safe to print in a CI
// log: no line breaks or other control characters (so it can never start
// a line, and so never form a workflow command), "%" and "::" escaped, and
// the length capped.
func logSafe(s string) string {
	var b strings.Builder
	for i, r := range s {
		if b.Len() >= maxLogField {
			b.WriteString(fmt.Sprintf("...(%d more bytes)", len(s)-i))
			break
		}
		switch {
		case r == '%':
			b.WriteString("%25")
		case r == ':' && strings.HasPrefix(s[i:], "::"):
			b.WriteString("%3A")
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || r == 0x85:
			b.WriteString(fmt.Sprintf("%%%02X", r))
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], "�"):
			b.WriteString("%FF")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// monitorFlags are the breaker and daily-limit flags shared by "limits"
// and "verify".
type monitorFlags struct {
	withdrawPercent, withdrawProject, dailyCount, maxDaily int
}

func (m *monitorFlags) register(f *flag.FlagSet) {
	f.IntVar(&m.withdrawPercent, "max-withdraw-percent", DefaultMaxWithdrawPercent, "breaker: percent of a pack's active rules one change may withdraw")
	f.IntVar(&m.withdrawProject, "max-withdraw-project", DefaultMaxWithdrawProject, "breaker: rules of one project one change may withdraw")
	f.IntVar(&m.dailyCount, "daily-loosening-count", -1, "loosening changes the automation merged in the last day (default: unknown)")
	f.IntVar(&m.maxDaily, "max-daily-loosening", DefaultMaxDailyLoosening, "cap on the daily count plus this change")
}

func (m monitorFlags) validate() error {
	switch {
	case m.withdrawPercent < 1 || m.withdrawPercent > 100:
		return errors.New("--max-withdraw-percent must be 1-100")
	case m.withdrawProject < 1:
		return errors.New("--max-withdraw-project must be at least 1")
	case m.maxDaily < 1:
		return errors.New("--max-daily-loosening must be at least 1")
	case m.dailyCount < -1 || m.dailyCount > 1_000_000:
		return errors.New("--daily-loosening-count must be 0-1000000")
	}
	return nil
}

func (m monitorFlags) apply(o *Options) {
	o.MaxWithdrawPercent, o.MaxWithdrawProject, o.MaxDailyLoosening = m.withdrawPercent, m.withdrawProject, m.maxDaily
	if m.dailyCount >= 0 {
		n := m.dailyCount
		o.DailyLoosening = &n
	}
}

func cmdDailyCount(args []string, layout Layout, stdout io.Writer) (int, error) {
	var gitDir, commits, bot string
	f := flag.NewFlagSet("gate daily-count", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&gitDir, "git-dir", "", "repository holding the commits and their parents")
	f.StringVar(&commits, "commits", "", "the main branch's commits of the last day (JSON)")
	f.StringVar(&bot, "bot-login", DefaultBotLogin, "the automation account's login")
	if err := parse(f, args); err != nil {
		return 2, err
	}
	if gitDir == "" || commits == "" {
		return 2, errors.New("--git-dir and --commits are required\n" + usage)
	}
	raw, err := readBoundedFile(commits, maxDailyCommitsFile)
	if err != nil {
		return 2, err
	}
	list, err := ParseDailyCommits(raw)
	if err != nil {
		return 2, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	n, err := DailyCount(ctx, layout, gitDir, list, bot)
	if err != nil {
		return 2, err
	}
	fmt.Fprintln(stdout, n)
	return 0, nil
}

// sourceFlag turns --source into the gate's upstream reader and citation
// checker: github installs the real ones (the same token for both), fixture
// the offline pair (whose citation mode never passes), and no source leaves
// both nil, which fails closed.
func sourceFlag(source string, citeTimeout time.Duration, getenv func(string) string) (Source, CitationChecker, error) {
	switch {
	case source == "":
		return nil, nil, nil
	case source == "github":
		token := getenv("GITHUB_TOKEN")
		if token == "" {
			token = getenv("GH_TOKEN")
		}
		return &GitHubSource{Token: token}, &rulecheck.CitationVerifier{Resolver: rulecheck.NewGitHubObjects(token), Fetcher: rulecheck.HTTPFetcher{}, Concurrency: 4, Timeout: citeTimeout}, nil
	case strings.HasPrefix(source, "fixture:") && len(source) > len("fixture:"):
		return extract.FixtureReader{Root: strings.TrimPrefix(source, "fixture:")}, OfflineCitations{}, nil
	}
	return nil, nil, errors.New("--source must be github or fixture:DIR")
}
