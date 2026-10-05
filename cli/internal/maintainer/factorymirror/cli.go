// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const usage = `usage:
  prufyx-maintainer factory mirror --state DIR --registry FILE [--wants FILE] [--concurrency N] [--force]
                                   [--release-pages N] [--remote-base URL]
                                   [--test-allow-file-remote [--test-releases-api-base URL]]
  prufyx-maintainer factory registry derive --out FILE [--rules FILE]... [--extra FILE]... [--wants-out FILE]
  prufyx-maintainer factory ack --state DIR --repo OWNER/REPO [--alarm ID] --note TEXT
  prufyx-maintainer factory status --state DIR`

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// RepeatableFlags returns the options that may be given more than once for
// the given arguments (the factory subcommand tree).
func RepeatableFlags(args []string) []string {
	if len(args) > 2 && args[0] == "factory" && args[1] == "registry" && args[2] == "derive" {
		return []string{"--rules", "--extra"}
	}
	return nil
}

// Main runs a "factory" subcommand. args excludes the word "factory".
// DefaultRulePacks are used by "registry derive" when --rules is not given.
// It returns a process exit code: 0 success, 1 operational failure (some
// repository could not be mirrored), 2 rejected input.
func Main(args []string, defaultRulePacks []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var err error
	code := 0
	switch {
	case args[0] == "mirror":
		code, err = cmdMirror(args[1:], getenv, stdout, stderr)
	case args[0] == "registry" && len(args) > 1 && args[1] == "derive":
		err = cmdDerive(args[2:], defaultRulePacks, stdout)
	case args[0] == "ack":
		err = cmdAck(args[1:], stdout)
	case args[0] == "status":
		err = cmdStatus(args[1:], stdout)
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "factory: %v\n", err)
		if errors.Is(err, ErrLocked) {
			return 1
		}
		return 2
	}
	return code
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

func cmdMirror(args []string, getenv func(string) string, stdout, stderr io.Writer) (int, error) {
	f := newFlags("factory mirror", stderr)
	state := f.String("state", "", "state directory")
	registry := f.String("registry", "", "registry file")
	wantsFile := f.String("wants", "", "JSON file listing pinned files to materialize")
	concurrency := f.Int("concurrency", 4, "simultaneous repositories (1-16)")
	force := f.Bool("force", false, "fetch even when upstream looks unchanged")
	remoteBase := f.String("remote-base", "https://", "URL prefix for upstream repositories (https:// only)")
	releasePages := f.Int("release-pages", DefaultReleasePages, "release pages (20 per page) to read per repository; 0 reads all of them")
	allowFile := f.Bool("test-allow-file-remote", false, "testing only: permit a file:// --remote-base")
	testAPIBase := f.String("test-releases-api-base", "", "testing only (needs --test-allow-file-remote): read release metadata from this http(s) base URL instead of api.github.com")
	gitTimeout := f.Duration("git-timeout", 45*time.Minute, "limit for one clone or fetch")
	staleAfter := f.Duration("lock-stale-after", DefaultLockStaleAfter, "age after which an unrefreshed lock is abandoned")
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		return 0, fmt.Errorf("%w: mirror options", ErrInvalid)
	}
	if *releasePages < 0 {
		return 0, fmt.Errorf("%w: --release-pages must not be negative", ErrInvalid)
	}
	if *state == "" || *registry == "" {
		return 0, fmt.Errorf("%w: --state and --registry are required", ErrInvalid)
	}
	repos, err := LoadRegistry(*registry)
	if err != nil {
		return 0, err
	}
	var wants []Want
	if *wantsFile != "" {
		raw, err := readBounded(*wantsFile, maxRulePackBytes)
		if err != nil {
			return 0, err
		}
		var doc struct {
			Wants []Want `json:"wants"`
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			return 0, fmt.Errorf("%w: wants: %v", ErrInvalid, err)
		}
		wants = doc.Wants
	}
	apiBase, err := validateTestAPIBase(*testAPIBase, *allowFile)
	if err != nil {
		return 0, err
	}
	tokens, err := TokenSourceFromEnvBase(getenv, time.Now, apiBase)
	if err != nil {
		return 0, err
	}
	opts := Options{
		StateDir: *state, Repos: repos, Wants: wants, RemoteBase: *remoteBase, AllowFileRemote: *allowFile,
		Concurrency: *concurrency, Force: *force, GitTimeout: *gitTimeout,
		LockStaleAfter: *staleAfter, Progress: stderr,
	}
	if tokens != nil {
		opts.Releases = GitHubReleases{Tokens: tokens, BaseURL: apiBase, MaxPages: *releasePages, CompleteScan: *releasePages == 0}
	} else {
		fmt.Fprintln(stderr, "mirror: no GitHub credential configured; release metadata is recorded as unknown")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := Run(ctx, opts)
	if res != nil {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	}
	if err != nil {
		if errors.Is(err, ErrLocked) || errors.Is(err, ErrInvalid) {
			return 0, err
		}
		fmt.Fprintf(stderr, "factory: %v\n", err)
		return 1, nil
	}
	if res.Failed > 0 {
		return 1, nil
	}
	for _, w := range res.Wants {
		if !w.Complete {
			return 1, nil
		}
	}
	return 0, nil
}

// validateTestAPIBase checks the test-only releases API base. It is refused
// unless the test flag that permits a file:// remote is also set, so a
// production run can never send its credential to another host. It returns
// the base without a trailing slash, or "" when none was given.
func validateTestAPIBase(base string, allowTestRemotes bool) (string, error) {
	if base == "" {
		return "", nil
	}
	if !allowTestRemotes {
		return "", fmt.Errorf("%w: --test-releases-api-base needs --test-allow-file-remote", ErrInvalid)
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(base, "?#") {
		return "", fmt.Errorf("%w: --test-releases-api-base must be an http(s) URL without credentials, query or fragment", ErrInvalid)
	}
	return strings.TrimRight(base, "/"), nil
}

func cmdDerive(args []string, defaultPacks []string, stdout io.Writer) error {
	f := newFlags("factory registry derive", io.Discard)
	out := f.String("out", "", "registry file to write")
	wantsOut := f.String("wants-out", "", "optional: write the pinned files cited by the packs")
	var rules, extra stringList
	f.Var(&rules, "rules", "rule pack (repeatable; default: the shipped packs)")
	f.Var(&extra, "extra", "extra registry file to union in (repeatable)")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *out == "" {
		return fmt.Errorf("%w: derive options", ErrInvalid)
	}
	packs := []string(rules)
	if len(packs) == 0 {
		packs = defaultPacks
	}
	repos, err := DeriveFromRulePacks(packs, extra)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(*out, MarshalRegistry(repos)); err != nil {
		return err
	}
	if *wantsOut != "" {
		wants, err := WantsFromRulePacks(packs)
		if err != nil {
			return err
		}
		raw, _ := json.MarshalIndent(map[string]any{"wants": wants}, "", "  ")
		if err := writeFileAtomic(*wantsOut, append(raw, '\n')); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "registry: %d repositories written to %s\n", len(repos), filepath.Base(*out))
	return nil
}

func cmdAck(args []string, stdout io.Writer) error {
	f := newFlags("factory ack", io.Discard)
	state := f.String("state", "", "state directory")
	repo := f.String("repo", "", "repository (owner/repo)")
	alarm := f.String("alarm", "", "alarm id (default: all open alarms of the repository)")
	note := f.String("note", "", "why the alarm was reviewed")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *state == "" || *repo == "" || strings.TrimSpace(*note) == "" {
		return fmt.Errorf("%w: ack options (--state, --repo and --note are required)", ErrInvalid)
	}
	n, err := Acknowledge(*state, *repo, *alarm, *note, time.Now)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "acknowledged %d alarm(s)\n", n)
	return nil
}

func cmdStatus(args []string, stdout io.Writer) error {
	f := newFlags("factory status", io.Discard)
	state := f.String("state", "", "state directory")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *state == "" {
		return fmt.Errorf("%w: status options", ErrInvalid)
	}
	idx, err := LoadIndex(*state)
	if err != nil {
		return err
	}
	summary := map[string]any{"repos": len(idx.Repos), "openAlarms": idx.OpenAlarms(), "updatedAt": idx.UpdatedAt}
	var frozen, failed, relUnknown []string
	for k, r := range idx.Repos {
		if r.Frozen {
			frozen = append(frozen, k)
		}
		if r.Status != "ok" {
			failed = append(failed, k)
		}
		if r.Releases.Status != ReleasesKnown {
			relUnknown = append(relUnknown, k)
		}
	}
	sortStrings(frozen, failed, relUnknown)
	summary["frozen"], summary["notOk"], summary["releasesNotKnown"] = frozen, failed, relUnknown
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}
