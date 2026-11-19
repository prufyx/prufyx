// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepinguard"
)

var pinGuardRepoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)

// runPinGuard refuses, with exit 21, unless the oldest-supported-client pin
// may be advertised by the knowledge feed. It only reads, through the GitHub
// CLI and the token in GH_TOKEN, which must be read-only.
func runPinGuard(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("knowledge-publish pin-guard", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var repo, pinFile string
	var allow, recheck bool
	flags.StringVar(&repo, "repo", "", "owner/name of the repository that publishes the releases")
	flags.StringVar(&pinFile, "pin-file", "", "absolute path of oldest-supported-client.txt")
	flags.BoolVar(&allow, "allow-downgrade", false, "accept a pin lower than the last published pin; only for the job inside the owner-approved environment")
	flags.BoolVar(&recheck, "recheck-tag", false, "only resolve the pinned tag again and refuse unless it points to the pinned ref")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !pinGuardRepoRE.MatchString(repo) || !filepath.IsAbs(pinFile) {
		return knowledgePublishError()
	}
	raw, err := os.ReadFile(pinFile)
	if err != nil {
		return pinGuardRefusal(fmt.Errorf("the pin file cannot be read: %v", err))
	}
	work, err := os.MkdirTemp("", "pin-guard-")
	if err != nil {
		return pinGuardRefusal(err)
	}
	defer os.RemoveAll(work)
	g := knowledgepinguard.GH{Repo: repo, WorkDir: work, Run: runGH}
	if recheck {
		if allow {
			return knowledgePublishError()
		}
		if err := knowledgepinguard.Recheck(raw, g); err != nil {
			return pinGuardRefusal(err)
		}
		return printJSON(stdout, map[string]any{"status": "OK", "recheck": true})
	}
	res, err := knowledgepinguard.Check(raw, g, knowledgepinguard.Options{AllowDowngrade: allow})
	if err != nil {
		return pinGuardRefusal(err)
	}
	return printJSON(stdout, map[string]any{"status": "OK", "version": res.Version, "ref": res.Ref, "legacy": res.Legacy, "downgrade": res.Downgrade, "notes": res.Notes})
}

func pinGuardRefusal(err error) error {
	var r *knowledgepinguard.Refusal
	msg := err.Error()
	if !errors.As(err, &r) {
		msg = "pin refused: " + msg
	}
	code := knowledgepinguard.ExitCode
	if errors.As(err, &r) && r.DowngradeOnly {
		code = knowledgepinguard.ExitDowngradeOnly
	}
	return &commandError{code: code, message: "knowledge-publish pin-guard: " + msg + "; nothing was signed and the feed keeps the last package"}
}

// runGH runs the GitHub CLI; the error carries its standard error text.
func runGH(args ...string) ([]byte, error) {
	cmd := exec.Command("gh", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gh %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}
