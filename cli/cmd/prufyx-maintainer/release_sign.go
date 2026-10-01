// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releaseworkflow"
)

// init installs the terminal-only passphrase prompt for release signing. The
// workflow package deliberately owns no terminal access, so a non-interactive
// process can never be coaxed into unlocking a signing key.
func init() {
	releaseworkflow.ReadSigningPassphrase = func(stderr io.Writer) ([]byte, error) {
		return promptPassphrase(stderr, false)
	}
}

// runReleaseSign creates a new offline release signing key and its matching
// single-key trust root. It grants no publication authority: the operator
// still decides whether the resulting root is the one downloaders should pin.
func runReleaseSign(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return releaseSignError()
	}
	switch args[0] {
	case "init":
		return runReleaseSignInit(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, err := fmt.Fprintln(stdout, "usage: prufyx-maintainer release-sign init --key-dir ABSOLUTE_NEW_DIR --expires UTC_RFC3339")
		return err
	default:
		return releaseSignError()
	}
}

func runReleaseSignInit(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("release-sign init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyDir := flags.String("key-dir", "", "new absolute private key directory outside a Git checkout")
	expires := flags.String("expires", "", "future trust-root expiry as exact UTC RFC3339")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, writeErr := fmt.Fprintln(stdout, "usage: prufyx-maintainer release-sign init --key-dir ABSOLUTE_NEW_DIR --expires UTC_RFC3339")
			return writeErr
		}
		return releaseSignError()
	}
	if flags.NArg() != 0 || *keyDir == "" || *expires == "" || releasesign.ValidateInitRequest(*keyDir, *expires) != nil {
		return releaseSignError()
	}
	passphrase, err := promptPassphrase(stderr, true)
	if err != nil {
		return releaseSignError()
	}
	result, err := releasesign.Init(releasesign.InitOptions{KeyDir: *keyDir, Expires: *expires, Passphrase: passphrase})
	if err != nil {
		return releaseSignError()
	}
	encoded, err := json.Marshal(struct {
		Status          string `json:"status"`
		KeyID           string `json:"keyId"`
		TrustRootDigest string `json:"trustRootDigest"`
		NetworkUsed     bool   `json:"networkUsed"`
		KeyCustody      string `json:"keyCustody"`
	}{"INITIALIZED", result.KeyID, result.TrustRootDigest, false, "local-encrypted-file"})
	if err != nil {
		return releaseSignError()
	}
	if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
		return &commandError{code: 2, message: "release-sign: receipt output failed"}
	}
	return nil
}

func releaseSignError() error {
	return &commandError{code: 2, message: "release-sign: operation rejected"}
}
