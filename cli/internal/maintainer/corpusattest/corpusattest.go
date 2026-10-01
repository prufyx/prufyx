// SPDX-License-Identifier: AGPL-3.0-only

// Package corpusattest emits the maintainer's corpus-completeness attestation
// over an UNFILTERED embedded rule pack — the community-project pack by
// default, or the CNCF pack with --pack cncf.
//
// The attestation is the maintainer asserting, per component, that every
// reviewed rule they hold for that component is present in this pack at this
// revision. It authors no compatibility claim: every rule it covers was
// already reviewed and is already shipped. Its only job is to let the engine
// tell "this is the complete applicable corpus" apart from "these are the
// rules the caller happened to select".
//
// It is deliberately computed over the whole pack. A filtered view cannot
// support a completeness statement, so this command never narrows by project
// or by version pair.
package corpusattest

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

const maxPackBytes = 4 << 20

// PackCommunity and PackCNCF name the two embedded corpora this command can
// attest. Each is attested separately and over its own unfiltered pack; there
// is deliberately no combined attestation, because the two packs carry
// independent revisions, digests and component sets.
const (
	PackCommunity = "community"
	PackCNCF      = "cncf"
)

// target binds one embedded pack to the paths and the parser that describe it.
// Every field is derived from the compiled package; nothing here is declared
// by the caller beyond which of the two packs to attest.
type target struct {
	packageDir string
	rulesPath  string
	assetPath  string
	// build renders the attestation for the current embedded pack, and parse
	// is the same parser the runtime uses to read the emitted asset back.
	build func() ([]byte, error)
	parse func([]byte) (attested, error)
}

// attested is the small read-only view of an attestation this command needs.
// It keeps the two packs' concrete Attestation types out of the command.
type attested struct {
	Revision   string
	PackDigest string
	Components int
	RuleCount  int
}

func targets() map[string]target {
	return map[string]target{
		PackCommunity: {
			packageDir: "internal/projectcheck",
			rulesPath:  "internal/projectcheck/data/rules.json",
			assetPath:  projectcheck.AttestationPath,
			build: func() ([]byte, error) {
				attestation, err := projectcheck.BuildAttestation()
				if err != nil {
					return nil, err
				}
				return json.MarshalIndent(attestation, "", "  ")
			},
			parse: func(raw []byte) (attested, error) {
				attestation, err := projectcheck.ParseAttestation(raw)
				if err != nil {
					return attested{}, err
				}
				return attested{Revision: attestation.Revision, PackDigest: attestation.PackDigest, Components: len(attestation.Components), RuleCount: attestation.RuleCount}, nil
			},
		},
		PackCNCF: {
			packageDir: "internal/cncfcheck",
			rulesPath:  "internal/cncfcheck/data/rules.json",
			assetPath:  cncfcheck.AttestationPath,
			build: func() ([]byte, error) {
				attestation, err := cncfcheck.BuildAttestation()
				if err != nil {
					return nil, err
				}
				return json.MarshalIndent(attestation, "", "  ")
			},
			parse: func(raw []byte) (attested, error) {
				attestation, err := cncfcheck.ParseAttestation(raw)
				if err != nil {
					return attested{}, err
				}
				return attested{Revision: attestation.Revision, PackDigest: attestation.PackDigest, Components: len(attestation.Components), RuleCount: attestation.RuleCount}, nil
			},
		},
	}
}

// Document renders the attestation for the community pack. It is the original
// entry point and is unchanged; DocumentFor covers the other packs.
func Document() ([]byte, error) { return DocumentFor(PackCommunity) }

// DocumentFor renders the attestation for one embedded pack as the exact bytes
// the asset holds: indented JSON with a trailing newline.
func DocumentFor(pack string) ([]byte, error) {
	selected, ok := targets()[pack]
	if !ok {
		return nil, fmt.Errorf("unknown rule pack")
	}
	raw, err := selected.build()
	if err != nil {
		return nil, err
	}
	// Round-trip through the same parser the runtime uses. An attestation this
	// command cannot itself parse must never reach the asset.
	if _, err := selected.parse(raw); err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// Digest is the attestation's canonical digest, computed with the reviewed
// corpus hashing helper rather than a second SHA-256 implementation.
func Digest(document []byte) (string, error) {
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		return "", err
	}
	canonical, err := sourcecorpus.Canonical(value)
	if err != nil {
		return "", err
	}
	return sourcecorpus.SHA(canonical), nil
}

// verifyPackBinding re-reads the pack file in the working tree and confirms it
// hashes to the packDigest the embedded pack produced. It is an independent
// cross-check: the digest inside the attestation is computed from the compiled
// asset, and this confirms the reviewer is looking at the same bytes.
func verifyPackBinding(packPath, expected string) error {
	raw, err := os.ReadFile(packPath)
	if err != nil {
		return err
	}
	if len(raw) > maxPackBytes {
		return fmt.Errorf("rule pack exceeds the reviewed bound")
	}
	if actual := sourcecorpus.SHA(raw); actual != expected {
		return fmt.Errorf("rule pack digest does not match the embedded pack")
	}
	return nil
}

// Run is the maintainer subcommand adapter. It follows the same
// (args, stdout, stderr) int shape as the other maintainer commands.
func Run(args []string, stdout, stderr io.Writer, cliRoot string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	mode := args[0]
	if mode != "generate" && mode != "check" {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	flags := flag.NewFlagSet("corpus-attestation "+mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	packName := flags.String("pack", PackCommunity, "rule pack to attest: community or cncf")
	output := flags.String("output", "", "attestation asset path")
	pack := flags.String("rules", "", "rule pack file the attestation is bound to")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	selected, known := targets()[*packName]
	if !known {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	if *output == "" {
		*output = filepath.Join(cliRoot, selected.packageDir, selected.assetPath)
	}
	if *pack == "" {
		*pack = filepath.Join(cliRoot, selected.rulesPath)
	}

	document, err := DocumentFor(*packName)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}
	attestation, err := selected.parse(document)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}
	if err := verifyPackBinding(*pack, attestation.PackDigest); err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: rule pack binding rejected")
		return 2
	}
	digest, err := Digest(document)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}

	if mode == "check" {
		current, readErr := os.ReadFile(*output)
		if readErr != nil || string(current) != string(document) {
			fmt.Fprintln(stderr, "corpus-attestation: committed attestation is stale")
			return 2
		}
		fmt.Fprintf(stdout, "corpus-attestation current: pack=%s revision=%s components=%d rules=%d digest=%s\n", *packName, attestation.Revision, attestation.Components, attestation.RuleCount, digest)
		return 0
	}
	if err := os.WriteFile(*output, document, 0o644); err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: cannot commit the attestation")
		return 2
	}
	fmt.Fprintf(stdout, "corpus-attestation written: pack=%s revision=%s components=%d rules=%d digest=%s\n", *packName, attestation.Revision, attestation.Components, attestation.RuleCount, digest)
	return 0
}
