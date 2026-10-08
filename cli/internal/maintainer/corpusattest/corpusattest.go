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
	"path"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/prufyx/prufyx/cli/internal/maintainer/treefs"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
	"github.com/prufyx/prufyx/cli/internal/validation"
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

// DocumentFromTree renders the attestation for one pack read from the files
// of a source tree (cliRoot is that tree's cli/ directory) instead of the
// embedded asset, as the exact bytes the committed asset must hold. It lets
// a checker built from one revision regenerate the attestation of another
// revision's pack, with this revision's admission rules.
func DocumentFromTree(pack, cliRoot string) ([]byte, error) {
	return DocumentFromFiles(pack, ReadRegularFile(cliRoot))
}

// MaxInputBytes bounds every input file DocumentFromFiles reads.
const MaxInputBytes = maxPackBytes

// DocumentFromFiles is DocumentFromTree with the files supplied by read,
// which is given paths relative to the cli/ directory, with forward
// slashes. A reader that refuses links and bounds sizes keeps a tree it
// does not trust from leading the read anywhere else.
func DocumentFromFiles(pack string, readFile func(rel string) ([]byte, error)) ([]byte, error) {
	read := func(rel string) ([]byte, error) {
		raw, err := readFile(rel)
		if err != nil {
			return nil, err
		}
		if len(raw) > maxPackBytes {
			return nil, fmt.Errorf("%s exceeds the reviewed bound", rel)
		}
		return raw, nil
	}
	var raw []byte
	switch pack {
	case PackCNCF:
		landscape, err := read("internal/cncfcheck/data/landscape-projects.json")
		if err != nil {
			return nil, err
		}
		priority, err := read("internal/cncfcheck/data/priority-portfolio.json")
		if err != nil {
			return nil, err
		}
		rules, err := read(targets()[PackCNCF].rulesPath)
		if err != nil {
			return nil, err
		}
		attestation, err := cncfcheck.BuildAttestationFromFiles(landscape, priority, rules)
		if err != nil {
			return nil, err
		}
		if raw, err = json.MarshalIndent(attestation, "", "  "); err != nil {
			return nil, err
		}
	case PackCommunity:
		registry, err := read("internal/projectcheck/data/projects.json")
		if err != nil {
			return nil, err
		}
		rules, err := read(targets()[PackCommunity].rulesPath)
		if err != nil {
			return nil, err
		}
		attestation, err := projectcheck.BuildAttestationFromFiles(registry, rules)
		if err != nil {
			return nil, err
		}
		if raw, err = json.MarshalIndent(attestation, "", "  "); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown rule pack")
	}
	if _, err := targets()[pack].parse(raw); err != nil {
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

// verifyPackBinding re-reads the pack file (rel below dir, read without
// following links) and confirms it hashes to the packDigest the attestation
// carries. With the embedded binding it is an independent cross-check that
// the reviewer is looking at the compiled bytes. With a tree binding it
// re-reads the file the attestation was computed from unless --rules names
// another file, so there it is a consistency check, not an independent one.
func verifyPackBinding(dir, rel, expected string) error {
	raw, err := treefs.Read(dir, rel, maxPackBytes)
	if err != nil {
		return err
	}
	if actual := sourcecorpus.SHA(raw); actual != expected {
		return fmt.Errorf("rule pack digest does not match the attested pack")
	}
	return nil
}

// location is a file as a directory (followed as given) and a path below it
// (never followed); every read and write of this command goes through it.
type location struct{ dir, rel string }

// resolveLocation is the flag value when given (its directory is the
// caller's own choice, its last element is not followed) and otherwise the
// default path below root.
func resolveLocation(flagValue, root, defaultRel string) location {
	if flagValue != "" {
		return location{dir: filepath.Dir(flagValue), rel: filepath.Base(flagValue)}
	}
	return location{dir: root, rel: defaultRel}
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
	treeDir := flags.String("tree", "", "checked-out source tree (its root or its cli/ directory) whose pack bytes the attestation is computed over and bound to; default is the pack embedded in this binary")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	selected, known := targets()[*packName]
	if !known {
		fmt.Fprintln(stderr, "corpus-attestation: command rejected")
		return 2
	}
	// The binding is explicit: either the pack embedded in this binary
	// (default) or the pack bytes of the named tree, never a mixture.
	var document []byte
	var err error
	binding := "embedded"
	if *treeDir != "" {
		treeCLI, terr := ResolveTreeCLI(*treeDir)
		if terr != nil {
			fmt.Fprintln(stderr, "corpus-attestation: tree rejected")
			return 2
		}
		cliRoot = treeCLI
		binding = "tree:" + filepath.ToSlash(treeCLI)
		document, err = DocumentFromFiles(*packName, ReadRegularFile(treeCLI))
	} else {
		document, err = DocumentFor(*packName)
	}
	if (*output == "" || *pack == "") && cliRoot == "" {
		fmt.Fprintln(stderr, "corpus-attestation: CLI root is unavailable")
		return 2
	}
	outLoc := resolveLocation(*output, cliRoot, path.Join(selected.packageDir, selected.assetPath))
	packLoc := resolveLocation(*pack, cliRoot, selected.rulesPath)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}
	attestation, err := selected.parse(document)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}
	if err := verifyPackBinding(packLoc.dir, packLoc.rel, attestation.PackDigest); err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: rule pack binding rejected")
		return 2
	}
	digest, err := Digest(document)
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: attestation rejected")
		return 2
	}

	if mode == "check" {
		current, readErr := treefs.Read(outLoc.dir, outLoc.rel, maxPackBytes)
		if readErr != nil || string(current) != string(document) {
			fmt.Fprintln(stderr, "corpus-attestation: committed attestation is stale")
			return 2
		}
		fmt.Fprintf(stdout, "corpus-attestation current: pack=%s revision=%s components=%d rules=%d digest=%s packDigest=%s binding=%s\n", *packName, attestation.Revision, attestation.Components, attestation.RuleCount, digest, attestation.PackDigest, binding)
		return 0
	}
	if err := treefs.Write(outLoc.dir, outLoc.rel, document, 0o644); err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: cannot commit the attestation")
		return 2
	}
	fmt.Fprintf(stdout, "corpus-attestation written: pack=%s revision=%s components=%d rules=%d digest=%s packDigest=%s binding=%s\n", *packName, attestation.Revision, attestation.Components, attestation.RuleCount, digest, attestation.PackDigest, binding)
	return 0
}

// treeLayout lists what a source tree's cli/ directory must hold for this
// command: both packs' data directories and every input file either pack is
// attested from. The committed attestation assets are not required (generate
// creates them).
var treeLayout = struct{ dirs, files []string }{
	dirs: []string{"internal/projectcheck/data", "internal/cncfcheck/data"},
	files: []string{
		"internal/projectcheck/data/projects.json", "internal/projectcheck/data/rules.json",
		"internal/cncfcheck/data/landscape-projects.json", "internal/cncfcheck/data/priority-portfolio.json", "internal/cncfcheck/data/rules.json",
	},
}

// hasTreeLayout reports whether dir holds the whole expected layout, every
// component a plain directory or regular file (nothing followed).
func hasTreeLayout(dir string) bool {
	for _, rel := range treeLayout.dirs {
		d, err := treefs.OpenDir(dir, rel)
		if err != nil {
			return false
		}
		d.Close()
	}
	for _, rel := range treeLayout.files {
		if kind, err := treefs.Kind(dir, rel); err != nil || kind != validation.EntryRegular {
			return false
		}
	}
	return true
}

// ResolveTreeCLI maps a --tree argument to the tree's cli/ directory. It
// accepts the tree root (which holds cli/) or the cli/ directory itself and
// rejects anything else, so a wrong path fails instead of silently falling
// back to the embedded pack. The result is deterministic: a candidate is
// accepted only when the whole expected layout is present as plain
// directories and regular files; a cli entry that is a symbolic link or not
// a directory is refused; and when both the argument and its cli/ child
// hold the layout the argument is ambiguous and is refused rather than
// guessed.
func ResolveTreeCLI(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	child := filepath.Join(abs, "cli")
	childOK := false
	switch kind, err := treefs.Kind(abs, "cli"); {
	case err == nil && kind == validation.EntryDirectory:
		childOK = hasTreeLayout(child)
	case err == nil:
		return "", fmt.Errorf("%s is not a plain directory", child)
	}
	selfOK := hasTreeLayout(abs)
	switch {
	case childOK && selfOK:
		return "", fmt.Errorf("ambiguous tree: both %s and its cli/ directory hold the source layout", abs)
	case childOK:
		return child, nil
	case selfOK:
		return abs, nil
	}
	return "", fmt.Errorf("not a source tree")
}

// ReadRegularFile reads files below root (paths relative to it, forward
// slashes) with the knowledge gate's reader semantics: no symbolic link on
// any component below root, a file opened without blocking so a FIFO or
// device is refused, type and size checked on the open descriptor, and the
// size bound applied before the content is read.
func ReadRegularFile(root string) func(rel string) ([]byte, error) {
	return func(rel string) ([]byte, error) {
		return treefs.Read(root, rel, MaxInputBytes)
	}
}
