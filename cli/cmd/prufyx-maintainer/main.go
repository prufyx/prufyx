// SPDX-License-Identifier: AGPL-3.0-only

// Command prufyx-maintainer provides local, bounded Community maintenance tools.
// It is separate from the end-user compatibility CLI and grants no publication authority.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/contribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/corpusattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgeexport"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepack"
	"github.com/prufyx/prufyx/cli/internal/maintainer/localkind"
	"github.com/prufyx/prufyx/cli/internal/maintainer/projectonboarding"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasegate"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasehelpers"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releaseworkflow"
	"github.com/prufyx/prufyx/cli/internal/maintainer/reviewrecord"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/prufyx/prufyx/cli/internal/maintainer/stagingreceipt"
	"github.com/prufyx/prufyx/cli/internal/maintainer/supportinventory"
)

type commandError struct {
	code    int
	message string
	err     error
	printed bool
}

func (e *commandError) Error() string { return e.message }
func (e *commandError) Unwrap() error { return e.err }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var command *commandError
		if errors.As(err, &command) {
			if !command.printed {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(command.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}
	var repeatable []string
	if len(args) > 1 && args[0] == "knowledge-publish" && args[1] == "finalize-root-transition" {
		repeatable = []string{"--signatures"}
	}
	if len(args) > 1 && args[0] == "knowledge-publish" && args[1] == "finalize-rotated-package" {
		repeatable = []string{"--successor-root"}
	}
	if len(args) > 1 && args[0] == "project" && args[1] == "init" {
		repeatable = []string{"--exact-tag"}
	}
	if len(args) > 1 && args[0] == "evidence" && args[1] == "repin" {
		repeatable = []string{"--project", "--rules"}
	}
	if duplicateLongFlag(args[1:], repeatable) {
		return &commandError{code: 2, message: "prufyx-maintainer: duplicate option rejected"}
	}
	switch args[0] {
	case "package-knowledge":
		return runPackageKnowledge(args[1:], stderr)
	case "export-knowledge":
		return runExportKnowledge(args[1:])
	case "knowledge-publish":
		return runKnowledgePublish(args[1:], stdout)
	case "knowledge-sign":
		return runKnowledgeSign(args[1:], stdout, stderr)
	case "support-inventory":
		return runSupportInventory(args[1:], stderr)
	case "release-gate":
		return runReleaseGate(args[1:])
	case "staging-receipt":
		if err := stagingreceipt.Run(args[1:], os.Stdin, stdout, stderr); err != nil {
			return &commandError{code: 2, message: "staging receipt: operation rejected", err: err}
		}
		return nil
	case "release-metadata", "release-verify-version", "release-verify-demo", "release-verify-scoped", "release-archive-smoke-receipt", "release-sbom", "release-verify-archive", "release-verify-marker":
		if err := releasehelpers.Run(args, os.Stdin, stdout, stderr); err != nil {
			return &commandError{code: 2, message: "release helper: operation rejected", err: err}
		}
		return nil
	case "release-sign":
		return runReleaseSign(args[1:], stdout, stderr)
	case "release":
		if err := releaseworkflow.Run(args[1:], stdout, stderr); err != nil {
			return &commandError{code: 2, message: "release workflow: operation rejected", err: err}
		}
		return nil
	case "local-kind":
		return runLocalKind(args[1:], stdout, stderr)
	case "contribution":
		return runContribution(args[1:], stdout, stderr)
	case "contribution-candidates":
		return runContributionCandidates(args[1:], stdout, stderr)
	case "selected-source-import":
		return runSelectedSourceImport(args[1:], stderr)
	case "source-corpus":
		if code := sourcecorpus.Run(args[1:], stdout, stderr); code != 0 {
			return &commandError{code: code, message: "source-corpus failed", printed: true}
		}
		return nil
	case "corpus-attestation":
		if code := runCorpusAttestation(args[1:], stdout, stderr); code != 0 {
			return &commandError{code: code, message: "corpus-attestation failed", printed: true}
		}
		return nil
	case "review-record":
		if err := reviewrecord.Run(args[1:], stdout); err != nil {
			return &commandError{code: 2, message: "review-record: record rejected", err: err}
		}
		return nil
	case "public-source-capture":
		if code := sourcecapture.Run(context.Background(), args[1:], stdout, stderr, sourcecapture.FixedHTTPSFetcher{}, time.Now); code != 0 {
			return &commandError{code: code, message: "public-source-capture failed", printed: true}
		}
		return nil
	case "project":
		if code := projectonboarding.Run(context.Background(), args[1:], stdout, stderr, projectonboarding.Options{}); code != 0 {
			return &commandError{code: code, message: "project onboarding failed", printed: true}
		}
		return nil
	case "evidence":
		if len(args) > 1 && args[1] == "reattest" {
			return runEvidenceReattest(args[2:], stdout, stderr)
		}
		if code := runEvidenceRepin(args[1:], stdout, stderr); code != 0 {
			return &commandError{code: code, message: "evidence repin failed", printed: true}
		}
		return nil
	case "rule":
		if code := runRuleCheck(args[1:], stdout, stderr); code != 0 {
			return &commandError{code: code, message: "rule validate failed", printed: true}
		}
		return nil
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, "usage: prufyx-maintainer <project|contribution|contribution-candidates|selected-source-import|source-corpus|corpus-attestation|review-record|public-source-capture|evidence|rule|export-knowledge|package-knowledge|knowledge-publish|knowledge-sign|support-inventory|release-gate|staging-receipt|release|local-kind|release-*> [options]")
		return nil
	default:
		return usageError()
	}
}

// runLocalKind is intentionally an explicit, manual proof command. It creates
// a disposable kind cluster and never reads the user's ordinary kubeconfig.
func runLocalKind(args []string, stdout, stderr io.Writer) error {
	root, err := cliRoot()
	if err != nil {
		return &commandError{code: 2, message: "local-kind: CLI root is unavailable", err: err}
	}
	flags := flag.NewFlagSet("local-kind", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := localkind.Options{FixtureDir: filepath.Join(root, "examples", "community", "local-kind")}
	flags.StringVar(&opts.Prufyx, "prufyx", "", "absolute prufyx executable")
	flags.StringVar(&opts.Collector, "collector", "", "absolute prufyx-collector executable")
	flags.StringVar(&opts.Evidence, "evidence", "", "new absolute evidence directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || opts.Prufyx == "" || opts.Collector == "" || opts.Evidence == "" {
		return &commandError{code: 2, message: "local-kind: command rejected"}
	}
	if err := localkind.Run(opts, stdout, stderr); err != nil {
		return &commandError{code: 2, message: "local-kind: proof failed", err: err}
	}
	return nil
}

func duplicateLongFlag(args []string, repeatable []string) bool {
	allowed := map[string]bool{}
	for _, name := range repeatable {
		allowed[name] = true
	}
	seen := map[string]bool{}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			continue
		}
		name := strings.SplitN(arg, "=", 2)[0]
		if seen[name] && !allowed[name] {
			return true
		}
		seen[name] = true
	}
	return false
}

func runReleaseGate(args []string) error {
	if len(args) == 0 {
		return &commandError{code: 2, message: "release gate: command rejected"}
	}
	mode := args[0]
	flags := flag.NewFlagSet("release-gate "+mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := releasegate.Options{}
	flags.StringVar(&opts.SourceRoot, "source-root", "", "Community source checkout")
	flags.StringVar(&opts.PolicyPath, "policy", "", "Community shipping policy")
	flags.StringVar(&opts.Go, "go", "go", "exact Go executable")
	switch mode {
	case "generate":
		flags.StringVar(&opts.OutputPath, "output", "", "new manifest output")
	case "verify":
		flags.StringVar(&opts.ManifestPath, "manifest", "", "source manifest")
	case "stage":
		flags.StringVar(&opts.ManifestPath, "manifest", "", "source manifest")
		flags.StringVar(&opts.OutputPath, "output", "", "new source stage")
		flags.BoolVar(&opts.RunNativeChecks, "run-native-checks", false, "run native staged-tree checks")
	default:
		return &commandError{code: 2, message: "release gate: command rejected"}
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || opts.SourceRoot == "" || opts.PolicyPath == "" || opts.Go == "" {
		return &commandError{code: 2, message: "release gate: command rejected"}
	}
	var err error
	switch mode {
	case "generate":
		if opts.OutputPath == "" {
			return &commandError{code: 2, message: "release gate: command rejected"}
		}
		_, err = releasegate.Generate(opts)
	case "verify":
		if opts.ManifestPath == "" {
			return &commandError{code: 2, message: "release gate: command rejected"}
		}
		_, err = releasegate.Verify(opts)
	case "stage":
		if opts.ManifestPath == "" || opts.OutputPath == "" {
			return &commandError{code: 2, message: "release gate: command rejected"}
		}
		_, err = releasegate.Stage(opts)
	}
	if err != nil {
		return &commandError{code: 2, message: "release gate: operation rejected", err: err}
	}
	return nil
}

func runContribution(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return &commandError{code: 2, message: "contribution-packet: command rejected"}
	}
	root, rootErr := cliRoot()
	if rootErr != nil {
		return &commandError{code: 2, message: "contribution-packet: CLI root is unavailable", err: rootErr}
	}
	mode := args[0]
	flags := flag.NewFlagSet("contribution "+mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := contribution.RunOptions{Mode: mode}
	switch mode {
	case "validate", "verify-sources":
		flags.StringVar(&opts.Validate.PacketPath, "packet", "", "candidate packet")
		flags.StringVar(&opts.Validate.LandscapePath, "landscape", filepath.Join(root, "internal/cncfcheck/data/landscape-projects.json"), "pinned CNCF landscape")
		if mode == "verify-sources" {
			flags.StringVar(&opts.SourceRoot, "source-root", "", "local content-addressed source root")
		}
	case "scaffold":
		flags.StringVar(&opts.Scaffold.Kind, "kind", "", "submission kind")
		flags.StringVar(&opts.Scaffold.ProjectSlug, "project-slug", "", "project slug")
		flags.StringVar(&opts.Scaffold.DisplayName, "display-name", "", "project display name")
		flags.StringVar(&opts.Scaffold.Repository, "repository", "", "canonical GitHub repository")
		flags.StringVar(&opts.Scaffold.CurrentVersion, "current-version", "", "current version")
		flags.StringVar(&opts.Scaffold.ProposedVersion, "proposed-version", "", "proposed version")
		flags.StringVar(&opts.Scaffold.TargetVersion, "target-version", "", "target version")
		flags.StringVar(&opts.Scaffold.Operation, "operation", "", "planned operation")
		flags.StringVar(&opts.Scaffold.Output, "output", "", "new private packet path")
	default:
		return &commandError{code: 2, message: "contribution-packet: command rejected"}
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return &commandError{code: 2, message: "contribution-packet: command rejected", err: err}
	}
	raw, err := contribution.Run(opts)
	if err != nil {
		return &commandError{code: 2, message: "contribution-packet: packet rejected", err: err}
	}
	if len(raw) > 0 {
		if _, err := stdout.Write(raw); err != nil {
			return fmt.Errorf("write contribution output: %w", err)
		}
	}
	return nil
}

func runContributionCandidates(args []string, stdout, stderr io.Writer) error {
	root, rootErr := cliRoot()
	if rootErr != nil {
		return &commandError{code: 2, message: "contribution-candidates: CLI root is unavailable", err: rootErr}
	}
	flags := flag.NewFlagSet("contribution-candidates", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var directory, landscape string
	flags.StringVar(&directory, "directory", filepath.Join(root, "examples/contributions"), "candidate directory")
	flags.StringVar(&landscape, "landscape", filepath.Join(root, "internal/cncfcheck/data/landscape-projects.json"), "pinned CNCF landscape")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || directory == "" || landscape == "" {
		return &commandError{code: 2, message: "contribution-candidates: rejected", err: err}
	}
	raw, err := contribution.ValidateCandidates(directory, landscape)
	if err != nil {
		return &commandError{code: 2, message: "contribution-candidates: rejected", err: err}
	}
	if _, err := stdout.Write(raw); err != nil {
		return fmt.Errorf("write candidate output: %w", err)
	}
	return nil
}

func runSelectedSourceImport(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("selected-source-import", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := contribution.ImportOptions{}
	flags.StringVar(&opts.CorpusRoot, "corpus-root", "", "reviewed corpus root")
	flags.StringVar(&opts.CollectionIndex, "collection-index", "", "accepted collection index")
	flags.StringVar(&opts.ExpectedIndexDigest, "expected-index-digest", "", "expected index digest")
	flags.StringVar(&opts.Output, "output", "", "selected source manifest output")
	flags.BoolVar(&opts.Check, "check", false, "verify output is current")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || opts.CorpusRoot == "" || opts.CollectionIndex == "" || opts.ExpectedIndexDigest == "" || opts.Output == "" {
		return &commandError{code: 2, message: "selected-source import: rejected", err: err}
	}
	if err := contribution.ImportSelectedSourceRecords(opts); err != nil {
		return &commandError{code: 2, message: "selected-source import: rejected", err: err}
	}
	return nil
}

func usageError() error {
	return &commandError{code: 2, message: "prufyx-maintainer: unknown or missing command"}
}

func runPackageKnowledge(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("package-knowledge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", "", "fixed target profile")
	input := flags.String("input", "", "operator-prepared metadata/ and targets/ directory")
	output := flags.String("output", "", "new archive in a private 0700 parent")
	if err := flags.Parse(args); err != nil {
		return &commandError{code: 2, message: "package-knowledge: packaging rejected", err: err}
	}
	if flags.NArg() != 0 || *profile == "" || *input == "" || *output == "" {
		return &commandError{code: 2, message: "package-knowledge: packaging rejected"}
	}
	if err := knowledgepack.WritePackage(*input, *output, *profile); err != nil {
		return &commandError{code: 2, message: "package-knowledge: packaging rejected", err: err}
	}
	return nil
}

func runExportKnowledge(args []string) error {
	flags := flag.NewFlagSet("export-knowledge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", "", "fixed public source profile")
	revision := flags.String("revision", "", "positive external semantic revision")
	output := flags.String("output", "", "new unsigned public target file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *profile == "" || *revision == "" || *output == "" {
		return &commandError{code: 2, message: "export-knowledge: command rejected"}
	}
	if err := knowledgeexport.Write(knowledgeexport.Options{Profile: *profile, Revision: *revision, Output: *output}); err != nil {
		return &commandError{code: 2, message: "export-knowledge: command rejected", err: err}
	}
	return nil
}

func cliRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	current := cwd
	for depth := 0; depth < 12; depth++ {
		for _, candidate := range []string{current, filepath.Join(current, "cli")} {
			if info, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil && info.Mode().IsRegular() {
				return candidate, nil
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", fmt.Errorf("locate cli root from %s", cwd)
}

// runEvidenceRepin wires the evidence-repin maintainer subcommand. It reads
// an optional GitHub token from the environment (GITHUB_TOKEN, falling
// back to GH_TOKEN) to raise the unauthenticated GitHub API rate limit; the
// token is never required, never logged, and never written to disk by this
// command itself.
func runEvidenceRepin(args []string, stdout, stderr io.Writer) int {
	root, err := cliRoot()
	if err != nil {
		fmt.Fprintln(stderr, "evidence: CLI root is unavailable")
		return 2
	}
	defaultRulePacks := []string{
		filepath.Join(root, "internal/cncfcheck/data/rules.json"),
		filepath.Join(root, "internal/projectcheck/data/rules.json"),
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	apiFetcher := evidencerepin.GitHubAPIFetcher{Token: token}
	return evidencerepin.Run(context.Background(), args, stdout, stderr, apiFetcher, sourcecapture.FixedHTTPSFetcher{}, time.Now, defaultRulePacks)
}

// runCorpusAttestation wires the corpus-attestation maintainer subcommand. It
// computes over the whole embedded rule pack, never a filtered view, and
// writes or verifies the attestation asset the runtime scope path consumes.
func runCorpusAttestation(args []string, stdout, stderr io.Writer) int {
	root, err := cliRoot()
	if err != nil {
		fmt.Fprintln(stderr, "corpus-attestation: CLI root is unavailable")
		return 2
	}
	return corpusattest.Run(args, stdout, stderr, root)
}

func runSupportInventory(args []string, stderr io.Writer) error {
	root, err := cliRoot()
	if err != nil {
		return &commandError{code: 2, message: "support inventory: CLI root is unavailable", err: err}
	}
	flags := flag.NewFlagSet("support-inventory", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cfg := supportinventory.Config{}
	flags.StringVar(&cfg.Rules, "rules", filepath.Join(root, "internal/cncfcheck/data/rules.json"), "CNCF rule pack")
	flags.StringVar(&cfg.Landscape, "landscape", filepath.Join(root, "internal/cncfcheck/data/landscape-projects.json"), "CNCF landscape inventory")
	flags.StringVar(&cfg.CertContract, "cert-contract", filepath.Join(root, "internal/certmanagervalues/source-contract-v1.json"), "cert-manager source contract")
	flags.StringVar(&cfg.PrometheusContract, "prometheus-contract", filepath.Join(root, "internal/prometheusmode/source-contract-v1.json"), "Prometheus source contract")
	flags.StringVar(&cfg.SPIFFEProfile, "spiffe-profile", filepath.Join(root, "internal/spiffex509svid/data/profile.json"), "SPIFFE profile")
	flags.StringVar(&cfg.CloudEventsProfile, "cloudevents-profile", filepath.Join(root, "internal/cloudeventsstructuredjson/data/profile.json"), "CloudEvents profile")
	flags.StringVar(&cfg.TiKVProfile, "tikv-profile", filepath.Join(root, "internal/tikvgcpv2/data/profile.json"), "TiKV profile")
	flags.StringVar(&cfg.CNCFPrepareSource, "cncf-prepare-source", filepath.Join(root, "internal/communityapp/cncf_prepare.go"), "CNCF preparer dispatch source")
	flags.StringVar(&cfg.ProjectRules, "community-project-rules", filepath.Join(root, "internal/projectcheck/data/rules.json"), "community-project rule pack")
	flags.StringVar(&cfg.ProjectRegistry, "community-project-registry", filepath.Join(root, "internal/projectcheck/data/projects.json"), "community-project identity registry")
	selected := flags.String("selected-source-manifest", "", "reviewed selected-source manifest")
	jsonOutput := flags.String("json-output", "", "generated canonical JSON output")
	markdownOutput := flags.String("markdown-output", "", "generated Markdown output")
	check := flags.Bool("check", false, "verify outputs are current")
	if err := flags.Parse(args); err != nil {
		return &commandError{code: 2, message: "support inventory: generation rejected", err: err}
	}
	if flags.NArg() != 0 || *selected == "" || *jsonOutput == "" || *markdownOutput == "" {
		return &commandError{code: 2, message: "support inventory: generation rejected"}
	}
	cfg.SelectedSourceManifest = *selected
	jsonRaw, markdown, err := supportinventory.Generate(cfg)
	if err != nil {
		return &commandError{code: 2, message: "support inventory: generation rejected", err: err}
	}
	if *check {
		currentJSON, currentMarkdown, readErr := readOutputPair(*jsonOutput, *markdownOutput)
		if readErr != nil || string(currentJSON) != string(jsonRaw) || string(currentMarkdown) != markdown {
			return &commandError{code: 2, message: "support inventory: generated output is stale"}
		}
		return nil
	}
	if err := writeOutputPair(*jsonOutput, jsonRaw, *markdownOutput, []byte(markdown)); err != nil {
		return &commandError{code: 2, message: "support inventory: cannot commit generated outputs", err: err}
	}
	return nil
}

// runRuleCheck wires the "rule validate" subcommand: an offline-by-default
// validator for a community-contributed rule candidate. It never writes to a
// rules.json file and never publishes a claim; it only reports findings.
func runRuleCheck(args []string, stdout, stderr io.Writer) int {
	root, err := cliRoot()
	if err != nil {
		fmt.Fprintln(stderr, "rule: CLI root is unavailable")
		return 2
	}
	defaults := rulecheck.CLIOptions{
		ExistingRulesPaths: []string{
			filepath.Join(root, "internal/cncfcheck/data/rules.json"),
			filepath.Join(root, "internal/projectcheck/data/rules.json"),
		},
	}
	return rulecheck.Run(args, stdout, stderr, defaults)
}
