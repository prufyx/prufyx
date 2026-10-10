// SPDX-License-Identifier: AGPL-3.0-only

// Command kindval checks Prufyx's Kubernetes knowledge against real API
// servers (kind clusters). It never creates a cluster itself:
// scripts/kind-val.sh creates one cluster per release line and calls the
// subcommands against it. The evaluation is offline; only snapshot,
// verdicts and crd talk to a cluster, and crd fetches manifests from GitHub.
//
//	kindval claims   --lines 1.30,1.31 [--crd FILE] --out FILE
//	kindval snapshot --kubeconfig FILE --line L --image REF --out FILE
//	kindval verdicts --kubeconfig FILE --line L --dir DIR --out FILE [--claims FILE] [--prufyx BIN --from-version X --to-version Y]
//	kindval crd      --kubeconfig FILE --line L --image REF --claims FILE --out FILE [--pair ID]
//	kindval evaluate --claims FILE --runs DIR --out FILE [--summary FILE] [--prufyx BIN] [--prufyx-commit SHA] [--log FILE]
//
// Files: claims (prufyx.io/kind-val-claims/v1) is the input, one claim per
// statement (see docs/kind-val.md for the contract); snapshot, verdicts and
// crd outputs are one file per cluster under the runs directory; evaluate
// writes the results (prufyx.io/kind-val-results/v1): every claim
// confirmed, refuted, undetermined or error, the served-API differences
// between consecutive lines, and the findings.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kindval claims|snapshot|verdicts|crd|evaluate [flags]")
		return 2
	}
	ctx := context.Background()
	var err error
	switch args[0] {
	case "claims":
		err = cmdClaims(args[1:])
	case "snapshot":
		err = cmdSnapshot(ctx, args[1:])
	case "verdicts":
		err = cmdVerdicts(ctx, args[1:])
	case "crd":
		err = cmdCRD(ctx, args[1:])
	case "evaluate":
		err = cmdEvaluate(args[1:], stdout)
	default:
		err = fmt.Errorf("unknown subcommand %q", args[0])
	}
	if err != nil {
		fmt.Fprintf(stderr, "kindval %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// fileDigest is the "sha256:..." digest of a file.
func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, ",") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func cmdClaims(args []string) error {
	fs := flag.NewFlagSet("claims", flag.ContinueOnError)
	lines := fs.String("lines", "", "comma-separated release lines of the matrix (1.30,1.31,...)")
	extra := fs.String("crd", "", "claims file whose claims are merged in (custom-resource claims, or any other)")
	out := fs.String("out", "", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *lines == "" || *out == "" {
		return errors.New("--lines and --out are required")
	}
	claims := Claims{Schema: ClaimsSchema, Claims: KubernetesClaims(splitLines(*lines))}
	if *extra != "" {
		more, err := loadClaims(*extra)
		if err != nil {
			return err
		}
		claims.Claims = append(claims.Claims, more.Claims...)
	}
	if err := claims.Validate(); err != nil {
		return err
	}
	return writeJSON(*out, claims)
}

// loadClaims reads and validates a claims file.
func loadClaims(path string) (Claims, error) {
	var claims Claims
	if err := readJSON(path, &claims); err != nil {
		return claims, err
	}
	if err := claims.Validate(); err != nil {
		return claims, fmt.Errorf("%s: %w", path, err)
	}
	return claims, nil
}

func cmdSnapshot(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig of the cluster")
	line := fs.String("line", "", "release line of the cluster (1.32)")
	image := fs.String("image", "", "node image reference, pinned by @sha256: digest")
	observed := fs.String("observed-digests", "", "repository digests of the image the node container runs (docker inspect), comma or space separated")
	out := fs.String("out", "", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kubeconfig == "" || *line == "" || *out == "" {
		return errors.New("--kubeconfig, --line and --out are required")
	}
	if err := requireDigest(*image); err != nil {
		return err
	}
	k := kube{run: execRunner, kubeconfig: *kubeconfig}
	s, err := k.snapshot(ctx, *line, *image, splitDigests(*observed), time.Now())
	if err != nil {
		return err
	}
	return writeJSON(*out, s)
}

func cmdVerdicts(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verdicts", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig of the cluster")
	line := fs.String("line", "", "release line of the cluster (1.32)")
	dir := fs.String("dir", "", "directory the corpus manifests are written to")
	out := fs.String("out", "", "output file")
	prufyx := fs.String("prufyx", "", "prufyx binary; without it only the server dry runs are recorded")
	fromVersion := fs.String("from-version", "", "version of the previous line the scan starts from (1.31.14)")
	toVersion := fs.String("to-version", "", "version of this line the scan targets (1.32.11)")
	claimsPath := fs.String("claims", "", "claims file; its k8s-removal claims join the corpus")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kubeconfig == "" || *line == "" || *dir == "" || *out == "" {
		return errors.New("--kubeconfig, --line, --dir and --out are required")
	}
	if (*prufyx == "") != (*fromVersion == "") || (*prufyx != "" && *toVersion == "") {
		return errors.New("--prufyx, --from-version and --to-version go together")
	}
	var claims Claims
	if *claimsPath != "" {
		var err error
		if claims, err = loadClaims(*claimsPath); err != nil {
			return err
		}
	}
	k := kube{run: execRunner, kubeconfig: *kubeconfig}
	vr, err := runVerdicts(ctx, k, execRunner, *dir, *line, *prufyx, *fromVersion, *toVersion, corpus(claims.Claims))
	if err != nil {
		return err
	}
	return writeJSON(*out, vr)
}

func cmdCRD(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("crd", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig of the cluster")
	line := fs.String("line", "", "release line of the cluster (1.37)")
	image := fs.String("image", "", "node image reference, pinned by @sha256: digest")
	observed := fs.String("observed-digests", "", "repository digests of the image the node container runs (docker inspect), comma or space separated")
	claimsPath := fs.String("claims", "", "claims file with the custom-resource claims")
	out := fs.String("out", "", "output file")
	only := fs.String("pair", "", "run only the pair with this id (<project>.<fromTag>-to-<toTag>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kubeconfig == "" || *line == "" || *claimsPath == "" || *out == "" {
		return errors.New("--kubeconfig, --line, --claims and --out are required")
	}
	if err := requireDigest(*image); err != nil {
		return err
	}
	claims, err := loadClaims(*claimsPath)
	if err != nil {
		return err
	}
	k := kube{run: execRunner, kubeconfig: *kubeconfig}
	cr := CRDRun{Schema: CRDRunSchema, Line: *line, Image: *image, ObservedImageDigests: splitDigests(*observed), Pairs: []CRDPairResult{}}
	for _, pair := range claims.Pairs() {
		if *only != "" && pair.ID != *only {
			continue
		}
		fmt.Fprintf(os.Stderr, "kindval crd: %s %s -> %s\n", pair.Project, pair.From.Tag, pair.To.Tag)
		cr.Pairs = append(cr.Pairs, runPair(ctx, k, httpFetcher, pair))
	}
	return writeJSON(*out, cr)
}

// loadRuns reads every snapshot, verdicts and crd file under dir (by their
// schema, whatever the file name).
func loadRuns(dir string) (Runs, error) {
	runs := Runs{Snapshots: map[string]Snapshot{}, Verdicts: map[string]VerdictRun{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return runs, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return runs, err
		}
		var head struct {
			Schema string `json:"schema"`
		}
		if err := json.Unmarshal(data, &head); err != nil {
			return runs, fmt.Errorf("%s: %w", path, err)
		}
		switch head.Schema {
		case SnapshotSchema:
			var s Snapshot
			if err := readJSON(path, &s); err != nil {
				return runs, err
			}
			runs.Snapshots[s.Line] = s
		case VerdictsSchema:
			var v VerdictRun
			if err := readJSON(path, &v); err != nil {
				return runs, err
			}
			runs.Verdicts[v.Line] = v
		case CRDRunSchema:
			var c CRDRun
			if err := readJSON(path, &c); err != nil {
				return runs, err
			}
			runs.CRD = append(runs.CRD, c)
		}
	}
	return runs, nil
}

func cmdEvaluate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	claimsPath := fs.String("claims", "", "claims file")
	dir := fs.String("runs", "", "directory with the snapshot, verdicts and crd files")
	out := fs.String("out", "", "results file")
	summary := fs.String("summary", "", "summary file (Markdown); the summary is also printed")
	prufyxCommit := fs.String("prufyx-commit", "", "source revision the scanned prufyx binary was built from")
	prufyxBin := fs.String("prufyx", "", "the scanned prufyx binary, for its digest")
	logPath := fs.String("log", "", "run log, for its digest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *claimsPath == "" || *dir == "" || *out == "" {
		return errors.New("--claims, --runs and --out are required")
	}
	claims, err := loadClaims(*claimsPath)
	if err != nil {
		return err
	}
	runs, err := loadRuns(*dir)
	if err != nil {
		return err
	}
	prov := Provenance{Prufyx: Binary{Commit: *prufyxCommit}}
	if *prufyxBin != "" {
		if prov.Prufyx.SHA256, err = fileDigest(*prufyxBin); err != nil {
			return err
		}
	}
	if *logPath != "" {
		if prov.LogDigest, err = fileDigest(*logPath); err != nil {
			return err
		}
	}
	res := Evaluate(claims, runs, prov, time.Now())
	if err := writeJSON(*out, res); err != nil {
		return err
	}
	text := Summary(res)
	if *summary != "" {
		if err := os.WriteFile(*summary, []byte(text), 0o600); err != nil {
			return err
		}
	}
	_, err = io.WriteString(stdout, text)
	return err
}

var imageDigestRef = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// requireDigest refuses a node image reference that is not pinned by a
// sha256 digest: a tag names whatever the registry serves today.
func requireDigest(image string) error {
	if !imageDigestRef.MatchString(image) {
		return fmt.Errorf("--image %q must be pinned by an @sha256:<64 hex> digest", image)
	}
	return nil
}

// splitDigests reads a comma or space separated list of digest references.
func splitDigests(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		out = append(out, f)
	}
	return out
}
