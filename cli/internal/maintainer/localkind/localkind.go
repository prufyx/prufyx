// SPDX-License-Identifier: AGPL-3.0-only

// Package localkind runs the explicit manual, declaration-only kind example.
// It never uses the caller's ambient kubectl context.
package localkind

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	nodeImage      = "kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f"
	proofTimeout   = 10 * time.Minute
	cleanupTimeout = 2 * time.Minute
)

type Options struct{ Prufyx, Collector, Evidence, FixtureDir string }

func Run(o Options, stdout, stderr io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), proofTimeout)
	defer cancel()
	if err := validate(&o); err != nil {
		return err
	}
	for _, n := range []string{"kind", "kubectl"} {
		if _, err := exec.LookPath(n); err != nil {
			return fmt.Errorf("%s is unavailable", n)
		}
	}
	for _, n := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		if os.Getenv(n) != "" {
			return errors.New("ambient proxy is present; choose collector routing separately")
		}
	}
	var nonce [8]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	name := "prufyx-proof-" + hex.EncodeToString(nonce[:])
	work, err := os.MkdirTemp("", "prufyx-local-kind-")
	if err != nil {
		return err
	}
	if err = os.Chmod(work, 0700); err != nil {
		return err
	}
	kube := filepath.Join(work, "kubeconfig")
	owned := true
	evidenceOwned := false
	complete := false
	defer func() {
		if owned {
			cleanup, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
			_ = kind(cleanup, "delete", "cluster", "--name", name, "--kubeconfig", kube)
			cancel()
		}
		if evidenceOwned && !complete {
			_ = os.RemoveAll(o.Evidence)
		}
		if work != "" {
			_ = os.RemoveAll(work)
		}
	}()
	if err = kind(ctx, "create", "cluster", "--name", name, "--image", nodeImage, "--kubeconfig", kube, "--wait", "120s"); err != nil {
		return errors.New("kind cluster creation failed")
	}
	if err = os.Chmod(kube, 0600); err != nil {
		return err
	}
	if got, err := kubectl(ctx, kube, "config", "current-context"); err != nil || strings.TrimSpace(string(got)) != "kind-"+name {
		return errors.New("task kubeconfig context mismatch")
	}
	server, err := kubectl(ctx, kube, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(server)), "https://127.0.0.1:") {
		return errors.New("task kubeconfig does not select a loopback endpoint")
	}
	if _, err = kubectl(ctx, kube, "create", "namespace", "prufyx-local-proof"); err != nil {
		return err
	}
	if _, err = kubectl(ctx, kube, "apply", "-f", filepath.Join(o.FixtureDir, "current-prometheus-agent.yaml")); err != nil {
		return err
	}
	replicas, err := kubectl(ctx, kube, "get", "deployment", "prometheus-declaration", "-n", "prufyx-local-proof", "-o", "jsonpath={.spec.replicas}")
	if err != nil || !zeroReplicas(replicas) {
		return errors.New("synthetic declaration deployment is not scaled to zero")
	}
	observationParent := filepath.Join(work, "observations")
	if err = os.Mkdir(observationParent, 0700); err != nil {
		return err
	}
	if err = run(ctx, o.Collector, []string{"collect", observationParent, "--kubeconfig", kube, "--acknowledge-kubeconfig-exec-risk", "--include-component-configuration", "--component-configuration-profile", "v3", "kind-" + name}, nil); err != nil {
		return errors.New("collector failed")
	}
	dirs, err := dirsOnly(observationParent)
	if err != nil || len(dirs) != 1 {
		return errors.New("collector output layout is invalid")
	}
	obs := dirs[0]
	captured, err := generatedAt(filepath.Join(obs, "index.json"))
	if err != nil {
		return err
	}
	if err = os.Mkdir(o.Evidence, 0700); err != nil {
		return err
	}
	evidenceOwned = true
	before, err := sha(o.Prufyx)
	if err != nil {
		return err
	}
	identityRaw, identityStderr, exit, err := runExit(ctx, o.Prufyx, []string{"version"}, nil)
	if err != nil || exit != 0 || len(identityStderr) != 0 {
		return errors.New("prufyx version failed")
	}
	identity, err := validIdentity(identityRaw)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	cases := []struct {
		name, want string
		exit       int
	}{{"proposed-preserve-agent.json", "PASS", 0}, {"proposed-preserve-agent.json", "PASS", 0}, {"proposed-change-to-server.json", "ATTENTION", 11}, {"proposed-ambiguous.json", "UNKNOWN", 11}}
	reports := make([]string, 0, len(cases))
	for i, tc := range cases {
		src := filepath.Join(o.FixtureDir, tc.name)
		proposal := filepath.Join(work, fmt.Sprintf("proposal-%d.json", i))
		if err = copy(src, proposal, 0600); err != nil {
			return err
		}
		d, err := sha(proposal)
		if err != nil {
			return err
		}
		out, commandStderr, exit, err := runExit(ctx, o.Prufyx, []string{"check", "prometheus-mode", "--observation-root", obs, "--proposed-workload", proposal, "--proposed-digest", d, "--captured-at", captured, "--now", now, "--max-age", "2h", "--format", "json"}, nil)
		if err != nil || exit != tc.exit || len(commandStderr) != 0 {
			return errors.New("declaration evaluation returned unexpected exit")
		}
		if err = claim(out, tc.want); err != nil {
			return err
		}
		path := filepath.Join(o.Evidence, fmt.Sprintf("%02d-%s-report.json", i, strings.TrimSuffix(tc.name, ".json")))
		if err = os.WriteFile(path, out, 0600); err != nil {
			return err
		}
		reports = append(reports, path)
	}
	if a, e := os.ReadFile(reports[0]); e != nil {
		return e
	} else if b, e := os.ReadFile(reports[1]); e != nil || string(a) != string(b) {
		return errors.New("same-input replay differs")
	}
	after, err := sha(o.Prufyx)
	if err != nil || after != before {
		return errors.New("prufyx binary changed during manual proof")
	}
	replayDigest, err := sha(reports[0])
	if err != nil {
		return err
	}
	receipt := proofReceipt(captured, before, now, replayDigest, identity)
	if err = writeJSON(filepath.Join(o.Evidence, "receipt.json"), receipt); err != nil {
		return err
	}
	if err = verifyClusterDeleted(
		func() error { return kind(ctx, "delete", "cluster", "--name", name, "--kubeconfig", kube) },
		func() (string, error) { return kindOutput(ctx, "get", "clusters") },
		name,
	); err != nil {
		return err
	}
	owned = false
	if err = removeTaskWorkspace(work, kube); err != nil {
		return err
	}
	work = ""
	if err = writeJSON(filepath.Join(o.Evidence, "cleanup-receipt.json"), map[string]any{"schema": "prufyx.io/local-kind-cleanup-receipt/v1alpha1", "clusterAbsent": true, "kubeconfigRetained": false}); err != nil {
		return err
	}
	if err = manifest(o.Evidence); err != nil {
		return err
	}
	complete = true
	_, err = fmt.Fprintf(stdout, "Local declaration proof passed; evidence: %s\n", o.Evidence)
	return err
}

func proofReceipt(captured, binaryDigest, evaluatedAt, replayDigest string, identity identityEvidence) map[string]any {
	return map[string]any{"schema": "prufyx.io/local-kind-prometheus-proof/v1alpha1", "fixture": map[string]any{"classification": "PUBLIC_SYNTHETIC_DECLARATION_ONLY", "replicas": 0, "runtimeClaim": false}, "cluster": map[string]any{"nodeImage": nodeImage, "taskKubeconfig": true, "ambientContextUsed": false}, "collector": map[string]any{"profile": "producer-v3", "capturedAt": captured}, "evaluator": map[string]any{"binaryDigest": binaryDigest, "identity": identity, "unchangedDuringEvaluation": true}, "evaluation": map[string]any{"evaluatedAt": evaluatedAt, "aggregate": "UNKNOWN", "preserveAgent": "PASS", "changeToServer": "ATTENTION", "multipleContainers": "UNKNOWN", "sameInputReplayByteEqual": true, "replayDigest": replayDigest}, "claimsExcluded": []string{"process startup", "applied runtime mode", "data and remote-write safety", "whole-upgrade compatibility"}}
}

func removeTaskWorkspace(work, kubeconfig string) error {
	if err := os.RemoveAll(work); err != nil {
		return errors.New("task directory cleanup failed")
	}
	if _, err := os.Lstat(work); !os.IsNotExist(err) {
		return errors.New("task directory remains after cleanup")
	}
	if _, err := os.Lstat(kubeconfig); !os.IsNotExist(err) {
		return errors.New("task kubeconfig remains after cleanup")
	}
	return nil
}

func validate(o *Options) error {
	if o.FixtureDir == "" {
		return errors.New("fixture directory is required")
	}
	for _, p := range []*string{&o.Prufyx, &o.Collector} {
		i, e := os.Lstat(*p)
		if e != nil || !filepath.IsAbs(*p) || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0111 == 0 {
			return errors.New("prufyx and collector must be absolute executable regular files")
		}
	}
	if !filepath.IsAbs(o.Evidence) {
		return errors.New("evidence directory must be absolute")
	}
	if _, e := os.Lstat(o.Evidence); !os.IsNotExist(e) {
		return errors.New("evidence directory must not exist")
	}
	return nil
}
func run(ctx context.Context, bin string, args, env []string) error {
	_, _, exit, err := runExit(ctx, bin, args, env)
	if err != nil {
		return err
	}
	if exit != 0 {
		return errors.New("command failed")
	}
	return nil
}
func runExit(ctx context.Context, bin string, args, env []string) ([]byte, []byte, int, error) {
	c := exec.CommandContext(ctx, bin, args...)
	if env != nil {
		c.Env = env
	}
	var errOut strings.Builder
	c.Stderr = &errOut
	out, e := c.Output()
	if e == nil {
		return out, []byte(errOut.String()), 0, nil
	}
	if ctx.Err() != nil {
		return nil, nil, 0, ctx.Err()
	}
	var x *exec.ExitError
	if errors.As(e, &x) {
		return out, []byte(errOut.String()), x.ExitCode(), nil
	}
	return nil, nil, 0, e
}
func kind(ctx context.Context, args ...string) error {
	return run(ctx, "kind", args, append(os.Environ(), "KIND_EXPERIMENTAL_PROVIDER=docker"))
}
func kindOutput(ctx context.Context, args ...string) (string, error) {
	o, _, exit, err := runExit(ctx, "kind", args, append(os.Environ(), "KIND_EXPERIMENTAL_PROVIDER=docker"))
	if err != nil {
		return "", err
	}
	if exit != 0 {
		return "", errors.New("kind command failed")
	}
	return string(o), nil
}
func kubectl(ctx context.Context, kube string, args ...string) ([]byte, error) {
	return commandOutput(ctx, "kubectl", append([]string{"--kubeconfig", kube}, args...)...)
}
func commandOutput(ctx context.Context, bin string, args ...string) ([]byte, error) {
	o, _, exit, e := runExit(ctx, bin, args, nil)
	if e != nil {
		return nil, e
	}
	if exit != 0 {
		return nil, errors.New("command failed")
	}
	return o, nil
}
func sha(p string) (string, error) {
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:]), nil
}
func copy(a, b string, m os.FileMode) error {
	x, e := os.ReadFile(a)
	if e != nil {
		return e
	}
	return os.WriteFile(b, x, m)
}
func dirsOnly(p string) ([]string, error) {
	es, e := os.ReadDir(p)
	if e != nil {
		return nil, e
	}
	var r []string
	for _, x := range es {
		if x.IsDir() {
			r = append(r, filepath.Join(p, x.Name()))
		}
	}
	return r, nil
}
func generatedAt(p string) (string, error) {
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	var x struct {
		GeneratedAt string `json:"generatedAt"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		return "", errors.New("collector index is invalid")
	}
	if _, err := time.Parse(time.RFC3339, x.GeneratedAt); err != nil {
		return "", errors.New("collector index is invalid")
	}
	return x.GeneratedAt, nil
}

type identityEvidence struct {
	Version          string `json:"version"`
	ReleaseState     string `json:"releaseState"`
	SourceRevision   string `json:"sourceRevision"`
	SourceTreeDigest string `json:"sourceTreeDigest"`
	AllowlistDigest  string `json:"allowlistDigest"`
	BuildProfile     string `json:"buildProfile"`
	GoVersion        string `json:"goVersion"`
	CandidateOnly    bool   `json:"candidateOnly"`
}

var (
	releaseVersionRE = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	revisionRE       = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	digestRE         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	buildProfileRE   = regexp.MustCompile(`^linux-(amd64|arm64)$`)
	goVersionRE      = regexp.MustCompile(`^go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[ A-Za-z0-9:._+-]*)?$`)
)

func validIdentity(b []byte) (identityEvidence, error) {
	var x struct {
		Result struct {
			Status     string `json:"status"`
			ReasonCode string `json:"reasonCode"`
		} `json:"result"`
		Data identityEvidence `json:"data"`
	}
	if json.Unmarshal(b, &x) != nil || x.Result.Status != "OK" || x.Result.ReasonCode != "build_identity_reported" || !x.Data.CandidateOnly {
		return identityEvidence{}, errors.New("prufyx identity envelope is invalid")
	}
	for _, value := range []string{x.Data.Version, x.Data.SourceRevision, x.Data.SourceTreeDigest, x.Data.AllowlistDigest, x.Data.BuildProfile, x.Data.GoVersion} {
		if len(value) > 128 || strings.ContainsAny(value, "/\\") {
			return identityEvidence{}, errors.New("prufyx identity contains unsupported value")
		}
	}
	development := x.Data.ReleaseState == "development" && x.Data.Version == "dev" && x.Data.SourceRevision == "unbound" && x.Data.SourceTreeDigest == "unbound" && x.Data.AllowlistDigest == "unbound" && x.Data.BuildProfile == "development"
	release := x.Data.ReleaseState == "release" && releaseVersionRE.MatchString(x.Data.Version) && revisionRE.MatchString(x.Data.SourceRevision) && digestRE.MatchString(x.Data.SourceTreeDigest) && digestRE.MatchString(x.Data.AllowlistDigest) && buildProfileRE.MatchString(x.Data.BuildProfile)
	if (!development && !release) || !goVersionRE.MatchString(x.Data.GoVersion) {
		return identityEvidence{}, errors.New("prufyx identity contains unsupported value")
	}
	return x.Data, nil
}
func claim(b []byte, want string) error {
	var x struct {
		Assessment string `json:"assessment"`
		Claim      struct {
			Status string `json:"status"`
		} `json:"claim"`
	}
	if json.Unmarshal(b, &x) != nil || x.Assessment != "UNKNOWN" || x.Claim.Status != want {
		return errors.New("evaluation result is invalid")
	}
	return nil
}
func writeJSON(p string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return os.WriteFile(p, append(b, byte(10)), 0600)
}
func manifest(root string) error {
	es, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	var lines []string
	for _, x := range es {
		if !x.Type().IsRegular() || x.Name() == "MANIFEST.sha256" {
			continue
		}
		d, e := sha(filepath.Join(root, x.Name()))
		if e != nil {
			return e
		}
		lines = append(lines, strings.TrimPrefix(d, "sha256:")+"  "+x.Name())
	}
	return os.WriteFile(filepath.Join(root, "MANIFEST.sha256"), []byte(strings.Join(lines, string(byte(10)))+string(byte(10))), 0600)
}
func containsLine(v, n string) bool {
	for _, x := range strings.Split(v, string(byte(10))) {
		if x == n {
			return true
		}
	}
	return false
}

func zeroReplicas(raw []byte) bool {
	return strings.TrimSpace(string(raw)) == "0"
}

func verifyClusterDeleted(deleteCluster func() error, listClusters func() (string, error), name string) error {
	if err := deleteCluster(); err != nil {
		return errors.New("kind cluster deletion failed")
	}
	list, err := listClusters()
	if err != nil || containsLine(list, name) {
		return errors.New("run-owned kind cluster remains")
	}
	return nil
}
