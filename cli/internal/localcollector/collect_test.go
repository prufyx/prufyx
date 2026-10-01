// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	t       *testing.T
	private string
	calls   [][]string
}

const testKubeconfigYAML = "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"

type oneFailureRunner struct{ fakeRunner }

type snapshotStabilityRunner struct {
	t        *testing.T
	original string
	want     []byte
	snapshot string
	calls    int
}

type snapshotFailureRunner struct {
	t        *testing.T
	snapshot string
}

func (r *snapshotFailureRunner) Run(ctx context.Context, argv, _ []string, _ time.Duration) (CommandResult, error) {
	r.t.Helper()
	if len(argv) < 2 || argv[0] != "--kubeconfig" {
		r.t.Fatalf("missing snapshot authority: %q", argv)
	}
	r.snapshot = argv[1]
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}
	return CommandResult{}, errors.New("benign fake runner failure")
}

func (r *snapshotStabilityRunner) Run(_ context.Context, argv, env []string, timeout time.Duration) (CommandResult, error) {
	r.t.Helper()
	if timeout != requestTimeout || len(argv) < 2 || argv[0] != "--kubeconfig" || argv[1] == r.original {
		r.t.Fatalf("unexpected snapshot authority: %q", argv)
	}
	if r.snapshot == "" {
		r.snapshot = argv[1]
		info, err := os.Stat(filepath.Dir(r.snapshot))
		if err != nil {
			r.t.Fatalf("read private snapshot directory: %v", err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			r.t.Fatalf("private snapshot directory mode=%v", info.Mode())
		}
		if err := os.WriteFile(r.original, []byte("apiVersion: v1\nkind: Config\nusers:\n- user:\n    tokenFile: relative-token\n"), 0o600); err != nil {
			r.t.Fatal(err)
		}
	} else if argv[1] != r.snapshot {
		r.t.Fatalf("snapshot changed between calls: %q then %q", r.snapshot, argv[1])
	}
	envBound := false
	for _, value := range env {
		if value == "KUBECONFIG="+r.snapshot {
			envBound = true
			break
		}
	}
	if !envBound {
		r.t.Fatalf("KUBECONFIG did not bind the snapshot: %q", env)
	}
	raw, err := os.ReadFile(r.snapshot)
	if err != nil || !bytes.Equal(raw, r.want) {
		r.t.Fatalf("snapshot bytes changed after source replacement: %q err=%v", raw, err)
	}
	r.calls++
	return CommandResult{Stdout: fakeResponse(argv), Exit: 0}, nil
}

type paginatedCRDRunner struct {
	t        *testing.T
	timeouts []time.Duration
}

func (f *paginatedCRDRunner) Run(ctx context.Context, argv, _ []string, timeout time.Duration) (CommandResult, error) {
	f.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || timeout <= 0 || timeout > time.Until(deadline)+time.Millisecond {
		f.t.Fatalf("page timeout %s is not bounded by parent deadline %v", timeout, deadline)
	}
	f.timeouts = append(f.timeouts, timeout)
	continuation := "next"
	if len(f.timeouts) == 2 {
		continuation = ""
	}
	value := map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": continuation}, "items": []any{}}
	raw, _ := json.Marshal(value)
	return CommandResult{Stdout: raw, Exit: 0}, nil
}

func (f *oneFailureRunner) Run(ctx context.Context, argv, env []string, timeout time.Duration) (CommandResult, error) {
	if strings.Contains(strings.Join(argv, " "), "storageclasses.storage.k8s.io") {
		return CommandResult{Exit: 1, Class: "authorization_rbac_forbidden"}, nil
	}
	return f.fakeRunner.Run(ctx, argv, env, timeout)
}

func (f *fakeRunner) Run(_ context.Context, argv, env []string, timeout time.Duration) (CommandResult, error) {
	f.t.Helper()
	f.calls = append(f.calls, append([]string(nil), argv...))
	joined := strings.Join(argv, "\x00")
	if !strings.Contains(joined, "--context\x00"+f.private) || timeout != requestTimeout {
		f.t.Fatalf("kubectl authority missing: %q timeout=%s", argv, timeout)
	}
	for _, value := range env {
		if strings.HasPrefix(value, "TOKEN=") {
			f.t.Fatal("undeclared token reached kubectl environment")
		}
	}
	return CommandResult{Stdout: fakeResponse(argv), Exit: 0}, nil
}

func fakeResponse(argv []string) []byte {
	joined := strings.Join(argv, " ")
	var value any
	switch {
	case strings.Contains(joined, "--raw=/version"):
		value = map[string]any{"gitVersion": "v1.34.1"}
	case strings.Contains(joined, " nodes "):
		value = map[string]any{"items": []any{}}
	case strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{}}
	case strings.Contains(joined, "--raw=/apis"):
		value = map[string]any{"groups": []any{}}
	case strings.Contains(joined, "--raw=/api") && !strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"versions": []any{"v1"}}
	default:
		value = map[string]any{"items": []any{}}
	}
	raw, _ := json.Marshal(value)
	return raw
}

func TestCollectWithFakeKubectl(t *testing.T) {
	t.Setenv("TOKEN", "private-token-canary")
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	tmp := t.TempDir()
	kubeconfig := filepath.Join(tmp, "private-kubeconfig-canary")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfigYAML+"# private-kubeconfig-content-canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(tmp, "out")
	fake := &fakeRunner{t: t, private: "private-context-canary"}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: fake}).Collect(context.Background(), Options{
		OutputRoot: output, Kubeconfig: kubeconfig, Contexts: []string{fake.private},
		AcknowledgeExecRisk: true, AllowPartial: false, Kubectl: os.Args[0],
		IncludeComponentConfiguration: true, ComponentConfigurationProfile: "v3",
		ExecEnv: proxyEnvironmentNames, Now: func() time.Time { return time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC) },
		Random: strings.NewReader(strings.Repeat("r", 32)),
	}, &stdout, &stderr)
	if code != 0 {
		omissions, _ := os.ReadFile(filepath.Join(dir, "000", "omissions.tsv"))
		t.Fatalf("Collect exit=%d stderr=%q omissions=%q", code, stderr.String(), omissions)
	}
	if len(fake.calls) != len(baseQueries)+1 {
		t.Fatalf("kubectl calls=%d want=%d", len(fake.calls), len(baseQueries)+1)
	}
	for _, path := range []string{filepath.Join(dir, "index.json"), filepath.Join(dir, "MANIFEST.sha256"), filepath.Join(dir, "000", "server-version.json"), filepath.Join(dir, "000", "crd-api-surface.json")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private output %s: %v mode=%v", path, err, info.Mode().Perm())
		}
	}
	for _, name := range []string{"index.json", "MANIFEST.sha256", filepath.Join("000", "snapshot-metadata.json"), filepath.Join("000", "omissions.tsv")} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{fake.private, "private-token-canary", "private-kubeconfig-canary", "private-kubeconfig-content-canary"} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatalf("private value %q escaped in %s", private, name)
			}
		}
	}
	if strings.Contains(stdout.String(), fake.private) || strings.Contains(stderr.String(), fake.private) {
		t.Fatal("raw context escaped through status streams")
	}
	var metadata map[string]any
	metadataRaw, err := os.ReadFile(filepath.Join(dir, "000", "snapshot-metadata.json"))
	if err != nil || json.Unmarshal(metadataRaw, &metadata) != nil {
		t.Fatal("read collector metadata")
	}
	if metadata["componentConfigurationFilterDigest"] != digest(componentFilterContract("v3")) || metadata["kubectlBoundedRunnerDigest"] != digest(boundedRunnerContract) {
		t.Fatalf("behavior-contract digests not bound: %#v", metadata)
	}
	var surface map[string]any
	surfaceRaw, err := os.ReadFile(filepath.Join(dir, "000", "component-configuration-surface.json"))
	if err != nil || json.Unmarshal(surfaceRaw, &surface) != nil {
		t.Fatal("read component surface")
	}
	if at(surface, "metadata", "filterDigest") != digest(componentFilterContract("v3")) || at(surface, "metadata", "aggregateDigest") != digest(componentAggregateContract("v3")) {
		t.Fatalf("surface contract digests not bound: %#v", at(surface, "metadata"))
	}
}

func TestCollectUsesOnePrivateKubeconfigSnapshotAndCleansIt(t *testing.T) {
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	tmp := t.TempDir()
	original := filepath.Join(tmp, "config")
	raw := []byte(testKubeconfigYAML + "# source-stability-canary\n")
	if err := os.WriteFile(original, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &snapshotStabilityRunner{t: t, original: original, want: raw}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: runner}).Collect(context.Background(), Options{
		OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: original, Contexts: []string{"private-context"},
		AcknowledgeExecRisk: true, Kubectl: os.Args[0], ExecEnv: proxyEnvironmentNames,
		Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("s", 32)),
	}, &stdout, &stderr)
	if code != 0 || runner.calls == 0 || dir == "" {
		t.Fatalf("collect code=%d calls=%d dir=%q stderr=%q", code, runner.calls, dir, stderr.String())
	}
	if relative, err := filepath.Rel(dir, runner.snapshot); err != nil || !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		t.Fatalf("snapshot was inside the observation directory: relative=%q err=%v", relative, err)
	}
	if _, err := os.Stat(runner.snapshot); !os.IsNotExist(err) {
		t.Fatalf("snapshot remained after collection: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(runner.snapshot)); !os.IsNotExist(err) {
		t.Fatalf("snapshot directory remained after collection: %v", err)
	}
	for _, path := range []string{filepath.Join(dir, "index.json"), filepath.Join(dir, "MANIFEST.sha256")} {
		contents, err := os.ReadFile(path)
		if err != nil || bytes.Contains(contents, raw) || bytes.Contains(contents, []byte(runner.snapshot)) {
			t.Fatalf("snapshot material reached exported output %s: %v", path, err)
		}
	}
}

func TestCollectCleansKubeconfigSnapshotAfterRunnerFailureOrCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprintf("canceled-%t", canceled), func(t *testing.T) {
			for _, name := range proxyEnvironmentNames {
				t.Setenv(name, "")
			}
			tmp := t.TempDir()
			config := filepath.Join(tmp, "config")
			if err := os.WriteFile(config, []byte(testKubeconfigYAML), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := &snapshotFailureRunner{t: t}
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			if canceled {
				cancel()
			}
			defer cancel()
			_, code := (Collector{Runner: runner}).Collect(ctx, Options{
				OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: config, Contexts: []string{"private-context"},
				AcknowledgeExecRisk: true, Kubectl: os.Args[0], ExecEnv: proxyEnvironmentNames,
				Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("f", 32)),
			}, &stdout, &stderr)
			if code != 6 || runner.snapshot == "" {
				t.Fatalf("collect code=%d snapshot=%q stderr=%q", code, runner.snapshot, stderr.String())
			}
			if _, err := os.Stat(runner.snapshot); !os.IsNotExist(err) {
				t.Fatalf("snapshot remained after runner failure: %v", err)
			}
			if _, err := os.Stat(filepath.Dir(runner.snapshot)); !os.IsNotExist(err) {
				t.Fatalf("snapshot directory remained after runner failure: %v", err)
			}
		})
	}
}

func TestCaptureCRDsUsesOnePaginationDeadline(t *testing.T) {
	runner := &paginatedCRDRunner{t: t}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	omissions := []omission{}
	histogram := map[string]int{}
	failed := (Collector{Runner: runner}).captureCRDs(ctx, nil, Options{Kubeconfig: "/not-opened"}, "private-context", t.TempDir(), &omissions, histogram)
	if failed || len(omissions) != 0 || len(runner.timeouts) != 2 {
		t.Fatalf("failed=%v omissions=%#v timeouts=%v", failed, omissions, runner.timeouts)
	}
	if runner.timeouts[0] >= requestTimeout || runner.timeouts[1] > runner.timeouts[0] {
		t.Fatalf("pagination timeouts do not share the parent budget: %v", runner.timeouts)
	}
}

func TestRemainingRequestTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	if got, ok := remainingRequestTimeout(now, now.Add(5*time.Second), requestTimeout); !ok || got != 5*time.Second {
		t.Fatalf("remaining timeout=(%s,%v)", got, ok)
	}
	if got, ok := remainingRequestTimeout(now, now, requestTimeout); ok || got != 0 {
		t.Fatalf("expired timeout=(%s,%v)", got, ok)
	}
}

func TestValidateOptionsRejectsKubeconfigLinksAndAcknowledgement(t *testing.T) {
	tmp := t.TempDir()
	original := filepath.Join(tmp, "config")
	if err := os.WriteFile(original, []byte(testKubeconfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(tmp, "linked")
	if err := os.Link(original, linked); err != nil {
		t.Fatal(err)
	}
	base := Options{OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: linked, Contexts: []string{"private"}, AcknowledgeExecRisk: true, Kubectl: "/bin/false"}
	if err := validateOptions(&base); err == nil {
		t.Fatal("hard-linked kubeconfig accepted")
	}
	symlink := filepath.Join(tmp, "symlink")
	if err := os.Symlink(original, symlink); err != nil {
		t.Fatal(err)
	}
	base.Kubeconfig = symlink
	if err := validateOptions(&base); err == nil {
		t.Fatal("symlinked kubeconfig accepted")
	}
	parent := filepath.Join(tmp, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	parentConfig := filepath.Join(parent, "config")
	if err := os.WriteFile(parentConfig, []byte(testKubeconfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(tmp, "linked-parent")
	if err := os.Symlink(parent, linkedParent); err != nil {
		t.Fatal(err)
	}
	base.Kubeconfig = filepath.Join(linkedParent, "config")
	if err := validateOptions(&base); err == nil {
		t.Fatal("kubeconfig below a symlinked parent accepted")
	}
	if err := os.Chmod(parentConfig, 0o644); err != nil {
		t.Fatal(err)
	}
	base.Kubeconfig = parentConfig
	if err := validateOptions(&base); err == nil {
		t.Fatal("group-readable kubeconfig accepted")
	}
	base.Kubeconfig = original
	base.AcknowledgeExecRisk = false
	if err := validateOptions(&base); err == nil {
		t.Fatal("missing exec-risk acknowledgement accepted")
	}
}

func TestKubeconfigSnapshotReferencePolicy(t *testing.T) {
	base := "apiVersion: v1\nkind: Config\ncontexts: []\n"
	for name, raw := range map[string]string{
		"absolute-built-in-and-bare-exec": base + "users:\n- user:\n    client-certificate: /private/client.pem\n    client-key: /private/client.key\n    tokenFile: /private/token\n    exec:\n      command: aws-iam-authenticator\n",
		"absolute-exec":                   base + "users:\n- user:\n    exec:\n      command: /private/bin/helper\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateKubeconfigSnapshotSemantics([]byte(raw)); err != nil {
				t.Fatalf("valid snapshot form rejected: %v", err)
			}
		})
	}
	for name, raw := range map[string]string{
		"relative-certificate-authority": base + "clusters:\n- cluster:\n    certificate-authority: ca.pem\nusers: []\n",
		"relative-client-certificate":    base + "users:\n- user:\n    client-certificate: cert.pem\n",
		"relative-client-key":            base + "users:\n- user:\n    client-key: keys/client.key\n",
		"relative-token-file":            base + "users:\n- user:\n    tokenFile: token\n",
		"relative-exec":                  base + "users:\n- user:\n    exec:\n      command: ./helper\n",
		"plugin-defined-auth-provider":   base + "users:\n- user:\n    auth-provider:\n      name: example\n",
		"case-folded-clusters":           base + "Clusters: []\nusers: []\n",
		"case-folded-users":              base + "Users:\n- user:\n    tokenFile: relative-token\n",
		"canonical-and-case-folded-user": base + "users: []\nUsers:\n- user:\n    tokenFile: relative-token\n",
		"case-folded-user":               base + "users:\n- User:\n    tokenFile: relative-token\n",
		"case-folded-client-certificate": base + "users:\n- user:\n    Client-Certificate: relative-cert\n",
		"case-folded-client-key":         base + "users:\n- user:\n    Client-Key: relative-key\n",
		"case-folded-token-file":         base + "users:\n- user:\n    tokenfile: relative-token\n",
		"case-folded-auth-provider":      base + "users:\n- user:\n    Auth-Provider:\n      name: example\n",
		"case-folded-exec":               base + "users:\n- user:\n    Exec:\n      command: ./helper\n",
		"case-folded-exec-command":       base + "users:\n- user:\n    exec:\n      Command: ./helper\n",
		"case-folded-cluster-path":       base + "clusters:\n- Cluster:\n    Certificate-Authority: relative-ca\nusers: []\n",
		"yaml-alias":                     base + "users: &users []\n",
		"multiple-documents":             base + "users: []\n---\napiVersion: v1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateKubeconfigSnapshotSemantics([]byte(raw)); err == nil {
				t.Fatal("unsafe snapshot form accepted")
			}
		})
	}
}

func TestReadKubeconfigForSnapshotRejectsOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxKubeconfigSnapshotBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readKubeconfigForSnapshot(path); err == nil || raw != nil {
		wipeKubeconfigBytes(raw)
		t.Fatalf("oversized kubeconfig accepted: bytes=%d err=%v", len(raw), err)
	}
}

func TestCollectPartialIsBoundedAndRedacted(t *testing.T) {
	t.Setenv("TOKEN", "private-token-canary")
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	tmp := t.TempDir()
	config := filepath.Join(tmp, "config")
	if err := os.WriteFile(config, []byte(testKubeconfigYAML+"# private-config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &oneFailureRunner{fakeRunner: fakeRunner{t: t, private: "private-context"}}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: fake}).Collect(context.Background(), Options{OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: config, Contexts: []string{"private-context"}, AcknowledgeExecRisk: true, Kubectl: os.Args[0], ExecEnv: proxyEnvironmentNames, Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("x", 32))}, &stdout, &stderr)
	if code != 6 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "000", "omissions.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("kubernetes_api_read_failed_authorization_rbac_forbidden")) {
		t.Fatalf("omissions=%q", raw)
	}
	combined := stdout.String() + stderr.String() + string(raw)
	for _, private := range []string{"private-context", "private-token-canary", "private-config"} {
		if strings.Contains(combined, private) {
			t.Fatalf("private value %q escaped", private)
		}
	}
}
