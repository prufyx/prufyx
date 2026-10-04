// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// TestSyntheticMetadataExtensionActivatesStableRawAdapter proves that an
// already-compiled raw-input adapter can acquire a fictional rule tuple from
// signed local metadata. The tuple and evidence dates are synthetic test data;
// this test makes no compatibility claim for Distribution 3.0.0 -> 4.0.0.
func TestSyntheticMetadataExtensionActivatesStableRawAdapter(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootRaw, emptyPackage, activePackage, emptyDigest, activeDigest := syntheticDistributionExtension(t, now)

	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath := writeMetadataExtensionFile(t, dir, "root.json", rootRaw)
	emptyPath := writeMetadataExtensionFile(t, dir, "empty.tar", emptyPackage)
	activePath := writeMetadataExtensionFile(t, dir, "active.tar", activePackage)
	raw := []byte(`{"schemaVersion":1,"name":"private/example","tag":"latest","architecture":"amd64","fsLayers":[],"history":[],"private-canary":"not-for-output"}`)
	rawPath := writeMetadataExtensionFile(t, dir, "manifest.json", raw)

	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "prufyx")
	build := exec.Command(goBinary, "build", "-o", binary, "./cmd/prufyx-community")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build direct-check binary: %v: %s", err, output)
	}

	embeddedArgs := []string{"check", "cncf", "--project", "distribution", "--image-manifest", rawPath, "--from", "3.0.0", "--to", "4.0.0", "--now", now.Format(time.RFC3339), "--format", "json"}
	embeddedCode, embeddedOut, embeddedErr := runMetadataExtensionCLI(t, binary, embeddedArgs...)
	if embeddedCode != 11 || len(embeddedErr) != 0 || !bytes.Contains(embeddedOut, []byte(`"assessment":"UNKNOWN"`)) || !bytes.Contains(embeddedOut, []byte(`"reasonCode":"RULE_TRANSITION_NOT_REVIEWED"`)) {
		t.Fatalf("embedded future tuple code=%d stdout=%s stderr=%s", embeddedCode, embeddedOut, embeddedErr)
	}

	rootDigest := digest(rootRaw)
	receipt1, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: emptyPath, StoreRoot: store, BootstrapRootPath: rootPath,
		BootstrapRootDigest: rootDigest, ExpectedRevision: "1", ExpectedBundleDigest: emptyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt1.TrustReceipt.Purpose != "synthetic_test_only" || !receipt1.SelectionChanged {
		t.Fatalf("empty import receipt=%+v", receipt1)
	}
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{
		PackagePath: activePath, StoreRoot: store,
		ExpectedRevision: "2", ExpectedBundleDigest: activeDigest,
	}); err != nil {
		t.Fatal(err)
	}

	externalArgs := []string{"check", "cncf", "--project", "distribution", "--image-manifest", rawPath, "--from", "3.0.0", "--to", "4.0.0", "--knowledge-db", store, "--format", "json"}
	externalCode, externalOut, externalErr := runMetadataExtensionCLI(t, binary, externalArgs...)
	if externalCode != 10 || !emptyOrAgeNote(externalErr) || !bytes.Contains(externalOut, []byte(`"status":"BLOCKED"`)) || !bytes.Contains(externalOut, []byte(`"knowledgeOrigin":"external_declared"`)) || !bytes.Contains(externalOut, []byte(`"purpose":"synthetic_test_only"`)) {
		t.Fatalf("external synthetic tuple code=%d stdout=%s stderr=%s", externalCode, externalOut, externalErr)
	}
	if bytes.Contains(externalOut, []byte("private-canary")) || bytes.Contains(externalOut, []byte("not-for-output")) || bytes.Contains(externalOut, []byte(rawPath)) || bytes.Contains(externalErr, []byte(rawPath)) {
		t.Fatal("private raw input crossed the direct-check boundary")
	}
	after, err := os.ReadFile(rawPath)
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("direct checks changed the raw input")
	}
}

func syntheticDistributionExtension(t *testing.T, now time.Time) (rootRaw, emptyPackage, activePackage []byte, emptyDigest, activeDigest string) {
	t.Helper()
	keys, err := generateKeySet()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, key := range keys {
			for index := range key.private {
				key.private[index] = 0
			}
		}
	}()
	root, err := signedRoot(1, now, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	rootRaw, err = root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := constraintsBundle("1", now, false)
	if err != nil {
		t.Fatal(err)
	}
	active, err := syntheticDistributionBundle("2", now)
	if err != nil {
		t.Fatal(err)
	}
	const target = "knowledge/constraints.v1.json"
	emptyPackage, err = signedTargetPackage(1, now, target, empty, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	activePackage, err = signedTargetPackage(2, now, target, active, keys, keys[metadata.TIMESTAMP].signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rootRaw, emptyPackage, activePackage, digest(empty), digest(active)
}

func syntheticDistributionBundle(revision string, now time.Time) ([]byte, error) {
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		return nil, err
	}
	catalogue, err := cncfcheck.Catalog(false, "distribution")
	if err != nil || len(catalogue.Projects) != 1 || len(catalogue.Projects[0].Checks) != 1 {
		return nil, errors.New("synthetic Distribution source is unavailable")
	}
	entry := catalogue.Projects[0].Checks[0]
	entry.Description = "Synthetic-test-only Distribution schema1 rule for a fictional version tuple."
	var rule map[string]json.RawMessage
	if json.Unmarshal(entry.Rule, &rule) != nil {
		return nil, errors.New("synthetic Distribution rule is invalid")
	}
	var subject map[string]json.RawMessage
	if json.Unmarshal(rule["subject"], &subject) != nil {
		return nil, errors.New("synthetic Distribution subject is invalid")
	}
	subject["from"], _ = json.Marshal("3.0.0")
	subject["to"], _ = json.Marshal("4.0.0")
	rule["subject"], _ = json.Marshal(subject)
	rule["id"], _ = json.Marshal("synthetic.distribution-schema1.3-to-4")
	var evidence map[string]json.RawMessage
	if json.Unmarshal(rule["evidence"], &evidence) != nil {
		return nil, errors.New("synthetic Distribution evidence is invalid")
	}
	evidence["reviewedAt"], _ = json.Marshal(now.Add(-time.Hour).Format(time.RFC3339))
	evidence["validUntil"], _ = json.Marshal(now.Add(24 * time.Hour).Format(time.RFC3339))
	rule["evidence"], _ = json.Marshal(evidence)
	entry.Rule, err = json.Marshal(rule)
	if err != nil {
		return nil, err
	}
	pack := struct {
		Schema              string            `json:"schema"`
		Revision            string            `json:"revision"`
		PolicyID            string            `json:"policyId"`
		PolicyDigest        string            `json:"policyDigest"`
		LandscapeFileDigest string            `json:"landscapeFileDigest"`
		RegistryDigest      string            `json:"registryDigest"`
		Entries             []cncfcheck.Entry `json:"entries"`
	}{requirements.PackSchema, revision, requirements.PolicyID, requirements.PolicyDigest, requirements.LandscapeFileDigest, requirements.RegistryDigest, []cncfcheck.Entry{entry}}
	document := struct {
		Schema                 string `json:"schema"`
		Revision               string `json:"revision"`
		Purpose                string `json:"purpose"`
		EngineCapabilityDigest string `json:"engineCapabilityDigest"`
		Pack                   any    `json:"pack"`
	}{requirements.Schema, revision, "synthetic_test_only", requirements.EngineCapabilityDigest, pack}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if _, err := cncfcheck.ParseExternalBundle(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func writeMetadataExtensionFile(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// emptyOrAgeNote reports whether standard error is empty or only the
// knowledge age note: the synthetic database's rule ends within a day of the
// wall clock, which the command says on standard error.
func emptyOrAgeNote(stderr []byte) bool {
	return len(stderr) == 0 || regexp.MustCompile(`^prufyx: note: \d+ knowledge rules? (expires?|has|have) [^\n]*\n$`).Match(stderr)
}

func runMetadataExtensionCLI(t *testing.T, binary string, args ...string) (int, []byte, []byte) {
	t.Helper()
	command := exec.Command(binary, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err == nil {
		return 0, stdout.Bytes(), stderr.Bytes()
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run direct check: %v", err)
	}
	return exitError.ExitCode(), stdout.Bytes(), stderr.Bytes()
}
