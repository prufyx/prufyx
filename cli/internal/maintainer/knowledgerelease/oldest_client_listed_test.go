// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

// pinnedClientSourceEnv names a directory that holds the source tree of the
// oldest supported client (the commit in cli/knowledge/oldest-supported-client.txt,
// for example from `git archive`). The test builds that client with the release
// version stamp and runs it against signed packages; it is an integration test
// (it compiles two more programs) and is skipped when the variable is unset.
const pinnedClientSourceEnv = "PRUFYX_PINNED_CLIENT_SRC"

func pinFileVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "knowledge", "oldest-supported-client.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "version=") {
		t.Fatalf("pin file %q", raw)
	}
	return strings.TrimPrefix(lines[1], "version=")
}

// buildClient builds program of the Go module whose cli directory is cliDir,
// stamped with version, the way the release and the oldest-client gate stamp it.
func buildClient(t *testing.T, cliDir, program, version, out string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-X github.com/prufyx/prufyx/cli/internal/buildidentity.Version="+version, "-o", out, "./cmd/"+program)
	cmd.Dir = cliDir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s %s in %s: %v\n%s", program, version, cliDir, err, output)
	}
}

type clientRun struct {
	code           int
	stdout, stderr string
}

func runVerify(t *testing.T, client, tarPath string, o Options, revision string) clientRun {
	t.Helper()
	raw, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	cmd := exec.Command(client, "db", "verify", tarPath, "--profile", "cncf-projects",
		"--bootstrap-root", o.Root, "--bootstrap-root-digest", o.RootDigest,
		"--expected-package-digest", "sha256:"+hex.EncodeToString(sum[:]), "--expected-revision", revision, "--format", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	run := clientRun{stdout: stdout.String(), stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		run.code = exit.ExitCode()
	default:
		t.Fatal(err)
	}
	return run
}

// TestOldestClientRefusesListedFamilyTooNew builds the pinned oldest supported
// client with its release stamp and runs `db verify` on packages signed with
// the same root:
//   - a package that carries the listed family and names the floor: exit 15,
//     "too new", never an integrity failure (exit 3);
//   - the control, a package the pinned client's own release tool built
//     without the family: exit 0;
//   - the same family package read by a client at the floor: exit 0.
//
// It also records what the pinned client does with a family package that does
// not name the floor (the defect the floor closes): a refusal for another cause (engine capability) at best.
func TestOldestClientRefusesListedFamilyTooNew(t *testing.T) {
	src := os.Getenv(pinnedClientSourceEnv)
	if src == "" {
		t.Skipf("integration test: set %s to the source tree of the oldest supported client", pinnedClientSourceEnv)
	}
	pinCLI := filepath.Join(src, "cli")
	if _, err := os.Stat(filepath.Join(pinCLI, "go.mod")); err != nil {
		t.Fatalf("%s=%s holds no cli/go.mod: %v", pinnedClientSourceEnv, src, err)
	}
	pinVersion := pinFileVersion(t)
	bin := t.TempDir()
	pinned, pinnedMaintainer, floorClient := filepath.Join(bin, "pinned"), filepath.Join(bin, "pinned-maintainer"), filepath.Join(bin, "at-floor")
	buildClient(t, pinCLI, "prufyx-community", pinVersion, pinned)
	buildClient(t, pinCLI, "prufyx-maintainer", pinVersion, pinnedMaintainer)
	buildClient(t, filepath.Join("..", "..", ".."), "prufyx-community", cncfcheck.ListedFamilyFloor, floorClient)

	// The family package: signed by this tree's release with the pin at the floor.
	withListedPack(t, nil)
	o := projectsFixture(t)
	o.Now = time.Now().UTC().Truncate(time.Second)
	o.OldestClient = cncfcheck.ListedFamilyFloor
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
	familyTar := filepath.Join(o.OutputDir, "cncf-projects-"+o.Revision+".tar")

	// The control: the pinned client's own release tool, same keys and root.
	control := filepath.Join(filepath.Dir(o.OutputDir), "control")
	cmd := exec.Command(pinnedMaintainer, "knowledge-publish", "release", "--profile", "cncf-projects", "--first-release",
		"--revision", o.Revision, "--version", "1", "--root", o.Root, "--root-digest", o.RootDigest,
		"--targets-key", o.TargetsKey, "--snapshot-key", o.SnapshotKey, "--timestamp-key", o.TimestampKey,
		"--passphrase-file", o.PassphraseFile, "--output-dir", control)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the pinned client's release tool: %v\n%s", err, output)
	}
	controlTar := filepath.Join(control, "cncf-projects-"+o.Revision+".tar")

	got := runVerify(t, pinned, familyTar, o, o.Revision)
	t.Logf("pinned %s, family package with the floor: exit %d stderr=%q", pinVersion, got.code, strings.TrimSpace(got.stderr))
	if got.code != 15 || !strings.Contains(got.stderr, "too new") || !strings.Contains(got.stderr, "upgrade prufyx to >= "+cncfcheck.ListedFamilyFloor) {
		t.Fatalf("pinned client on the family package: exit %d, want 15 with too new and the floor; stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
	}
	got = runVerify(t, pinned, controlTar, o, o.Revision)
	t.Logf("pinned %s, control package: exit %d", pinVersion, got.code)
	if got.code != 0 || !json.Valid([]byte(got.stdout)) || !strings.Contains(got.stdout, "VERIFIED") {
		t.Fatalf("pinned client on the control package: exit %d stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
	}
	got = runVerify(t, floorClient, familyTar, o, o.Revision)
	t.Logf("client at the floor %s, family package: exit %d", cncfcheck.ListedFamilyFloor, got.code)
	if got.code != 0 || !strings.Contains(got.stdout, "VERIFIED") {
		t.Fatalf("client at the floor on the family package: exit %d stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
	}

	// The defect: the same family package without the floor. The publish guard
	// refuses to write it, so the guard is lifted for this one build only.
	member := []byte(`,"minClientVersion":"` + cncfcheck.ListedFamilyFloor + `"`)
	dropFloor := func(index cncfcheck.ExternalTarget) cncfcheck.ExternalTarget {
		if !bytes.Contains(index.Bytes, member) {
			t.Fatal("the index does not carry the floor")
		}
		index.Bytes = bytes.Replace(index.Bytes, member, nil, 1)
		return index
	}
	withListedPack(t, dropFloor)
	original := checkListedShipping
	checkListedShipping = func([]byte, [][]byte, string) error { return nil }
	defer func() { checkListedShipping = original }()
	bare := projectsFixture(t)
	bare.Now = o.Now
	bare.OldestClient = cncfcheck.ListedFamilyFloor
	bare.Root, bare.RootDigest, bare.TargetsKey, bare.SnapshotKey, bare.TimestampKey, bare.PassphraseFile = o.Root, o.RootDigest, o.TargetsKey, o.SnapshotKey, o.TimestampKey, o.PassphraseFile
	if _, err := Run(bare); err != nil {
		t.Fatalf("build of the package without the floor: %v", err)
	}
	got = runVerify(t, pinned, filepath.Join(bare.OutputDir, "cncf-projects-"+bare.Revision+".tar"), bare, bare.Revision)
	t.Logf("pinned %s, family package WITHOUT the floor: exit %d stderr=%q", pinVersion, got.code, strings.TrimSpace(got.stderr))
	// Today the pinned client also refuses on the engine capability (exit 15,
	// a different cause), so only the cause is asserted: without the floor the
	// refusal never names the minimum client, and it is never a pass.
	if got.code == 0 || strings.Contains(got.stderr, "upgrade prufyx to >=") {
		t.Fatalf("without the floor the pinned client exited %d with %q", got.code, got.stderr)
	}
}
