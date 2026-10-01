// SPDX-License-Identifier: AGPL-3.0-only

package validation

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var runFixtureNames = []string{
	"current-bundle.json",
	"plan.json",
	"proposed-bundle.json",
	"report.json",
	"replay.json",
	"run-manifest.json",
}

func stageRunFixture(t *testing.T, root *OutputRoot) {
	t.Helper()
	for _, name := range runFixtureNames {
		if err := root.Stage(name, []byte(name)); err != nil {
			t.Fatalf("Stage(%q): %v", name, err)
		}
	}
}

func TestOutputRootExplicitBatchPublishesOnceAndSortedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	batch, err := root.BeginBatch()
	if err != nil {
		t.Fatal(err)
	}
	stageRunFixture(t, batch)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public root before commit = %v", err)
	}
	manifest, err := batch.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	var decoded RunManifest
	if err := json.Unmarshal(manifest, &decoded); err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(decoded.Files))
	for i, file := range decoded.Files {
		got[i] = file.Name
	}
	want := append([]string(nil), runFixtureNames...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest names = %v, want %v", got, want)
	}
	if err := batch.Commit(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(runFixtureNames) {
		t.Fatalf("published files = %d, want %d", len(entries), len(runFixtureNames))
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("published root mode = %v/%v, want 0700", info, err)
	}
	for _, name := range runFixtureNames {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() || !singleLink(info) {
			t.Fatalf("published %s mode/type/link = %v/%v/%v", name, info.Mode(), info.Mode().IsRegular(), singleLink(info))
		}
	}
	if err := batch.Commit(); !errors.Is(err, ErrIO) {
		t.Fatalf("second Commit() = %v, want ErrIO", err)
	}
}

func TestOutputRootFinalDirectoryObserverDoesNotConsumeValidationScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		outputFinalDirectoryHook = nil
		_ = root.Close()
	})
	stageRunFixture(t, &root)
	outputFinalDirectoryHook = func(directory *os.File) error {
		_, err := directory.Readdirnames(-1)
		return err
	}
	if err := root.Commit(); err != nil {
		t.Fatalf("Commit after observing final directory = %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(runFixtureNames) {
		t.Fatalf("published files = %d, want %d", len(entries), len(runFixtureNames))
	}
}

func TestOutputRootExplicitBatchPostRenameSyncErrorRetainsCompleteRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stageRunFixture(t, &root)
	outputParentSyncHook = func(*os.File) error { return errors.New("synthetic post-rename fsync failure") }
	defer func() { outputParentSyncHook = nil }()
	if err := root.Commit(); !errors.Is(err, ErrIO) {
		t.Fatalf("post-rename Commit = %v, want ErrIO", err)
	}
	for _, name := range runFixtureNames {
		data, readErr := os.ReadFile(filepath.Join(path, name))
		if readErr != nil || string(data) != name {
			t.Fatalf("post-rename output %s = %q/%v, want complete exact bytes", name, data, readErr)
		}
	}
	if err := root.Commit(); !errors.Is(err, ErrIO) {
		t.Fatalf("retry Commit = %v, want ErrIO", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareOutputRoot(path); !errors.Is(err, ErrIO) {
		t.Fatalf("replacement PrepareOutputRoot = %v, want no-overwrite ErrIO", err)
	}
}

func TestOutputRootExplicitBatchRejectsDuplicateOversizeAndUnknown(t *testing.T) {
	cases := []struct {
		name string
		call func(*OutputRoot) error
	}{
		{name: "unknown", call: func(root *OutputRoot) error { return root.Stage("unknown.json", []byte("x")) }},
		{name: "duplicate", call: func(root *OutputRoot) error {
			if err := root.Stage(runFixtureNames[0], []byte("one")); err != nil {
				return err
			}
			return root.Stage(runFixtureNames[0], []byte("two"))
		}},
		{name: "oversize", call: func(root *OutputRoot) error {
			return root.Stage(runFixtureNames[0], bytes.Repeat([]byte("x"), MaxOutputReportBytes+1))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			root, err := PrepareOutputRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			batch, err := root.BeginBatch()
			if err != nil {
				t.Fatal(err)
			}
			err = tc.call(batch)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("public root after rejected Stage = %v", statErr)
			}
			if closeErr := root.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		})
	}
}

func TestOutputRootExplicitBatchPartialWriteFaultCleansPrivateStage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.BeginBatch(); err != nil {
		t.Fatal(err)
	}
	outputWriteFaultHook = func(name string) error {
		if name == runFixtureNames[0] {
			return errors.New("synthetic partial write")
		}
		return nil
	}
	defer func() { outputWriteFaultHook = nil }()
	if err := root.Stage(runFixtureNames[0], []byte("partial")); err == nil {
		t.Fatal("fault-injected Stage succeeded")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public root after partial write = %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".prufyx-output-stage-") {
			t.Fatalf("private staging directory remained: %s", entry.Name())
		}
	}
}

func TestOutputRootExplicitBatchCollisionNeverOverwrites(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	stageRunFixture(t, &root)
	if err := os.WriteFile(path, []byte("owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Commit(); err == nil {
		t.Fatal("collision Commit succeeded")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "owner" {
		t.Fatalf("collision owner changed: %q/%v", data, err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOutputRootStageNameSwapDoesNotChangeDescriptorBoundPublication(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		outputStageRenameHook = nil
		_ = root.Close()
	})
	stageRunFixture(t, &root)
	stagePath := filepath.Join(parent, root.stageName)
	attackerStage := filepath.Join(parent, "attacker-stage")
	movedStage := filepath.Join(parent, "moved-stage")
	if err := os.Mkdir(attackerStage, 0o700); err != nil {
		t.Fatal(err)
	}
	attackerBytes := []byte("attacker-owned")
	if err := os.WriteFile(filepath.Join(attackerStage, "attacker.txt"), attackerBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	outputStageRenameHook = func(stageName string) error {
		if stageName != root.stageName {
			return errors.New("unexpected stage name")
		}
		if err := os.Rename(stagePath, movedStage); err != nil {
			return err
		}
		return os.Rename(attackerStage, stagePath)
	}
	if err := root.Commit(); err != nil {
		t.Fatalf("stage-name swap Commit = %v, want descriptor-bound success", err)
	}
	// The source pathname was swapped, but publication copied from the retained
	// descriptor. The competing directory remains untouched at its new name.
	for _, name := range runFixtureNames {
		got, err := os.ReadFile(filepath.Join(path, name))
		if err != nil || string(got) != name {
			t.Fatalf("published %s = %q/%v, want staged bytes", name, got, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(path, "attacker.txt"))
	if !errors.Is(err, os.ErrNotExist) || got != nil {
		t.Fatalf("attacker content was published: %q/%v", got, err)
	}
	if _, err := os.Stat(movedStage); err != nil {
		t.Fatalf("original stage was not retained for descriptor cleanup: %v", err)
	}
}

func TestOutputRootStageNameSwapDestinationRacePreservesBothOwners(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		outputStageRenameHook = nil
		_ = root.Close()
	})
	stageRunFixture(t, &root)
	stagePath := filepath.Join(parent, root.stageName)
	attackerStage := filepath.Join(parent, "attacker-stage")
	movedStage := filepath.Join(parent, "moved-stage")
	if err := os.Mkdir(attackerStage, 0o700); err != nil {
		t.Fatal(err)
	}
	stageOwnerBytes := []byte("stage-owner")
	if err := os.WriteFile(filepath.Join(attackerStage, "owner.txt"), stageOwnerBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	destinationBytes := []byte("destination-owner")
	outputStageRenameHook = func(stageName string) error {
		if err := os.Rename(stagePath, movedStage); err != nil {
			return err
		}
		if err := os.Rename(attackerStage, stagePath); err != nil {
			return err
		}
		return os.WriteFile(path, destinationBytes, 0o600)
	}
	if err := root.Commit(); !errors.Is(err, ErrIO) {
		t.Fatalf("stage/destination race Commit = %v, want ErrIO", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, destinationBytes) {
		t.Fatalf("destination owner = %q/%v, want unchanged content", got, err)
	}
	got, err = os.ReadFile(filepath.Join(stagePath, "owner.txt"))
	if err != nil || !bytes.Equal(got, stageOwnerBytes) {
		t.Fatalf("stage-name owner = %q/%v, want unchanged content", got, err)
	}
}

func TestOutputRootFinalDirectorySwapNeverCleansAttacker(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		outputFilePostCopyHook = nil
		outputFinalDirectoryHook = nil
		_ = root.Close()
	})
	stageRunFixture(t, &root)
	moved := filepath.Join(parent, "moved-run")
	attacker := filepath.Join(parent, "attacker-run")
	outputFilePostCopyHook = func(_ *os.File, name string) error {
		if name != runFixtureNames[0] {
			return nil
		}
		if err := os.Rename(path, moved); err != nil {
			return err
		}
		if err := os.Mkdir(attacker, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(attacker, "owner.txt"), []byte("attacker"), 0o600); err != nil {
			return err
		}
		return os.Rename(attacker, path)
	}
	if err := root.Commit(); !errors.Is(err, ErrIO) {
		t.Fatalf("final directory swap Commit = %v, want ErrIO", err)
	}
	got, err := os.ReadFile(filepath.Join(path, "owner.txt"))
	if err != nil || string(got) != "attacker" {
		t.Fatalf("attacker final content = %q/%v, want unchanged", got, err)
	}
}

func TestOutputRootPerFileCreatorIsNeverRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		outputFileCommitHook = nil
		_ = root.Close()
	})
	stageRunFixture(t, &root)
	outputFileCommitHook = func(directory *os.File, name string) error {
		if name != runFixtureNames[0] {
			return nil
		}
		creator, err := openRelativeExclusive(directory, name, 0o600)
		if err != nil {
			return err
		}
		if err := writeAll(creator, []byte("attacker")); err != nil {
			_ = creator.Close()
			return err
		}
		if err := creator.Sync(); err != nil {
			_ = creator.Close()
			return err
		}
		if err := creator.Close(); err != nil {
			return err
		}
		return errors.New("synthetic destination creator")
	}
	if err := root.Commit(); err == nil {
		t.Fatal("per-file creator Commit succeeded")
	}
	got, err := os.ReadFile(filepath.Join(path, runFixtureNames[0]))
	if err != nil || string(got) != "attacker" {
		t.Fatalf("per-file creator output = %q/%v, want unchanged", got, err)
	}
}

func TestOutputRootFinalValidationFailureRemovesOwnedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		outputFinalDirectoryHook = nil
		_ = root.Close()
	})
	stageRunFixture(t, &root)
	outputFinalDirectoryHook = func(*os.File) error { return errors.New("synthetic final validation failure") }
	if err := root.Commit(); err == nil {
		t.Fatal("final validation failure Commit succeeded")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned final directory remained after failure: %v", err)
	}
}

func TestOutputRootExplicitBatchRejectsStagedHardlinkBeforeCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stageRunFixture(t, &root)
	// The staging directory is private but this test models a same-UID writer
	// that obtains its name from the local filesystem.
	stagePath := filepath.Join(filepath.Dir(path), root.stageName, runFixtureNames[0])
	linkPath := filepath.Join(t.TempDir(), "link")
	if err := os.Link(stagePath, linkPath); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if err := root.Commit(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("hard-linked Commit = %v, want ErrIntegrity", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public root after hard-link rejection = %v", err)
	}
	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}
}

func TestOutputRootExplicitBatchRejectsStagedByteTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stageRunFixture(t, &root)
	stagePath := filepath.Join(filepath.Dir(path), root.stageName, runFixtureNames[0])
	if err := os.WriteFile(stagePath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Commit(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered Commit = %v, want ErrIntegrity", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public root after tamper rejection = %v", err)
	}
}

func TestOutputRootExplicitBatchRejectsStagedSymlinkAsIntegrity(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stageRunFixture(t, &root)
	stagePath := filepath.Join(parent, root.stageName, runFixtureNames[0])
	if err := os.Remove(stagePath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, stagePath); err != nil {
		t.Fatal(err)
	}
	if err := root.Commit(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("symlink Commit = %v, want ErrIntegrity", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public root after symlink rejection = %v", err)
	}
}

func TestOutputRootExplicitBatchEnforcesMaximumBeforeNextStage(t *testing.T) {
	names := RunArtifactAllowlist()
	if len(names) < MaxRunArtifacts+1 {
		t.Fatalf("allowlist has %d names, need at least %d", len(names), MaxRunArtifacts+1)
	}
	root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range names[:MaxRunArtifacts] {
		if err := root.Stage(name, []byte(name)); err != nil {
			t.Fatalf("Stage(%q): %v", name, err)
		}
	}
	if err := root.Stage(names[MaxRunArtifacts], []byte("too many")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("maximum Stage = %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(root.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("public root after maximum rejection = %v", err)
	}
}

func TestOutputRootExplicitBatchCleansRogueStagedFile(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stageRunFixture(t, &root)
	rogue := filepath.Join(parent, root.stageName, "rogue.json")
	if err := os.WriteFile(rogue, []byte("rogue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Commit(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("rogue Commit = %v, want ErrIntegrity", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".prufyx-output-stage-") {
			t.Fatalf("staging directory remained after rogue cleanup: %s", entry.Name())
		}
	}
}

func TestOutputRootExplicitBatchCleansEmptyRogueDirectory(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stageRunFixture(t, &root)
	rogue := filepath.Join(parent, root.stageName, "rogue-dir")
	if err := os.Mkdir(rogue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.Commit(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("rogue directory Commit = %v, want ErrIntegrity", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".prufyx-output-stage-") {
			t.Fatalf("staging directory remained after empty rogue cleanup: %s", entry.Name())
		}
	}
}

func TestOutputRootExplicitBatchReportsNonEmptyRogueDirectory(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "run")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	stageRunFixture(t, &root)
	rogue := filepath.Join(parent, root.stageName, "rogue-dir")
	if err := os.Mkdir(rogue, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rogue, "child"), []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = root.Commit()
	if !errors.Is(err, ErrIntegrity) || !errors.Is(err, ErrIO) {
		t.Fatalf("non-empty rogue Commit = %v, want integrity plus cleanup I/O", err)
	}
	if _, statErr := os.Stat(filepath.Join(parent, root.stageName)); statErr != nil {
		t.Fatalf("non-empty rogue tree was silently discarded: %v", statErr)
	}
	if err := os.Remove(filepath.Join(rogue, "child")); err != nil {
		t.Fatal(err)
	}
	// The parent descriptor remains available after Commit's failed cleanup;
	// remove the now-empty quarantine tree by descriptor-relative cleanup.
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOutputRootWorkflowProfileRequiresExactEightFiles(t *testing.T) {
	root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"current-bundle.json", "adapter-artifact.json", "plan.json", "proposed-bundle.json", "binding.json", "report.json"} {
		if err := root.Stage(name, []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := root.Commit(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("incomplete workflow Commit = %v, want ErrIntegrity", err)
	}
}

func TestOutputRootExplicitBatchAllowlistIncludesWorkflowArtifacts(t *testing.T) {
	for _, name := range []string{"adapter-artifact.json", "binding.json"} {
		t.Run(name, func(t *testing.T) {
			root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "run"))
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err := root.BeginBatch(); err != nil {
				t.Fatal(err)
			}
			if err := root.Stage(name, []byte("workflow")); err != nil {
				t.Fatalf("Stage(%q) = %v, want accepted workflow artifact", name, err)
			}
		})
	}
	root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "run-unknown"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Stage("untrusted.json", []byte("private")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown artifact = %v, want ErrInvalid", err)
	}
}

func TestCanonicalRunManifestRejectsUnboundedSetsAndIsStable(t *testing.T) {
	files := make(map[string][]byte, len(runFixtureNames))
	for _, name := range runFixtureNames {
		files[name] = []byte(strings.ToUpper(name))
	}
	first, err := CanonicalRunManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	other := make(map[string][]byte, len(files))
	for name, value := range files {
		other[name] = value
	}
	second, err := CanonicalRunManifest(other)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("manifest not stable: %v, equal=%v", err, bytes.Equal(first, second))
	}
	if _, err := CanonicalRunManifest(map[string][]byte{"report.json": []byte("one")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short manifest error = %v, want ErrInvalid", err)
	}
}
