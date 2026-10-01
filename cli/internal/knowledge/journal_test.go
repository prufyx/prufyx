// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

var errSimulatedProcessCut = errors.New("simulated process cut")

func TestInitialImportFaultHooksRequireExactResume(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	stages := []string{"pending-published", "refresh-returned", "trust-pointer-published", "revision-floor-pointer-published", "admission-published", "selection-published", "before-pending-clear"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			storeRoot := filepath.Join(dir, "store")
			rootPath := writeJournalFile(t, dir, "root.json", artifacts.Root)
			packagePath := writeJournalFile(t, dir, "revision-1.tar", artifacts.Revision1)
			req := ImportRequest{PackagePath: packagePath, StoreRoot: storeRoot, BootstrapRootPath: rootPath, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}
			cut := func(got string, _ *storeFS) error {
				if got == stage {
					return errSimulatedProcessCut
				}
				return nil
			}
			if _, err = importWithRefTime(req, journalAdmission, now, &now, cut); !errors.Is(err, errSimulatedProcessCut) {
				t.Fatalf("cut error=%v", err)
			}
			status, inspectErr := Inspect(storeRoot)
			if inspectErr != nil || status.State != "RECOVERY_REQUIRED" || status.CurrentEligible {
				t.Fatalf("status=%#v err=%v", status, inspectErr)
			}
			other := req
			other.PackagePath = writeJournalFile(t, dir, "revision-2.tar", artifacts.Revision2)
			if _, err = Import(other, journalAdmission); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("different package resumed transaction: %v", err)
			}
			other = req
			other.ExpectedRevision = ""
			if _, err = Import(other, journalAdmission); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("different assertions resumed transaction: %v", err)
			}
			receipt, retryErr := Import(req, journalAdmission)
			if retryErr != nil || receipt.Status != "IMPORTED" {
				t.Fatalf("exact retry receipt=%#v err=%v", receipt, retryErr)
			}
			if _, statErr := os.Stat(filepath.Join(storeRoot, "import-pending.json")); !os.IsNotExist(statErr) {
				t.Fatalf("pending marker remains: %v", statErr)
			}
		})
	}
}

func TestPostPublicationFailuresReturnDurableReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		stage            string
		journalWriteFail bool
		selectionChanged bool
	}{
		{name: "metadata-pointer", stage: "trust-pointer-published"},
		{name: "revision-floor-pointer", stage: "revision-floor-pointer-published"},
		{name: "selection-pointer", stage: "selection-published", selectionChanged: true},
		{name: "journal-write-after-metadata-pointer", stage: "metadata-current-published", journalWriteFail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			req := ImportRequest{
				PackagePath:          writeJournalFile(t, dir, "revision.tar", artifacts.Revision1),
				StoreRoot:            filepath.Join(dir, "store"),
				BootstrapRootPath:    writeJournalFile(t, dir, "root.json", artifacts.Root),
				BootstrapRootDigest:  manifest.BootstrapRoot.Digest,
				ExpectedRevision:     "1",
				ExpectedBundleDigest: manifest.Revisions[0].BundleDigest,
			}
			hook := func(stage string, store *storeFS) error {
				if stage != tc.stage {
					return nil
				}
				if !tc.journalWriteFail {
					return errSimulatedProcessCut
				}
				if err := store.remove("import-pending.json"); err != nil {
					return err
				}
				root, err := store.openDir(".", false)
				if err != nil {
					return err
				}
				defer root.Close()
				return fdMkdir(root, "import-pending.json", 0o700)
			}
			receipt, importErr := importWithRefTime(req, journalAdmission, now, &now, hook)
			if importErr == nil || !errors.Is(importErr, ErrRecoveryRequired) || (!tc.journalWriteFail && !errors.Is(importErr, errSimulatedProcessCut)) {
				t.Fatalf("error=%v", importErr)
			}
			if receipt.APIVersion != "prufyx.io/knowledge-import-receipt/v1" || receipt.Status != "REJECTED" || !receipt.TrustStateAdvanced || receipt.SelectionChanged != tc.selectionChanged {
				t.Fatalf("receipt=%#v error=%v", receipt, importErr)
			}
			if normalized, normalizeErr := normalizeDigest(receipt.TrustStateDigest); normalizeErr != nil || normalized != receipt.TrustStateDigest {
				t.Fatalf("unbound trust state digest %q", receipt.TrustStateDigest)
			}
		})
	}
}

func TestPostPublicationUnreadablePointerReturnsNoProgressClaims(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	req := ImportRequest{PackagePath: writeJournalFile(t, dir, "revision.tar", artifacts.Revision1), StoreRoot: filepath.Join(dir, "store"), BootstrapRootPath: writeJournalFile(t, dir, "root.json", artifacts.Root), BootstrapRootDigest: manifest.BootstrapRoot.Digest}
	hook := func(stage string, store *storeFS) error {
		if stage != "trust-pointer-published" {
			return nil
		}
		if err := store.remove("trust/current.json"); err != nil {
			return err
		}
		if err := store.write("trust/current.json", []byte("bad\n"), true); err != nil {
			return err
		}
		return errSimulatedProcessCut
	}
	receipt, importErr := importWithRefTime(req, journalAdmission, now, &now, hook)
	if receipt.APIVersion != "" || !errors.Is(importErr, errSimulatedProcessCut) || !errors.Is(importErr, ErrRecoveryRequired) || !errors.Is(importErr, ErrIntegrity) {
		t.Fatalf("receipt=%#v error=%v", receipt, importErr)
	}
}

func TestPostPublicationFailureValidatesUnchangedPriorSelectionAtReceiptTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	storeRoot := filepath.Join(dir, "store")
	rootPath := writeJournalFile(t, dir, "root.json", artifacts.Root)
	if _, err = importAt(ImportRequest{PackagePath: writeJournalFile(t, dir, "revision-1.tar", artifacts.Revision1), StoreRoot: storeRoot, BootstrapRootPath: rootPath, BootstrapRootDigest: manifest.BootstrapRoot.Digest}, journalAdmission, now); err != nil {
		t.Fatal(err)
	}
	req := ImportRequest{PackagePath: writeJournalFile(t, dir, "revision-2.tar", artifacts.Revision2), StoreRoot: storeRoot}
	hook := func(stage string, _ *storeFS) error {
		if stage == "trust-pointer-published" {
			return errSimulatedProcessCut
		}
		return nil
	}
	later := now.Add(time.Second)
	receipt, importErr := importWithRefTime(req, journalAdmission, later, &later, hook)
	if !errors.Is(importErr, errSimulatedProcessCut) || !errors.Is(importErr, ErrRecoveryRequired) || receipt.Status != "REJECTED" || !receipt.TrustStateAdvanced || receipt.SelectionChanged {
		t.Fatalf("receipt=%#v error=%v", receipt, importErr)
	}
}

func TestImportSIGKILLRecoveryMatrix(t *testing.T) {
	if os.Getenv("PRUFYX_KNOWLEDGE_KILL_HELPER") == "1" {
		t.Skip("parent-only test")
	}
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	stages := []string{
		"pending-published", "refresh-timestamp-fetch", "refresh-returned",
		"metadata-state-published", "metadata-pending-accepted", "metadata-current-published", "trust-pointer-published",
		"floor-state-published", "floor-pending-accepted", "floor-current-published", "revision-floor-pointer-published",
		"admission-published", "selection-published", "before-pending-clear",
	}
	for _, established := range []bool{false, true} {
		mode := "bootstrap"
		if established {
			mode = "established"
		}
		for _, stage := range stages {
			t.Run(mode+"-"+stage, func(t *testing.T) {
				dir := t.TempDir()
				storeRoot := filepath.Join(dir, "store")
				rootPath := writeJournalFile(t, dir, "root.json", artifacts.Root)
				p1 := writeJournalFile(t, dir, "revision-1.tar", artifacts.Revision1)
				p2 := writeJournalFile(t, dir, "revision-2.tar", artifacts.Revision2)
				var priorReceipt ImportReceipt
				if established {
					priorReceipt, err = Import(ImportRequest{PackagePath: p1, StoreRoot: storeRoot, BootstrapRootPath: rootPath, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}, journalAdmission)
					if err != nil {
						t.Fatal(err)
					}
				}
				req := ImportRequest{PackagePath: p1, StoreRoot: storeRoot, BootstrapRootPath: rootPath, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}
				wrongPackage := p2
				if established {
					req = ImportRequest{PackagePath: p2, StoreRoot: storeRoot, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest}
					wrongPackage = p1
				}
				killImportProcess(t, req, stage, filepath.Join(dir, "ready"))
				status, inspectErr := Inspect(storeRoot)
				if inspectErr != nil || status.State != "RECOVERY_REQUIRED" || status.CurrentEligible {
					t.Fatalf("status=%#v err=%v", status, inspectErr)
				}
				if established {
					verifiedAt, parseErr := time.Parse(time.RFC3339, priorReceipt.TrustReceipt.VerifiedAt)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					_, historicalErr := OpenHistorical(SelectionRequest{StoreRoot: storeRoot, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest, ExpectedTrustReceiptDigest: priorReceipt.TrustReceiptDigest}, verifiedAt, journalAdmission)
					if historicalErr != nil {
						t.Fatalf("historical admission unavailable during recovery: %v", historicalErr)
					}
				}
				wrong := req
				wrong.PackagePath = wrongPackage
				if _, err = Import(wrong, journalAdmission); !errors.Is(err, ErrRecoveryRequired) {
					t.Fatalf("different package resumed transaction: %v", err)
				}
				receipt, retryErr := Import(req, journalAdmission)
				if retryErr != nil || receipt.Status != "IMPORTED" {
					t.Fatalf("exact retry receipt=%#v err=%v", receipt, retryErr)
				}
			})
		}
	}
}

func TestRepeatedSIGKILLResumesSameBoundedTransition(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	req := ImportRequest{PackagePath: writeJournalFile(t, dir, "revision.tar", artifacts.Revision1), StoreRoot: filepath.Join(dir, "store"), BootstrapRootPath: writeJournalFile(t, dir, "root.json", artifacts.Root), BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest}
	killImportProcess(t, req, "floor-pending-accepted", filepath.Join(dir, "ready-1"))
	killImportProcess(t, req, "floor-pending-accepted", filepath.Join(dir, "ready-2"))
	receipt, err := Import(req, journalAdmission)
	if err != nil || receipt.Status != "IMPORTED" {
		t.Fatalf("repeated exact resume receipt=%#v err=%v", receipt, err)
	}
}

func killImportProcess(t *testing.T, req ImportRequest, stage, ready string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestImportSIGKILLHelper$")
	cmd.Env = append(os.Environ(),
		"PRUFYX_KNOWLEDGE_KILL_HELPER=1",
		"PRUFYX_KNOWLEDGE_KILL_STAGE="+stage,
		"PRUFYX_KNOWLEDGE_KILL_READY="+ready,
		"PRUFYX_KNOWLEDGE_STORE="+req.StoreRoot,
		"PRUFYX_KNOWLEDGE_PACKAGE="+req.PackagePath,
		"PRUFYX_KNOWLEDGE_ROOT="+req.BootstrapRootPath,
		"PRUFYX_KNOWLEDGE_ROOT_DIGEST="+req.BootstrapRootDigest,
		"PRUFYX_KNOWLEDGE_REVISION="+req.ExpectedRevision,
		"PRUFYX_KNOWLEDGE_BUNDLE="+req.ExpectedBundleDigest,
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, statErr := os.Stat(ready); statErr == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			t.Fatal("helper did not reach process cut")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if waitErr := cmd.Wait(); waitErr == nil {
		t.Fatal("helper was not killed")
	}
}

func TestImportSIGKILLHelper(t *testing.T) {
	if os.Getenv("PRUFYX_KNOWLEDGE_KILL_HELPER") != "1" {
		return
	}
	req := ImportRequest{
		PackagePath:          os.Getenv("PRUFYX_KNOWLEDGE_PACKAGE"),
		StoreRoot:            os.Getenv("PRUFYX_KNOWLEDGE_STORE"),
		BootstrapRootPath:    os.Getenv("PRUFYX_KNOWLEDGE_ROOT"),
		BootstrapRootDigest:  os.Getenv("PRUFYX_KNOWLEDGE_ROOT_DIGEST"),
		ExpectedRevision:     os.Getenv("PRUFYX_KNOWLEDGE_REVISION"),
		ExpectedBundleDigest: os.Getenv("PRUFYX_KNOWLEDGE_BUNDLE"),
	}
	stage := os.Getenv("PRUFYX_KNOWLEDGE_KILL_STAGE")
	hook := func(got string, _ *storeFS) error {
		if got != stage {
			return nil
		}
		if err := os.WriteFile(os.Getenv("PRUFYX_KNOWLEDGE_KILL_READY"), []byte("ready\n"), 0o600); err != nil {
			return err
		}
		select {}
	}
	_, err := importWithRefTime(req, journalAdmission, time.Time{}, nil, hook)
	t.Fatalf("helper returned instead of waiting for kill: %v", err)
}

func TestBootstrapRejectsArbitraryNonemptyOrCorruptRecoveryState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []string{"trust", "clock", "pending"} {
		t.Run(corrupt, func(t *testing.T) {
			dir := t.TempDir()
			storeRoot := filepath.Join(dir, "store")
			if err := os.Mkdir(storeRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			switch corrupt {
			case "trust":
				if err := os.Mkdir(filepath.Join(storeRoot, "trust"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "clock":
				if err := os.WriteFile(filepath.Join(storeRoot, "clock-floor.json"), []byte("bad\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(filepath.Join(storeRoot, "import-pending.json"), []byte("bad\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			req := ImportRequest{PackagePath: writeJournalFile(t, dir, "revision.tar", artifacts.Revision1), StoreRoot: storeRoot, BootstrapRootPath: writeJournalFile(t, dir, "root.json", artifacts.Root), BootstrapRootDigest: manifest.BootstrapRoot.Digest}
			if _, err := importAt(req, journalAdmission, now); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("corrupt %s allowed bootstrap: %v", corrupt, err)
			}
		})
	}
}

func TestImportRejectsMalformedExistingSelectionBeforeTransaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	storeRoot := filepath.Join(dir, "store")
	req := ImportRequest{PackagePath: writeJournalFile(t, dir, "revision-1.tar", artifacts.Revision1), StoreRoot: storeRoot, BootstrapRootPath: writeJournalFile(t, dir, "root.json", artifacts.Root), BootstrapRootDigest: manifest.BootstrapRoot.Digest}
	if _, err = importAt(req, journalAdmission, now); err != nil {
		t.Fatal(err)
	}
	invalid := []byte(`{"apiVersion":"wrong","revision":"1","bundleDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","trustReceiptDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","trustStateDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}` + "\n")
	if err = os.WriteFile(filepath.Join(storeRoot, "selection.json"), invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = importAt(ImportRequest{PackagePath: writeJournalFile(t, dir, "revision-2.tar", artifacts.Revision2), StoreRoot: storeRoot}, journalAdmission, now); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("malformed selection overwritten: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(storeRoot, "import-pending.json")); !os.IsNotExist(statErr) {
		t.Fatalf("transaction started over corrupt selection: %v", statErr)
	}
}

func TestPendingClearFailureReturnsDurableRecoveryReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	req := ImportRequest{PackagePath: writeJournalFile(t, dir, "revision.tar", artifacts.Revision1), StoreRoot: filepath.Join(dir, "store"), BootstrapRootPath: writeJournalFile(t, dir, "root.json", artifacts.Root), BootstrapRootDigest: manifest.BootstrapRoot.Digest}
	hook := func(stage string, store *storeFS) error {
		if stage != "before-pending-clear" {
			return nil
		}
		if err := store.remove("import-pending.json"); err != nil {
			return err
		}
		dir, err := store.openDir(".", false)
		if err != nil {
			return err
		}
		defer dir.Close()
		return fdMkdir(dir, "import-pending.json", 0o700)
	}
	receipt, err := importWithRefTime(req, journalAdmission, now, &now, hook)
	if !errors.Is(err, ErrRecoveryRequired) || receipt.APIVersion != "prufyx.io/knowledge-import-receipt/v1" || receipt.Status != "REJECTED" || !receipt.TrustStateAdvanced || !receipt.SelectionChanged || receipt.TrustStateDigest == "" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
}

func TestCompletedRetryClearFailureReturnsDurableRecoveryReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifacts, err := knowledgefixture.Generate(now)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err = json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	req := ImportRequest{PackagePath: writeJournalFile(t, dir, "revision.tar", artifacts.Revision1), StoreRoot: filepath.Join(dir, "store"), BootstrapRootPath: writeJournalFile(t, dir, "root.json", artifacts.Root), BootstrapRootDigest: manifest.BootstrapRoot.Digest}
	cutAfterSelection := func(stage string, _ *storeFS) error {
		if stage == "selection-published" {
			return errSimulatedProcessCut
		}
		return nil
	}
	if _, err = importWithRefTime(req, journalAdmission, now, &now, cutAfterSelection); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("initial cut error=%v", err)
	}
	breakClear := func(stage string, store *storeFS) error {
		if stage != "before-completed-recovery-clear" {
			return nil
		}
		if err := store.remove("import-pending.json"); err != nil {
			return err
		}
		root, err := store.openDir(".", false)
		if err != nil {
			return err
		}
		defer root.Close()
		return fdMkdir(root, "import-pending.json", 0o700)
	}
	receipt, retryErr := importWithRefTime(req, journalAdmission, now, &now, breakClear)
	if !errors.Is(retryErr, ErrRecoveryRequired) || receipt.APIVersion != "prufyx.io/knowledge-import-receipt/v1" || receipt.Status != "REJECTED" || !receipt.TrustStateAdvanced || !receipt.SelectionChanged || receipt.TrustStateDigest == "" {
		t.Fatalf("receipt=%#v error=%v", receipt, retryErr)
	}
}

func journalAdmission(raw []byte) (Admission, error) {
	var header struct {
		Revision string `json:"revision"`
		Purpose  string `json:"purpose"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Admission{}, err
	}
	return Admission{Revision: header.Revision, Purpose: header.Purpose, EngineCapabilityDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HasRule: true, RuleDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", EvidenceExpiresAt: "2030-01-01T00:00:00Z"}, nil
}

func writeJournalFile(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
