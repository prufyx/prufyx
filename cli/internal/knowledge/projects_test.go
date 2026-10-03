// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type projectsFixture struct {
	repo    *knowledgefixture.ProjectsRepository
	dir     string
	store   string
	root    string
	version int64
}

func newProjectsFixture(t *testing.T) *projectsFixture {
	t.Helper()
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	dir := t.TempDir()
	return &projectsFixture{repo: repo, dir: dir, store: filepath.Join(dir, "projects-store"), root: writeConstraintsFixtureFile(t, dir, "root.json", repo.Root)}
}

// projectsTargets builds the embedded pack as index plus project targets,
// keyed by TUF target path.
func projectsTargets(t *testing.T, revision string, projectRevisions map[string]string) map[string][]byte {
	t.Helper()
	index, projects, err := cncfcheck.BuildEmbeddedExternalTargets(revision, projectRevisions)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string][]byte{index.Path: index.Bytes}
	for _, project := range projects {
		targets[project.Path] = project.Bytes
	}
	return targets
}

func (f *projectsFixture) write(t *testing.T, p knowledgefixture.ProjectsPackage) string {
	t.Helper()
	f.version++
	p.Version = f.version
	raw, err := f.repo.Package(p)
	if err != nil {
		t.Fatal(err)
	}
	return writeConstraintsFixtureFile(t, f.dir, "package-"+strconv.FormatInt(f.version, 10)+".tar", raw)
}

func (f *projectsFixture) importPackage(packagePath string) (ImportReceipt, error) {
	req := ImportRequest{PackagePath: packagePath, StoreRoot: f.store}
	if _, err := loadSelectionAt(f.store); err != nil {
		req.BootstrapRootPath, req.BootstrapRootDigest = f.root, f.repo.RootDigest
	}
	return ImportConstraintsProjects(req)
}

func loadSelectionAt(storeRoot string) (selectionPointer, error) {
	store, err := ensureStoreRoot(storeRoot)
	if err != nil {
		return selectionPointer{}, err
	}
	defer store.Close()
	return loadSelection(store)
}

// firstProjects returns two project target paths in index order.
func firstProjects(targets map[string][]byte) (string, string) {
	var paths []string
	for name := range targets {
		if name != ConstraintsProjectsIndexTargetPath {
			paths = append(paths, name)
		}
	}
	if len(paths) < 2 {
		return "", ""
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if paths[j] < paths[i] {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}
	return paths[0], paths[1]
}

func projectOf(t *testing.T, targetPath string) string {
	t.Helper()
	project, ok := cncfcheck.ProjectFromTargetPath(targetPath)
	if !ok {
		t.Fatalf("not a project target: %s", targetPath)
	}
	return project
}

func assertSelectionKept(t *testing.T, store string, want selectionPointer, receipt ImportReceipt) {
	t.Helper()
	got, err := loadSelectionAt(store)
	if err != nil || got != want || receipt.SelectionChanged {
		t.Fatalf("selection changed after rejection: got=%+v want=%+v receipt=%+v err=%v", got, want, receipt, err)
	}
}

func TestConstraintsProjectsHappyPathLazyOpenAndUpgrade(t *testing.T) {
	f := newProjectsFixture(t)
	targets := projectsTargets(t, "5", nil)
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: targets}))
	if err != nil || receipt.Status != "IMPORTED" || receipt.TrustReceipt.TargetPath != ConstraintsProjectsIndexTargetPath || receipt.TrustReceipt.KnowledgeRevision != "5" || len(receipt.ProjectTargets) != len(targets)-1 {
		t.Fatalf("import receipt=%+v err=%v", receipt, err)
	}
	status, err := InspectConstraintsProjects(f.store)
	if err != nil || status.State != "READY" || status.SelectedRevision != "5" || !status.CurrentEligible {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	first, second := firstProjects(targets)
	opened, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{projectOf(t, first)})
	if err != nil || !opened.Valid() || !opened.PerProject() || opened.TrustReceipt().TargetPath != ConstraintsProjectsIndexTargetPath {
		t.Fatalf("open=%+v err=%v", opened, err)
	}
	target, ok := opened.ProjectTarget(projectOf(t, first))
	if !ok || !bytes.Equal(target.Bytes(), targets[first]) || target.Revision != "5" || target.Path != first {
		t.Fatalf("project target=%+v ok=%t", target, ok)
	}
	if _, ok := opened.ProjectTarget(projectOf(t, second)); ok {
		t.Fatal("a project that was not requested was loaded")
	}
	absent, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{"visual-studio-code-kubernetes-tools"})
	if err != nil || !absent.Valid() {
		t.Fatalf("open with a project outside the index: err=%v", err)
	}
	if _, ok := absent.ProjectTarget("visual-studio-code-kubernetes-tools"); ok {
		t.Fatal("a project outside the index produced a target")
	}
	if _, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{"../etc"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid project name accepted: %v", err)
	}

	// Revision 6 changes only the second project; the first keeps revision 5.
	upgraded := projectsTargets(t, "6", map[string]string{projectOf(t, first): "5"})
	if !bytes.Equal(upgraded[first], targets[first]) || bytes.Equal(upgraded[second], targets[second]) {
		t.Fatal("unexpected upgrade fixture")
	}
	receipt, err = f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: upgraded}))
	if err != nil || !receipt.SelectionChanged || receipt.TrustReceipt.KnowledgeRevision != "6" {
		t.Fatalf("upgrade receipt=%+v err=%v", receipt, err)
	}
	opened, err = OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{projectOf(t, second)})
	if err != nil {
		t.Fatal(err)
	}
	if target, ok := opened.ProjectTarget(projectOf(t, second)); !ok || target.Revision != "6" {
		t.Fatalf("upgraded project=%+v ok=%t", target, ok)
	}
	verifiedAt, err := time.Parse(time.RFC3339, receipt.TrustReceipt.VerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := OpenHistoricalCNCF(SelectionRequest{StoreRoot: f.store, ExpectedRevision: "6", ExpectedBundleDigest: receipt.TrustReceipt.TargetDigest, ExpectedTrustReceiptDigest: receipt.TrustReceiptDigest}, verifiedAt, []string{projectOf(t, first)})
	if err != nil || historical.Mode() != SelectionHistorical {
		t.Fatalf("historical open err=%v", err)
	}
	if target, ok := historical.ProjectTarget(projectOf(t, first)); !ok || target.Revision != "5" {
		t.Fatalf("historical project=%+v ok=%t", target, ok)
	}
}

func TestConstraintsProjectsVerifyListsEveryProject(t *testing.T) {
	f := newProjectsFixture(t)
	targets := projectsTargets(t, "3", nil)
	receipt, err := VerifyConstraintsProjects(VerifyRequest{PackagePath: f.write(t, knowledgefixture.ProjectsPackage{Targets: targets}), BootstrapRootPath: f.root, BootstrapRootDigest: f.repo.RootDigest})
	if err != nil || receipt.Profile != "cncf-projects" || len(receipt.ProjectTargets) != len(targets)-1 || receipt.TargetPath != ConstraintsProjectsIndexTargetPath {
		t.Fatalf("verify receipt=%+v err=%v", receipt, err)
	}
	for _, project := range receipt.ProjectTargets {
		if project.Length < 1 || project.Length > cncfcheck.MaxExternalTargetBytes || digestBytes(targets[project.TargetPath]) != project.Digest {
			t.Fatalf("project receipt %+v", project)
		}
	}
}

func TestConstraintsProjectsRejectTamperedMissingExtraAndMismatchedTargets(t *testing.T) {
	base := projectsTargets(t, "5", nil)
	first, second := firstProjects(base)
	otherIndex, otherProjects, err := cncfcheck.BuildEmbeddedExternalTargets("5", map[string]string{projectOf(t, first): "4"})
	if err != nil {
		t.Fatal(err)
	}
	var olderFirst []byte
	for _, project := range otherProjects {
		if project.Path == first {
			olderFirst = project.Bytes
		}
	}
	without := func(name string) map[string][]byte {
		copy := map[string][]byte{}
		for k, v := range base {
			if k != name {
				copy[k] = v
			}
		}
		return copy
	}
	withIndex := func(index []byte) map[string][]byte {
		copy := without(ConstraintsProjectsIndexTargetPath)
		copy[ConstraintsProjectsIndexTargetPath] = index
		return copy
	}
	extraProject := "visual-studio-code-kubernetes-tools"
	extraTargets := without("")
	extraTargets[cncfcheck.ProjectTargetPath(extraProject)] = base[first]
	cases := []struct {
		name string
		pkg  knowledgefixture.ProjectsPackage
		want string
	}{
		{"tampered project bytes", knowledgefixture.ProjectsPackage{Targets: base, Replace: map[string][]byte{first: flipByte(base[first])}}, "does not match its signed length and hash"},
		{"tampered index bytes", knowledgefixture.ProjectsPackage{Targets: base, Replace: map[string][]byte{ConstraintsProjectsIndexTargetPath: bytes.Replace(base[ConstraintsProjectsIndexTargetPath], []byte(`"revision":"5"`), []byte(`"revision":"9"`), 1)}}, "TUF verification"},
		{"project member missing from package", knowledgefixture.ProjectsPackage{Targets: base, Omit: []string{second}}, "does not match its signed length and hash"},
		{"project listed in index but not signed", knowledgefixture.ProjectsPackage{Targets: without(second)}, "listed in the index but not signed"},
		{"project signed but not in index", knowledgefixture.ProjectsPackage{Targets: extraTargets}, "signed but not listed in the index"},
		{"unsigned extra package member", knowledgefixture.ProjectsPackage{Targets: base, Extra: map[string][]byte{knowledgefixture.ProjectsPackageMember(cncfcheck.ProjectTargetPath(extraProject), base[first]): base[first]}}, "unused package member"},
		{"index digest differs from signed target", knowledgefixture.ProjectsPackage{Targets: withIndex(otherIndex.Bytes)}, "differs between index and targets metadata"},
		{"signed project differs from index", knowledgefixture.ProjectsPackage{Targets: func() map[string][]byte { c := without(first); c[first] = olderFirst; return c }()}, "differs between index and targets metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newProjectsFixture(t)
			good, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
			if err != nil {
				t.Fatal(err)
			}
			kept, err := loadSelectionAt(f.store)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := f.importPackage(f.write(t, tc.pkg))
			if err == nil || !(errors.Is(err, ErrIntegrity) || errors.Is(err, ErrInvalid)) {
				t.Fatalf("accepted: receipt=%+v err=%v", receipt, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rejected for another reason: %v", err)
			}
			assertSelectionKept(t, f.store, kept, receipt)
			// The last good revision stays available for exact replay, and a
			// later valid package recovers current use.
			verifiedAt, _ := time.Parse(time.RFC3339, good.TrustReceipt.VerifiedAt)
			if _, err := OpenHistoricalCNCF(SelectionRequest{StoreRoot: f.store, ExpectedRevision: "5", ExpectedBundleDigest: good.TrustReceipt.TargetDigest, ExpectedTrustReceiptDigest: good.TrustReceiptDigest}, verifiedAt, []string{projectOf(t, first)}); err != nil {
				t.Fatalf("last good revision unavailable: %v", err)
			}
			recovered, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "6", nil)}))
			if err != nil || recovered.TrustReceipt.KnowledgeRevision != "6" {
				t.Fatalf("recovery receipt=%+v err=%v", recovered, err)
			}
		})
	}
}

func TestConstraintsProjectsRollbackOfOneProjectAndIndex(t *testing.T) {
	f := newProjectsFixture(t)
	base := projectsTargets(t, "5", nil)
	first, _ := firstProjects(base)
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base})); err != nil {
		t.Fatal(err)
	}
	kept, err := loadSelectionAt(f.store)
	if err != nil {
		t.Fatal(err)
	}
	// The index advances to 6 but one project goes back to revision 4.
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "6", map[string]string{projectOf(t, first): "4"})}))
	if !errors.Is(err, ErrRollback) || !strings.Contains(err.Error(), first) {
		t.Fatalf("one-project rollback accepted: receipt=%+v err=%v", receipt, err)
	}
	assertSelectionKept(t, f.store, kept, receipt)
	// The index itself goes back to revision 4.
	receipt, err = f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "4", nil)}))
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("index rollback accepted: receipt=%+v err=%v", receipt, err)
	}
	assertSelectionKept(t, f.store, kept, receipt)
	// A project dropped from a later index keeps its floor.
	dropped := projectsTargets(t, "7", nil)
	delete(dropped, first)
	index := rebuildIndexWithout(t, dropped[ConstraintsProjectsIndexTargetPath], projectOf(t, first))
	dropped[ConstraintsProjectsIndexTargetPath] = index
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: dropped})); err != nil {
		t.Fatalf("index without one project rejected: %v", err)
	}
	reAdded := projectsTargets(t, "8", map[string]string{projectOf(t, first): "4"})
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: reAdded})); !errors.Is(err, ErrRollback) {
		t.Fatalf("re-added project below its retained floor accepted: %v", err)
	}
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "8", nil)})); err != nil {
		t.Fatalf("valid re-add rejected: %v", err)
	}
}

func rebuildIndexWithout(t *testing.T, raw []byte, project string) []byte {
	t.Helper()
	var document struct {
		Schema                 string                         `json:"schema"`
		Revision               string                         `json:"revision"`
		Purpose                string                         `json:"purpose"`
		EngineCapabilityDigest string                         `json:"engineCapabilityDigest"`
		Projects               []cncfcheck.ExternalIndexEntry `json:"projects"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	kept := document.Projects[:0]
	for _, entry := range document.Projects {
		if entry.Project != project {
			kept = append(kept, entry)
		}
	}
	document.Projects = kept
	out, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalIndex(out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConstraintsProjectsRejectOversizeTargetBeforeStoreUse(t *testing.T) {
	f := newProjectsFixture(t)
	base := projectsTargets(t, "5", nil)
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base})); err != nil {
		t.Fatal(err)
	}
	before := snapshotConstraintsStatusFiles(t, f.store)
	oversize := map[string][]byte{}
	for k, v := range base {
		oversize[k] = v
	}
	first, _ := firstProjects(base)
	oversize[first] = bytes.Repeat([]byte(" "), cncfcheck.MaxExternalTargetBytes+1)
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: oversize})); err == nil {
		t.Fatal("oversize project target accepted")
	}
	assertStatusDurableFilesUnchanged(t, before, snapshotConstraintsStatusFiles(t, f.store))
}

// TestSplitTargetsRoleEnforcesPerTargetCap exercises the trusted-set check
// directly, below the package and metadata gates that also reject oversize
// targets.
func TestSplitTargetsRoleEnforcesPerTargetCap(t *testing.T) {
	profile := constraintsProjectsProfile()
	role := metadata.Targets(time.Now().Add(time.Hour))
	hash := metadata.Hashes{"sha256": make([]byte, sha256Size)}
	role.Signed.Targets[profile.targetPath] = &metadata.TargetFiles{Length: 10, Hashes: hash, Path: profile.targetPath}
	project := cncfcheck.ProjectTargetPath("kubernetes")
	role.Signed.Targets[project] = &metadata.TargetFiles{Length: int64(cncfcheck.MaxExternalTargetBytes), Hashes: hash, Path: project}
	if err := validateSplitTargetsRole(role, profile); err != nil {
		t.Fatalf("target at the cap rejected: %v", err)
	}
	role.Signed.Targets[project].Length = int64(cncfcheck.MaxExternalTargetBytes) + 1
	if err := validateSplitTargetsRole(role, profile); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("target over the cap accepted: %v", err)
	}
	role.Signed.Targets[project].Length = 10
	role.Signed.Targets["knowledge/constraints.v1.json"] = &metadata.TargetFiles{Length: 10, Hashes: hash}
	if err := validateSplitTargetsRole(role, profile); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("foreign target accepted: %v", err)
	}
}

func TestConstraintsLayoutsFailClosedAcrossProfiles(t *testing.T) {
	// A single-target store keeps working with the new client.
	single := makeConstraintsFixture(t)
	if _, err := ImportConstraints(constraintsInitialRequest(single)); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: single.store}, []string{"kubernetes"})
	if err != nil || !opened.Valid() || opened.PerProject() || opened.TrustReceipt().TargetPath != ConstraintsTargetPath {
		t.Fatalf("single-target store not readable: %+v err=%v", opened, err)
	}
	before := snapshotConstraintsStatusFiles(t, single.store)

	f := newProjectsFixture(t)
	split := f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "5", nil)})
	// The single-target profile refuses a per-project package before it
	// opens the store, with a layout error.
	_, err = ImportConstraints(ImportRequest{PackagePath: split, StoreRoot: single.store})
	if !errors.Is(err, ErrLayout) || !errors.Is(err, ErrInvalid) {
		t.Fatalf("single-target profile accepted per-project package: %v", err)
	}
	assertStatusDurableFilesUnchanged(t, before, snapshotConstraintsStatusFiles(t, single.store))
	if status, err := InspectConstraints(single.store); err != nil || status.State != "READY" {
		t.Fatalf("single-target store disturbed: %+v err=%v", status, err)
	}
	// The per-project profile refuses the single-target store.
	if _, err := ImportConstraintsProjects(ImportRequest{PackagePath: split, StoreRoot: single.store}); !errors.Is(err, ErrLayout) || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("per-project profile used a single-target store: %v", err)
	}
	assertStatusDurableFilesUnchanged(t, before, snapshotConstraintsStatusFiles(t, single.store))
	// ... and a single-target package.
	if _, err := ImportConstraintsProjects(ImportRequest{PackagePath: single.p1, StoreRoot: filepath.Join(f.dir, "fresh"), BootstrapRootPath: single.root, BootstrapRootDigest: single.manifest.BootstrapRoot.Digest}); !errors.Is(err, ErrLayout) {
		t.Fatalf("per-project profile accepted single-target package: %v", err)
	}
	// A per-project store is refused by the single-target profile.
	if _, err := f.importPackage(split); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSelectedConstraints(SelectionRequest{StoreRoot: f.store}); !errors.Is(err, ErrLayout) {
		t.Fatalf("single-target profile opened per-project store: %v", err)
	}
}

func flipByte(raw []byte) []byte {
	out := append([]byte(nil), raw...)
	out[len(out)/2] ^= 0x01
	return out
}

func TestConstraintsProjectsStoredProjectTamperFailsClosed(t *testing.T) {
	f := newProjectsFixture(t)
	targets := projectsTargets(t, "5", nil)
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: targets}))
	if err != nil {
		t.Fatal(err)
	}
	first, second := firstProjects(targets)
	stored := filepath.Join(f.store, filepath.FromSlash(receipt.AdmissionPath), "projects", projectOf(t, first)+".json")
	if err := os.WriteFile(stored, flipByte(targets[first]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{projectOf(t, first)}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered stored project opened: %v", err)
	}
	// Lazy opening of another project does not read the tampered file.
	if _, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{projectOf(t, second)}); err != nil {
		t.Fatalf("untouched project unavailable: %v", err)
	}
	if status, err := InspectConstraintsProjects(f.store); err != nil || status.State != "INTEGRITY_FAILURE" {
		t.Fatalf("status after tamper=%+v err=%v", status, err)
	}
}
