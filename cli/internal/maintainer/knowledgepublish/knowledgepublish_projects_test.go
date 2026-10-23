// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// embeddedProjectTargets builds the per-project layout of the embedded pack.
func embeddedProjectTargets(t *testing.T, revision string) ([]byte, []Target) {
	t.Helper()
	index, built, err := cncfcheck.BuildEmbeddedExternalTargets(revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	projects := make([]Target, 0, len(built))
	for _, target := range built {
		projects = append(projects, Target{Path: target.Path, Raw: target.Bytes})
	}
	return index.Bytes, projects
}

// signProjectRoles runs prepare, sign and finalize for the three roles of a
// per-project publication under root, returning the finalized metadata.
func signProjectRoles(t *testing.T, root []byte, rootDigest string, keys map[string]testKey, index []byte, projects []Target) (targets, snapshot, timestamp []byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	targetsPrep, err := PrepareTargets(TargetsOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: projects, Version: 7, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	assertPreparation(t, targetsPrep, metadata.TARGETS, rootDigest, digest(index), 7)
	targets = finalizeTestRole(t, root, rootDigest, targetsPrep, keys[metadata.TARGETS])
	snapshotPrep, err := PrepareSnapshot(SnapshotOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: projects, Targets: targets, Version: 8, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot = finalizeTestRole(t, root, rootDigest, snapshotPrep, keys[metadata.SNAPSHOT])
	timestampPrep, err := PrepareTimestamp(TimestampOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: projects, Targets: targets, Snapshot: snapshot, Version: 9, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	timestamp = finalizeTestRole(t, root, rootDigest, timestampPrep, keys[metadata.TIMESTAMP])
	return targets, snapshot, timestamp
}

func signedProjectOptions(t *testing.T, revision string) FinalizePackageOptions {
	t.Helper()
	index, projects := embeddedProjectTargets(t, revision)
	root, rootDigest, keys := testRoot(t, time.Now().UTC().Truncate(time.Second))
	targets, snapshot, timestamp := signProjectRoles(t, root, rootDigest, keys, index, projects)
	return FinalizePackageOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: projects, Targets: targets, Snapshot: snapshot, Timestamp: timestamp}
}

func TestPerProjectPublication_SignPackageFinalizeRoundTrip(t *testing.T) {
	opts := signedProjectOptions(t, "61")
	if len(opts.Projects) < 2 {
		t.Fatalf("embedded pack split into %d projects", len(opts.Projects))
	}
	// The one targets role signs the index and every project target.
	role, err := parseTargets(opts.Targets, true)
	if err != nil || len(role.Signed.Targets) != len(opts.Projects)+1 || role.Signed.Targets[cncfcheck.ExternalIndexTargetPath] == nil {
		t.Fatalf("targets role: %d targets, err=%v", len(role.Signed.Targets), err)
	}
	packageRaw, receipt, err := FinalizePackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	v := receipt.Verification
	if receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.Profile != "cncf-projects" || receipt.KnowledgeRevision != "61" || receipt.TargetDigest != digest(opts.Target) || receipt.PackageDigest != digest(packageRaw) || receipt.NetworkUsed || receipt.KeysHandled || v.Profile != "cncf-projects" || v.TargetPath != cncfcheck.ExternalIndexTargetPath || len(v.ProjectTargets) != len(opts.Projects) {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	again, _, err := FinalizePackage(opts)
	if err != nil || !bytes.Equal(packageRaw, again) {
		t.Fatalf("package is not deterministic: err=%v", err)
	}
	// An independent consumer verification of the written package.
	dir := t.TempDir()
	packagePath, rootPath := filepath.Join(dir, "package.tar"), filepath.Join(dir, "root.json")
	if err := os.WriteFile(packagePath, packageRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, opts.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := knowledge.VerifyConstraintsProjects(knowledge.VerifyRequest{PackagePath: packagePath, BootstrapRootPath: rootPath, BootstrapRootDigest: opts.RootDigest, ExpectedPackageDigest: digest(packageRaw), ExpectedRevision: "61", ExpectedBundleDigest: digest(opts.Target)})
	if err != nil || got.Status != "VERIFIED" || len(got.ProjectTargets) != len(opts.Projects) {
		t.Fatalf("consumer verification: %+v err=%v", got, err)
	}
	// The single-target consumer must refuse the same package.
	if _, err := knowledge.VerifyConstraints(knowledge.VerifyRequest{PackagePath: packagePath, BootstrapRootPath: rootPath, BootstrapRootDigest: opts.RootDigest}); err == nil {
		t.Fatal("single-target consumer accepted a per-project package")
	}
}

func TestPerProjectPublication_RefusesInconsistentTargetSets(t *testing.T) {
	index, projects := embeddedProjectTargets(t, "62")
	root, rootDigest, keys := testRoot(t, time.Now().UTC().Truncate(time.Second))
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	clone := func() []Target { return append([]Target(nil), projects...) }
	mutated := func() []Target {
		out := clone()
		out[0] = Target{Path: out[0].Path, Raw: append(append([]byte(nil), out[0].Raw...), ' ')}
		return out
	}
	swapped := func() []Target {
		out := clone()
		out[0], out[1] = Target{Path: out[0].Path, Raw: out[1].Raw}, Target{Path: out[1].Path, Raw: out[0].Raw}
		return out
	}
	cases := map[string][]Target{
		"missing project": clone()[1:],
		"extra project":   append(clone(), Target{Path: "knowledge/cncf/projects/not-listed.v1.json", Raw: projects[0].Raw}),
		"duplicate path":  append(clone()[1:], clone()[1]),
		"mutated bytes":   mutated(),
		"swapped bytes":   swapped(),
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PrepareTargets(TargetsOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: set, Version: 1, Expires: expires}); !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// A signed role over the right set refuses a different set later in the chain.
	targets, _, _ := signProjectRoles(t, root, rootDigest, keys, index, projects)
	if _, err := PrepareSnapshot(SnapshotOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: mutated(), Targets: targets, Version: 8, Expires: expires}); !errors.Is(err, ErrRejected) {
		t.Fatalf("snapshot over mutated project accepted: %v", err)
	}
	// The single-target options never accept the index as a bundle.
	if _, err := PrepareTargets(TargetsOptions{Root: root, RootDigest: rootDigest, Target: index, Version: 1, Expires: expires}); !errors.Is(err, ErrRejected) {
		t.Fatalf("index accepted as a single bundle: %v", err)
	}
}

func TestPerProjectPublication_ReleasePlanIsRefused(t *testing.T) {
	opts := signedProjectOptions(t, "63")
	packageRaw, planRaw, _, err := FinalizePackageWithReleasePlan(opts, "https://metadata.example.test/cncf-projects-63.tar")
	if !errors.Is(err, ErrRejected) || len(packageRaw) != 0 || len(planRaw) != 0 {
		t.Fatalf("release plan for cncf-projects: package=%d plan=%d err=%v", len(packageRaw), len(planRaw), err)
	}
}

func TestPerProjectPublication_FinalizeRotatedPackage(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	index, projects := embeddedProjectTargets(t, "64")
	initial, initialDigest, oldKeys := testRoot(t, now)
	template, templateDigest, newKeys := testRoot(t, now)
	transition, err := PrepareRootTransition(RootTransitionOptions{TrustedRoot: initial, TrustedRootDigest: initialDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest})
	if err != nil {
		t.Fatal(err)
	}
	successor, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: RootTransitionOptions{TrustedRoot: initial, TrustedRootDigest: initialDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest}, UnsignedMetadata: transition.UnsignedMetadata, Request: transition.Request, Signatures: [][]byte{rootContribution(t, transition, oldKeys[metadata.ROOT]), rootContribution(t, transition, newKeys[metadata.ROOT])}})
	if err != nil {
		t.Fatal(err)
	}
	successorDigest := digest(successor)
	targets, snapshot, timestamp := signProjectRoles(t, successor, successorDigest, newKeys, index, projects)
	opts := RotatedFinalizePackageOptions{InitialRoot: initial, InitialRootDigest: initialDigest, SuccessorRoots: [][]byte{successor}, Target: index, Projects: projects, Targets: targets, Snapshot: snapshot, Timestamp: timestamp}
	packageRaw, receipt, err := FinalizeRotatedPackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(packageRaw) == 0 || receipt.Profile != "cncf-projects" || receipt.Verification.Profile != "cncf-projects" || len(receipt.Verification.RootHistory) != 2 || len(receipt.Verification.ProjectTargets) != len(projects) {
		t.Fatalf("rotated per-project receipt: %+v", receipt)
	}
	// Dropping the projects must not fall back to a single-target package.
	opts.Projects = nil
	if _, _, err := FinalizeRotatedPackage(opts); !errors.Is(err, ErrRejected) {
		t.Fatalf("index accepted as a single bundle: %v", err)
	}
}

func TestValidateTargetsShape_AcceptsSingleOrPerProjectOnly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	hash := metadata.HexBytes(make([]byte, 32))
	build := func(paths ...string) *metadata.Metadata[metadata.TargetsType] {
		role := metadata.Targets(now.Add(time.Hour))
		role.Signed.Version = 1
		for _, path := range paths {
			role.Signed.Targets[path] = &metadata.TargetFiles{Length: 1, Hashes: metadata.Hashes{"sha256": hash}}
		}
		return role
	}
	valid := [][]string{
		{knowledge.ConstraintsTargetPath},
		{cncfcheck.ExternalIndexTargetPath, cncfcheck.ProjectTargetPath("alpha")},
	}
	for _, paths := range valid {
		if err := validateTargetsShape(build(paths...)); err != nil {
			t.Fatalf("%v rejected: %v", paths, err)
		}
	}
	invalid := [][]string{
		{},
		{cncfcheck.ExternalIndexTargetPath}, // an index without projects
		{knowledge.ConstraintsTargetPath, cncfcheck.ExternalIndexTargetPath},
		{cncfcheck.ExternalIndexTargetPath, "knowledge/cncf/other.v1.json"},
		{cncfcheck.ProjectTargetPath("alpha"), cncfcheck.ProjectTargetPath("beta")}, // no index
		{knowledge.ConstraintsTargetPath, cncfcheck.ProjectTargetPath("alpha")},
	}
	for _, paths := range invalid {
		if err := validateTargetsShape(build(paths...)); !errors.Is(err, ErrRejected) {
			t.Fatalf("%v accepted: %v", paths, err)
		}
	}
}

// A targets role that is validly signed but lists a different set than the
// one being chained (a dropped or an extra project) is refused when the
// snapshot is prepared.
func TestPerProjectPublication_SignedRoleOverAnotherSetIsRefused(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	index, projects := embeddedProjectTargets(t, "65")
	root, rootDigest, keys := testRoot(t, now)
	for name, edit := range map[string]func(map[string]*metadata.TargetFiles){
		"dropped project": func(all map[string]*metadata.TargetFiles) { delete(all, projects[0].Path) },
		"extra project": func(all map[string]*metadata.TargetFiles) {
			info := *all[projects[0].Path]
			all["knowledge/cncf/projects/not-listed.v1.json"] = &info
		},
	} {
		t.Run(name, func(t *testing.T) {
			prep, err := PrepareTargets(TargetsOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: projects, Version: 7, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
			if err != nil {
				t.Fatal(err)
			}
			role, err := parseTargets(prep.UnsignedMetadata, false)
			if err != nil {
				t.Fatal(err)
			}
			edit(role.Signed.Targets)
			unsigned, err := role.ToBytes(false)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := cjson.EncodeCanonical(role.Signed)
			if err != nil {
				t.Fatal(err)
			}
			other := Preparation{Role: metadata.TARGETS, UnsignedMetadata: unsigned, Payload: payload}
			signed, err := FinalizeRole(root, rootDigest, metadata.TARGETS, unsigned, signatureEnvelope(t, other, keys[metadata.TARGETS]))
			if err != nil {
				t.Fatalf("a per-project role over another set is still a valid role: %v", err)
			}
			expires := now.Add(48 * time.Hour).Format(time.RFC3339)
			if _, err := PrepareSnapshot(SnapshotOptions{Root: root, RootDigest: rootDigest, Target: index, Projects: projects, Targets: signed, Version: 8, Expires: expires}); !errors.Is(err, ErrRejected) {
				t.Fatalf("snapshot over a role with another set accepted: %v", err)
			}
		})
	}
}
