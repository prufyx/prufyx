// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

// The client-floor fixture writer. For every client floor this tree knows it
// signs, with throwaway keys, one package that carries the floor's feature and
// names the floor as its minimum client, plus one control package without any
// floor feature, all at this tree's engine capability. CI runs it inside the
// tree under test (the head, and the pinned ref), and the admit tests give the
// packages to the client built from the same tree.
//
// The writer test name, this package path, the environment variable, the
// manifest schema and the floor names are frozen once a pinned tag holds them.

import (
	"bytes"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	floorFixtureDirEnv  = "PRUFYX_FLOOR_FIXTURE_DIR"
	floorManifestSchema = "prufyx.io/client-floor-fixtures/v1"
	floorManifestName   = "manifest.json"
	floorControlPackage = "control.tar"
	floorRootName       = "root.json"

	floorProviderFacts = "ProviderFactsMinClientVersion"
	floorPinnedLease   = "PinnedLeaseMinClientVersion"
	floorListedFamily  = "ListedFamilyFloor"
	floorOptInLevel    = "BoundaryCoveredFloor"

	// The raw values the carry assertion looks for. They are written out here
	// on purpose: they are what a released client reads.
	floorListedFamilyToken = "changelog.listed_entries"
	floorOptInSchemaName   = "prufyx.io/cncf-source-rule-pack/v1alpha16"
	floorPinnedLeaseToken  = "pinned"
)

type clientFloorFeature struct{ name, version string }

// floorFeatures are the client floors, in version order.
func floorFeatures() []clientFloorFeature {
	return []clientFloorFeature{
		{floorProviderFacts, cncfcheck.ProviderFactsMinClientVersion},
		{floorPinnedLease, cncfcheck.PinnedLeaseMinClientVersion},
		{floorListedFamily, cncfcheck.ListedFamilyFloor},
		{floorOptInLevel, cncfcheck.BoundaryCoveredFloor},
	}
}

type floorManifest struct {
	Schema           string                 `json:"schema"`
	CapabilityDigest string                 `json:"capabilityDigest"`
	Root             string                 `json:"root"`
	RootDigest       string                 `json:"rootDigest"`
	Revision         string                 `json:"revision"`
	Control          string                 `json:"control"`
	Features         []floorManifestFeature `json:"features"`
}

type floorManifestFeature struct {
	Floor   string `json:"floor"`
	Package string `json:"package"`
}

func floorTime(at time.Time) string { return at.UTC().Truncate(time.Second).Format(time.RFC3339) }

// syntheticFloorPack is a small rule pack for one fixture. Its rules are the
// first pinnable rule and the first ranged rule of the embedded pack, with
// every evidence date taken from now, so it never expires with the wall clock.
// feature "" is the control, without any floor feature.
func syntheticFloorPack(t *testing.T, now time.Time, feature string) []byte {
	t.Helper()
	embedded, err := cncfcheck.EmbeddedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(embedded, &pack); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"lineAttestations", "pathPolicies", "servedAPIs", "distributions"} {
		delete(pack, section)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(pack["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	reviewed := floorTime(now.Add(-24 * time.Hour))
	var chosen []map[string]any
	pinnable, ranged := -1, -1
	for _, raw := range entries {
		var entry map[string]any
		encoded, err := json.Marshal(raw)
		if err != nil || json.Unmarshal(encoded, &entry) != nil {
			t.Fatal("an embedded entry cannot be read")
		}
		rule, ok1 := entry["rule"].(map[string]any)
		evidence, ok2 := rule["evidence"].(map[string]any)
		if !ok1 || !ok2 {
			t.Fatal("an embedded entry has no rule evidence")
		}
		if evidence["state"] != "active" || rule["severity"] != nil {
			continue
		}
		evidence["reviewedAt"] = reviewed
		evidence["validUntil"] = floorTime(now.Add(60 * 24 * time.Hour))
		if _, derived := evidence["derivedAt"]; derived {
			evidence["derivedAt"] = reviewed
		}
		switch {
		case pinnable < 0 && rule["range"] == nil && rule["operator"] == "forbid_predicate_value" && rule["condition"] != nil && floorPinEligible(t, rule):
			pinnable = len(chosen)
			chosen = append(chosen, entry)
		case ranged < 0 && rule["range"] != nil && rule["operator"] == "forbid_set_member":
			ranged = len(chosen)
			chosen = append(chosen, entry)
		}
		if pinnable >= 0 && ranged >= 0 {
			break
		}
	}
	if pinnable < 0 || ranged < 0 {
		t.Fatalf("the embedded pack has no pinnable rule (%d) or no ranged rule (%d)", pinnable, ranged)
	}
	if feature == floorPinnedLease {
		evidence := chosen[pinnable]["rule"].(map[string]any)["evidence"].(map[string]any)
		until, err := constraintengine.PinnedValidUntil(reviewed)
		if err != nil {
			t.Fatal(err)
		}
		evidence["lease"], evidence["validUntil"] = floorPinnedLeaseToken, until
	}
	if pack["entries"], err = json.Marshal(chosen); err != nil {
		t.Fatal(err)
	}
	if feature == floorListedFamily {
		attestation := lineattest.LineAttestation{
			Component: "pkg:github/prometheus/prometheus", Line: "0.51", FactFamily: lineattest.FamilyChangelogListedEntries, Completeness: lineattest.Completeness,
			RuleIDs: []string{},
			Releases: &lineattest.Releases{
				From: []lineattest.Release{{Version: "0.50.0", Commit: strings.Repeat("1", 40)}},
				To:   []lineattest.Release{{Version: "0.51.0", Commit: strings.Repeat("2", 40)}},
			},
			Evidence: lineattest.Evidence{
				Basis: constraintengine.BasisMechanical, ReviewedAt: reviewed, ValidUntil: floorTime(now.Add(60 * 24 * time.Hour)), DerivedAt: reviewed,
				Extractor: &constraintengine.Extractor{ID: "changelog.listed-entries", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("b", 64)},
				Sources:   []constraintengine.SourceEvidence{{ID: "changelog", URL: "https://github.com/prometheus/prometheus/blob/" + strings.Repeat("2", 40) + "/CHANGELOG.md", Revision: strings.Repeat("2", 40), ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
			},
		}
		if pack["lineAttestations"], err = lineattest.Marshal([]lineattest.LineAttestation{attestation}); err != nil {
			t.Fatal(err)
		}
	}
	// The pack declares the level its content requires; the opt-in level is
	// the one a pack declares itself.
	if feature == floorOptInLevel {
		pack["schema"] = json.RawMessage(strconv.Quote(floorOptInSchemaName))
	} else {
		// The embedded pack states a level its own content needs; the
		// synthetic one states the level of what is left.
		pack["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha2"`)
		if pack["schema"], err = json.Marshal(mustSchema(t, pack)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func floorPinEligible(t *testing.T, rule map[string]any) bool {
	t.Helper()
	raw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	reasons, err := constraintengine.PinnedRuleReasons(raw)
	return err == nil && len(reasons) == 0
}

// addIndexMinimum names version as the index's minimum client, as the last
// member, which keeps the index canonical. No builder names a minimum for the
// provider facts or the pinned lease, so an index that already names one is
// refused.
func addIndexMinimum(index []byte, version string) ([]byte, bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal(index, &members) != nil || len(index) < 2 || index[len(index)-1] != '}' {
		return nil, false
	}
	for name := range members {
		if strings.EqualFold(name, "minClientVersion") {
			return nil, false
		}
	}
	out := append([]byte(nil), index[:len(index)-1]...)
	return append(out, []byte(`,"minClientVersion":"`+version+`"}`)...), true
}

// floorTestAddsMinimum are the floors whose minimum no builder names.
func floorTestAddsMinimum(name string) bool {
	return name == floorProviderFacts || name == floorPinnedLease
}

// floorKeys is projectsFixture with the writer's clock: the throwaway root is
// signed again so that it expires relative to now, not to the wall clock the
// key tool reads.
func floorKeys(t *testing.T, now time.Time) Options {
	t.Helper()
	o := projectsFixture(t)
	o.Now = now.UTC().Truncate(time.Second)
	raw, err := os.ReadFile(o.Root)
	if err != nil {
		t.Fatal(err)
	}
	root, err := metadata.Root().FromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(o.Root), "root.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	private, err := knowledgesign.DecryptPrivateKey(encoded, []byte(testRootPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	root.Signed.Expires = o.Now.Add(300 * 24 * time.Hour)
	root.ClearSignatures()
	if _, err := root.Sign(signer); err != nil {
		t.Fatal(err)
	}
	if raw, err = root.ToBytes(false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.Root, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	o.RootDigest = cncfcheck.TargetDigest(raw)
	if err := knowledgesign.ValidateRoot(raw, o.RootDigest); err != nil {
		t.Fatal(err)
	}
	return o
}

// writeFloorFixtures signs the fixture packages into dir, which must not hold
// anything yet. Every date, the root expiry included, comes from now.
func writeFloorFixtures(t *testing.T, dir string, now time.Time) floorManifest {
	t.Helper()
	if !filepath.IsAbs(dir) {
		t.Fatalf("the fixture directory %q is not absolute", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if held, err := os.ReadDir(dir); err != nil || len(held) != 0 {
		t.Fatalf("the fixture directory %s must be empty: %d entries, %v", dir, len(held), err)
	}
	keys := floorKeys(t, now)
	write := func(name string, raw []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.ReadFile(keys.Root)
	if err != nil {
		t.Fatal(err)
	}
	write(floorRootName, root)
	manifest := floorManifest{Schema: floorManifestSchema, Root: floorRootName, RootDigest: keys.RootDigest, Revision: keys.Revision, Control: floorControlPackage}
	original := buildPinned
	defer func() { buildPinned = original }()
	build := func(name string, feature clientFloorFeature) {
		pack := syntheticFloorPack(t, keys.Now, feature.name)
		buildPinned = func(revision string, _ []byte, oldest string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, int, error) {
			index, targets, excluded, err := cncfcheck.BuildExternalTargetsFromPackPinned(pack, revision, oldest)
			if err == nil && floorTestAddsMinimum(feature.name) {
				edited, ok := addIndexMinimum(index.Bytes, feature.version)
				if !ok {
					t.Fatalf("%s: the builder already names a minimum client", feature.name)
				}
				index.Bytes = edited
			}
			return index, targets, excluded, err
		}
		o := keys
		o.OldestClient = feature.version
		o.OutputDir = filepath.Join(filepath.Dir(keys.OutputDir), "floor-"+strings.TrimSuffix(name, ".tar"))
		if _, err := Run(o); err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		raw, err := os.ReadFile(filepath.Join(o.OutputDir, "cncf-projects-"+o.Revision+".tar"))
		if err != nil {
			t.Fatal(err)
		}
		write(name, raw)
		index, _, err := signedMembers(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		capability, err := indexCapability(index)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.CapabilityDigest == "" {
			manifest.CapabilityDigest = capability
		} else if manifest.CapabilityDigest != capability {
			t.Fatalf("fixture %s has capability %s, the others %s", name, capability, manifest.CapabilityDigest)
		}
	}
	build(floorControlPackage, clientFloorFeature{"", ""})
	for _, feature := range floorFeatures() {
		name := feature.name + ".tar"
		build(name, feature)
		manifest.Features = append(manifest.Features, floorManifestFeature{Floor: feature.name, Package: name})
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write(floorManifestName, raw)
	return manifest
}

// TestWriteFloorFixtures writes the fixtures for CI. Without the directory
// variable it is skipped, and CI requires its pass line.
func TestWriteFloorFixtures(t *testing.T) {
	dir := os.Getenv(floorFixtureDirEnv)
	if dir == "" {
		t.Skipf("set %s to an empty directory", floorFixtureDirEnv)
	}
	manifest := writeFloorFixtures(t, dir, time.Now())
	t.Logf("capability %s, %d features", manifest.CapabilityDigest, len(manifest.Features))
}

// The written packages verify with this tree, carry exactly their own feature,
// and the control carries none.
func TestFloorFixtureWriterOutput(t *testing.T) {
	checkFloorFixtureWriter(t, time.Now().UTC().Truncate(time.Second))
}

// verifyFloorFixture verifies one written package at the clock at.
func verifyFloorFixture(set floorFixtures, path string, at time.Time) error {
	index, _, err := signedMembers(path)
	if err != nil {
		return err
	}
	_, err = knowledge.VerifyConstraintsProjects(knowledge.VerifyRequest{
		PackagePath: path, BootstrapRootPath: set.root(), BootstrapRootDigest: set.manifest.RootDigest,
		ExpectedRevision: set.manifest.Revision, ExpectedBundleDigest: cncfcheck.TargetDigest(index), Now: at,
	})
	return err
}

// checkFloorFixtureWriter runs the whole writer at the clock now and checks
// every package it wrote at that clock.
func checkFloorFixtureWriter(t *testing.T, now time.Time) floorFixtures {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fixtures")
	writeFloorFixtures(t, dir, now)
	set, err := loadFloorFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(path string) {
		t.Helper()
		if err := verifyFloorFixture(set, path, now); err != nil {
			t.Fatalf("%s does not verify: %v", path, err)
		}
	}
	verify(set.control())
	controlIndex, controlTargets, err := signedMembers(set.control())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(controlIndex, []byte("minClientVersion")) {
		t.Fatal("the control names a minimum client")
	}
	for _, feature := range floorFeatures() {
		path, ok := set.feature(feature.name)
		if !ok {
			t.Fatalf("no fixture for %s", feature.name)
		}
		verify(path)
		index, targets, err := signedMembers(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := carryAssertion(feature, index, targets); err != nil {
			t.Fatalf("%s: %v", feature.name, err)
		}
		if feature.name == floorProviderFacts {
			continue
		}
		edited, ok := addIndexMinimum(controlIndex, feature.version)
		if !ok {
			t.Fatal("the control index cannot take a minimum")
		}
		if err := carryAssertion(feature, edited, controlTargets); err == nil {
			t.Fatalf("the control carries %s", feature.name)
		}
	}
	return set
}

// The writer and its synthetic inputs are made from the writer's clock alone:
// ten years from now the whole writer signs every package and each verifies,
// the builder admits the inputs and a release would not be expired.
func TestFloorFixtureInputsDoNotExpire(t *testing.T) {
	future := time.Now().UTC().AddDate(10, 0, 0).Truncate(time.Second)
	checkFloorFixtureWriter(t, future)
	// Control: packages written today are refused at that clock.
	today := checkFloorFixtureWriter(t, time.Now().UTC().Truncate(time.Second))
	if err := verifyFloorFixture(today, today.control(), future); err == nil {
		t.Fatal("setup: a package written today verifies ten years from now")
	}
	check := func(inputs, release time.Time, feature clientFloorFeature) error {
		index, _, _, err := cncfcheck.BuildExternalTargetsFromPackPinned(syntheticFloorPack(t, inputs, feature.name), "91", feature.version)
		if err != nil {
			return err
		}
		parsed, err := cncfcheck.ParseExternalIndex(index.Bytes)
		if err != nil {
			return err
		}
		admission, err := parsed.Admission()
		if err != nil {
			return err
		}
		_, _, err = Options{Now: release}.expiries(admission.EvidenceExpiresAt)
		return err
	}
	for _, feature := range append([]clientFloorFeature{{"", ""}}, floorFeatures()...) {
		if err := check(future, future, feature); err != nil {
			t.Errorf("%q at a clock ten years ahead: %v", feature.name, err)
		}
	}
	// Control: inputs dated today would be expired then. The pinned lease is
	// left out: its rule is dated ten years ahead by definition.
	if err := check(time.Now().UTC(), future, clientFloorFeature{"", ""}); err == nil {
		t.Fatal("setup: inputs dated today are not expired ten years from now")
	}
}

func TestAddIndexMinimumRefusesAPresentOne(t *testing.T) {
	got, ok := addIndexMinimum([]byte(`{"a":1}`), "v1.0.0")
	if !ok || string(got) != `{"a":1,"minClientVersion":"v1.0.0"}` {
		t.Fatalf("%q %v", got, ok)
	}
	for _, bad := range []string{"", "[]", "junk", `{"a":1}` + "\n", `{"minClientVersion":"v1.0.0"}`, `{"minClientVersion":null}`, `{"MinClientVersion":"v1.0.0"}`} {
		if _, ok := addIndexMinimum([]byte(bad), "v1.0.0"); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
