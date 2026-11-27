// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

// The admit checks of a client under test (the head archive's client, or the
// pinned one), for every client floor its version reaches:
//
//   A: the client reads the packages its own tree wrote: exit 0, VERIFIED.
//   B: the client reads the packages this tree writes: exit 0, VERIFIED; or,
//      for a pinned client only, exit 15 for the engine capability when this
//      tree's capability differs from the client's and A passed.
//
// For a floor a pinned client does not reach, this tree's package must be
// refused as too new. Every case first reads, from the signed bytes, that the
// index names the floor as its minimum and that the package carries the
// feature.

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepinguard"
)

const (
	// floorRunEnv selects the run: "head" (the client built from this
	// checkout's archive, at the highest floor) or "pin" (the pinned client).
	floorRunEnv = "PRUFYX_FLOOR_RUN"
	floorRunPin = "pin"

	floorRunHead = "head"

	// capabilityMismatchText is what a client prints when it refuses a package
	// for its engine capability.
	capabilityMismatchText = "KNOWLEDGE CAPABILITY MISMATCH"
	upgradeToText          = "upgrade prufyx to >="
	tooNewExit             = 15
)

var (
	signedIndexRE   = regexp.MustCompile(`^targets/knowledge/cncf/([0-9a-f]{64})\.index\.v1\.json$`)
	signedProjectRE = regexp.MustCompile(`^targets/knowledge/(?:cncf|community)/projects/([0-9a-f]{64})\.[a-z0-9-]+\.v1\.json$`)
	plainNameRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// signedMembers reads the index and the project targets from the package
// itself. Each is named by its digest, which must match its bytes.
func signedMembers(tarPath string) (index []byte, targets [][]byte, err error) {
	raw, err := os.ReadFile(tarPath)
	if err != nil {
		return nil, nil, err
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		isIndex := signedIndexRE.FindStringSubmatch(header.Name)
		match := isIndex
		if match == nil {
			match = signedProjectRE.FindStringSubmatch(header.Name)
		}
		if match == nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(reader, 8<<20))
		if err != nil {
			return nil, nil, err
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != match[1] {
			return nil, nil, fmt.Errorf("%s does not hold the bytes it is named for", header.Name)
		}
		if isIndex == nil {
			targets = append(targets, body)
		} else if index != nil {
			return nil, nil, errors.New("the package holds two indexes")
		} else {
			index = body
		}
	}
	if index == nil || len(targets) == 0 {
		return nil, nil, errors.New("the package holds no index or no project target")
	}
	return index, targets, nil
}

// jsonMember reads the member name of a JSON object, matching the name
// exactly. present is false only for an object without it.
func jsonMember(raw []byte, name string, into any) (present bool, err error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return false, fmt.Errorf("not a JSON object (looking for %s)", name)
	}
	value, ok := members[name]
	if !ok {
		return false, nil
	}
	if string(bytes.TrimSpace(value)) == "null" {
		return true, fmt.Errorf("%s is null", name)
	}
	if err := json.Unmarshal(value, into); err != nil {
		return true, fmt.Errorf("%s has another type: %v", name, err)
	}
	return true, nil
}

func requiredMember(raw []byte, name string, into any) error {
	present, err := jsonMember(raw, name, into)
	if err == nil && !present {
		err = fmt.Errorf("%s is absent", name)
	}
	return err
}

func indexCapability(index []byte) (string, error) {
	var capability string
	if err := requiredMember(index, "engineCapabilityDigest", &capability); err != nil || capability == "" {
		return "", fmt.Errorf("engine capability of the index: %q %v", capability, err)
	}
	return capability, nil
}

// carryAssertion is the positive read of the raw members: the index names the
// floor as its minimum client, and the package carries the feature. Anything
// absent, unreadable, of another type or value fails. The provider facts, and
// only they, have no content a client reads; a floor without an assertion here
// fails.
func carryAssertion(feature clientFloorFeature, index []byte, targets [][]byte) error {
	var minimum string
	if err := requiredMember(index, "minClientVersion", &minimum); err != nil {
		return fmt.Errorf("%s: index: %w", feature.name, err)
	}
	if minimum != feature.version {
		return fmt.Errorf("%s: the index names the minimum %q, not %q", feature.name, minimum, feature.version)
	}
	var carries func(pack []byte) (bool, error)
	switch feature.name {
	case floorProviderFacts:
		return nil
	case floorListedFamily:
		carries = func(pack []byte) (bool, error) {
			var records []json.RawMessage
			if present, err := jsonMember(pack, "lineAttestations", &records); err != nil || !present {
				return false, err
			}
			found := false
			for _, record := range records {
				var family string
				if err := requiredMember(record, "factFamily", &family); err != nil {
					return false, err
				}
				found = found || family == floorListedFamilyToken
			}
			return found, nil
		}
	case floorOptInLevel:
		carries = func(pack []byte) (bool, error) {
			var schema string
			if err := requiredMember(pack, "schema", &schema); err != nil {
				return false, err
			}
			return schema == floorOptInSchemaName, nil
		}
	case floorPinnedLease:
		carries = func(pack []byte) (bool, error) {
			var entries []json.RawMessage
			if err := requiredMember(pack, "entries", &entries); err != nil {
				return false, err
			}
			found := false
			for _, entry := range entries {
				var rule, evidence json.RawMessage
				if err := requiredMember(entry, "rule", &rule); err != nil {
					return false, err
				}
				if err := requiredMember(rule, "evidence", &evidence); err != nil {
					return false, err
				}
				var lease string
				if _, err := jsonMember(evidence, "lease", &lease); err != nil {
					return false, err
				}
				found = found || lease == floorPinnedLeaseToken
			}
			return found, nil
		}
	default:
		return fmt.Errorf("%s: no carry assertion for this floor", feature.name)
	}
	found := false
	for _, target := range targets {
		var pack json.RawMessage
		if err := requiredMember(target, "pack", &pack); err != nil {
			return fmt.Errorf("%s: target: %w", feature.name, err)
		}
		has, err := carries(pack)
		if err != nil {
			return fmt.Errorf("%s: target: %w", feature.name, err)
		}
		found = found || has
	}
	if !found {
		return fmt.Errorf("%s: no target carries the feature", feature.name)
	}
	return nil
}

// floorFixtures is a fixture directory as the writer of some tree left it.
type floorFixtures struct {
	dir      string
	manifest floorManifest
}

func loadFloorFixtures(dir string) (floorFixtures, error) {
	set := floorFixtures{dir: dir}
	raw, err := os.ReadFile(filepath.Join(dir, floorManifestName))
	if err != nil {
		return set, fmt.Errorf("the fixture writer left no manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set.manifest); err != nil {
		return set, fmt.Errorf("manifest: %w", err)
	}
	m := set.manifest
	if m.Schema != floorManifestSchema || m.CapabilityDigest == "" || m.RootDigest == "" || m.Revision == "" {
		return set, fmt.Errorf("manifest: schema %q or a required value is missing", m.Schema)
	}
	names := []string{m.Root, m.Control}
	seen := map[string]bool{}
	for _, f := range m.Features {
		if f.Floor == "" || seen[f.Floor] {
			return set, fmt.Errorf("manifest: floor %q is empty or repeated", f.Floor)
		}
		seen[f.Floor] = true
		names = append(names, f.Package)
	}
	for _, name := range names {
		if !plainNameRE.MatchString(name) {
			return set, fmt.Errorf("manifest: %q is not a file name (the control and the root are required)", name)
		}
		if info, err := os.Lstat(filepath.Join(dir, name)); err != nil || !info.Mode().IsRegular() {
			return set, fmt.Errorf("manifest names %s, which is not a file: %v", name, err)
		}
	}
	return set, nil
}

func (s floorFixtures) root() string    { return filepath.Join(s.dir, s.manifest.Root) }
func (s floorFixtures) control() string { return filepath.Join(s.dir, s.manifest.Control) }

func (s floorFixtures) feature(name string) (string, bool) {
	for _, f := range s.manifest.Features {
		if f.Floor == name {
			return filepath.Join(s.dir, f.Package), true
		}
	}
	return "", false
}

// floorVerify runs the client under test on one package of a fixture set.
type floorVerify func(set floorFixtures, pkg string) clientRun

func verified(run clientRun) bool {
	return run.code == 0 && json.Valid([]byte(run.stdout)) && strings.Contains(run.stdout, "VERIFIED")
}

func describeRun(run clientRun) string {
	return fmt.Sprintf("exit %d stdout=%q stderr=%q", run.code, strings.TrimSpace(run.stdout), strings.TrimSpace(run.stderr))
}

// signedFeature reads one feature package of a set, asserts what it carries
// and returns it with its capability.
func signedFeature(set floorFixtures, feature clientFloorFeature) (pkg, capability string, err error) {
	pkg, ok := set.feature(feature.name)
	if !ok {
		return "", "", fmt.Errorf("%s: the writer made no package", feature.name)
	}
	index, targets, err := signedMembers(pkg)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", feature.name, err)
	}
	if err := carryAssertion(feature, index, targets); err != nil {
		return "", "", err
	}
	if capability, err = indexCapability(index); err != nil {
		return "", "", err
	}
	return pkg, capability, nil
}

// admitA: the client reads the package of its own tree.
func admitA(verify floorVerify, client floorFixtures, feature clientFloorFeature) error {
	pkg, capability, err := signedFeature(client, feature)
	if err != nil {
		return fmt.Errorf("A: %w", err)
	}
	if capability != client.manifest.CapabilityDigest {
		return fmt.Errorf("A: %s: capability %s is not the manifest's %s", feature.name, capability, client.manifest.CapabilityDigest)
	}
	if run := verify(client, pkg); !verified(run) {
		return fmt.Errorf("A: %s: the client does not admit its own tree's package: %s", feature.name, describeRun(run))
	}
	return nil
}

// judgeB judges the client's answer to this tree's feature package.
func judgeB(run clientRun, mode, headCapability, clientCapability string, aErr error) error {
	if verified(run) {
		return nil
	}
	if mode == floorRunPin && run.code == tooNewExit && strings.Contains(run.stderr, capabilityMismatchText) &&
		!strings.Contains(run.stderr, upgradeToText) && headCapability != "" && clientCapability != "" && headCapability != clientCapability && aErr == nil {
		return nil
	}
	return fmt.Errorf("%s run, capability %s against %s, A: %v: %s", mode, headCapability, clientCapability, aErr, describeRun(run))
}

// refusedAsTooNew is the only accepted answer to a package of a floor the
// client does not reach.
func refusedAsTooNew(run clientRun, floor string) error {
	if run.code == tooNewExit && strings.Contains(run.stderr, "too new") && strings.Contains(run.stderr, upgradeToText+" "+floor) {
		return nil
	}
	return fmt.Errorf("want exit %d, too new, %s %s: %s", tooNewExit, upgradeToText, floor, describeRun(run))
}

// admitFloors holds the client at version to every floor. client are the
// packages of the client's tree, head those of this tree.
func admitFloors(verify floorVerify, client, head floorFixtures, features []clientFloorFeature, version, mode string) (problems []string) {
	fail := func(err error) {
		if err != nil {
			problems = append(problems, err.Error())
		}
	}
	if mode != floorRunHead && mode != floorRunPin {
		return []string{fmt.Sprintf("unknown run %q", mode)}
	}
	if !buildidentity.ValidVersion(version) || len(features) == 0 {
		return []string{fmt.Sprintf("client version %q is not a version, or there is no floor", version)}
	}
	if run := verify(client, client.control()); !verified(run) {
		fail(fmt.Errorf("control: the client does not admit its own tree's package without a floor feature: %s", describeRun(run)))
	}
	for _, feature := range features {
		if !buildidentity.ValidVersion(feature.version) {
			fail(fmt.Errorf("%s: %q is not a version", feature.name, feature.version))
			continue
		}
		reached := buildidentity.AtLeast(version, feature.version)
		if !reached && mode == floorRunHead {
			fail(fmt.Errorf("%s: the head run must reach every floor; %s is below %s", feature.name, version, feature.version))
			continue
		}
		var aErr error
		if reached {
			aErr = admitA(verify, client, feature)
			fail(aErr)
		}
		pkg, headCapability, err := signedFeature(head, feature)
		if err != nil {
			fail(fmt.Errorf("head: %w", err))
			continue
		}
		run := verify(head, pkg)
		if !reached {
			if err := refusedAsTooNew(run, feature.version); err != nil {
				fail(fmt.Errorf("%s: unreached floor: %w", feature.name, err))
			}
			continue
		}
		if err := judgeB(run, mode, headCapability, client.manifest.CapabilityDigest, aErr); err != nil {
			fail(fmt.Errorf("B: %s: %w", feature.name, err))
		}
	}
	return problems
}

// highestFloor is the version of the highest floor.
func highestFloor(features []clientFloorFeature) (string, error) {
	highest := ""
	for _, f := range features {
		if !buildidentity.ValidVersion(f.version) {
			return "", fmt.Errorf("floor %s %q is not a version", f.name, f.version)
		}
		if highest == "" || buildidentity.AtLeast(f.version, highest) {
			highest = f.version
		}
	}
	if highest == "" {
		return "", errors.New("there is no floor")
	}
	return highest, nil
}

type admitConfig struct{ mode, source, fixtures, version string }

// admitConfigFrom reads the run from the environment. skip is true only when
// none of the three variables is set; a partly set run fails.
func admitConfigFrom(getenv func(string) string, pin []byte) (cfg admitConfig, skip bool, err error) {
	cfg = admitConfig{mode: getenv(floorRunEnv), source: getenv(pinnedClientSourceEnv), fixtures: getenv(floorFixtureDirEnv)}
	if cfg.mode == "" && cfg.source == "" && cfg.fixtures == "" {
		return cfg, true, nil
	}
	if cfg.mode == "" || cfg.source == "" || cfg.fixtures == "" {
		return cfg, false, fmt.Errorf("%s, %s and %s are needed together: %q, %q, %q", floorRunEnv, pinnedClientSourceEnv, floorFixtureDirEnv, cfg.mode, cfg.source, cfg.fixtures)
	}
	switch cfg.mode {
	case floorRunHead:
		cfg.version, err = highestFloor(floorFeatures())
	case floorRunPin:
		if string(pin) == knowledgepinguard.LegacyPin {
			return cfg, false, errors.New("the pin run has nothing to prove for the legacy pin")
		}
		_, cfg.version, err = knowledgepinguard.ParsePin(pin)
	default:
		err = fmt.Errorf("%s=%q is neither %s nor %s", floorRunEnv, cfg.mode, floorRunHead, floorRunPin)
	}
	return cfg, false, err
}

// admitRun reads the run of an admit test, builds the client under test and
// returns how to run it.
func admitRun(t *testing.T) (admitConfig, floorVerify) {
	t.Helper()
	pin, err := os.ReadFile(filepath.Join("..", "..", "..", "knowledge", "oldest-supported-client.txt"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, skip, err := admitConfigFrom(os.Getenv, pin)
	if skip {
		t.Skipf("integration test: set %s, %s and %s", floorRunEnv, pinnedClientSourceEnv, floorFixtureDirEnv)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.source, "cli", "go.mod")); err != nil {
		t.Fatalf("%s=%s holds no cli/go.mod: %v", pinnedClientSourceEnv, cfg.source, err)
	}
	client := filepath.Join(t.TempDir(), "client")
	buildClient(t, filepath.Join(cfg.source, "cli"), "prufyx-community", cfg.version, client)
	return cfg, verifyWith(t, client)
}

func verifyWith(t *testing.T, client string) floorVerify {
	return func(set floorFixtures, pkg string) clientRun {
		return runClient(t, client, pkg, set.root(), set.manifest.RootDigest, set.manifest.Revision)
	}
}

// TestPinnedClientAdmitsReachedFloors runs the admit checks for the client
// under test (see the file comment).
func TestPinnedClientAdmitsReachedFloors(t *testing.T) {
	cfg, verify := admitRun(t)
	client, err := loadFloorFixtures(cfg.fixtures)
	if err != nil {
		t.Fatal(err)
	}
	headDir := filepath.Join(t.TempDir(), "head")
	writeFloorFixtures(t, headDir, time.Now())
	head, err := loadFloorFixtures(headDir)
	if err != nil {
		t.Fatal(err)
	}
	if problems := admitFloors(verify, client, head, floorFeatures(), cfg.version, cfg.mode); len(problems) != 0 {
		t.Fatalf("%s run, client %s:\n%s", cfg.mode, cfg.version, strings.Join(problems, "\n"))
	}
	t.Logf("%s run: client %s admitted", cfg.mode, cfg.version)
}

// integrityRefusal is the whole of what the client prints for a package it
// refuses as an integrity failure: no reason of capability or minimum follows.
const integrityRefusal = "prufyx: knowledge package verification failed"

// lackingRead removes one feature's read from a copy of the client source: one
// exact replacement, and the refusal that client then gives.
type lackingRead struct {
	floor, file, old, new string
	exit                  int
	message               string
}

// The listed family's read is removed by renaming the family to an
// unregistered one in the section passed at the external read. The table entry
// stays, because the embedded pack is admitted through it.
const (
	listedFamilyToken       = `"changelog.listed_entries"`
	unregisteredFamily      = "changelog.unregistered_entries"
	unregisteredFamilyToken = `"` + unregisteredFamily + `"`
	renamedListedSection    = "bytes.ReplaceAll(section, []byte(`" + listedFamilyToken + "`), []byte(`" + unregisteredFamilyToken + "`))"
)

// The renamed section is refused because its family is not registered, and for
// no other reason: the same section parses before the rename.
func TestRenamedListedFamilyIsUnknown(t *testing.T) {
	pack, err := os.ReadFile(filepath.Join("..", "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	section, present, err := lineattest.PackSection(pack)
	if err != nil || !present {
		t.Fatalf("embedded attestations: present=%v, %v", present, err)
	}
	if _, err := lineattest.Parse(section); err != nil {
		t.Fatalf("the unchanged section: %v", err)
	}
	if !bytes.Contains(section, []byte(listedFamilyToken)) {
		t.Fatalf("the embedded section holds no %s", listedFamilyToken)
	}
	renamed := bytes.ReplaceAll(section, []byte(listedFamilyToken), []byte(unregisteredFamilyToken))
	_, err = lineattest.Parse(renamed)
	want := fmt.Sprintf("unknown factFamily %q", unregisteredFamily)
	if !errors.Is(err, lineattest.ErrInvalid) || !strings.Contains(err.Error(), want) {
		t.Fatalf("the renamed section: %v, want %s", err, want)
	}
}

func lackingReads() []lackingRead {
	return []lackingRead{
		{
			floor: floorPinnedLease, file: "internal/constraintengine/lease.go",
			old: "\tcase LeasePinned:\n\tdefault:\n", new: "\tdefault:\n",
			exit: 3, message: integrityRefusal,
		},
		{
			floor: floorListedFamily, file: "internal/cncfcheck/external_records.go",
			old:  "if _, err := admitAttestations(section, true, pack.Entries); err != nil {",
			new:  "if _, err := admitAttestations(" + renamedListedSection + ", true, pack.Entries); err != nil {",
			exit: 3, message: integrityRefusal,
		},
		{
			floor: floorOptInLevel, file: "internal/cncfcheck/external.go",
			old: "if !validPackSchema(packValue) || ", new: "if packValue.Schema == packSchemaBoundaryCovered || !validPackSchema(packValue) || ",
			exit: 3, message: integrityRefusal,
		},
	}
}

// replaceOnce replaces old, which source must hold exactly once.
func replaceOnce(source, old, new string) (string, error) {
	if n := strings.Count(source, old); old == "" || n != 1 {
		return "", fmt.Errorf("%q occurs %d times, want once", old, n)
	}
	return strings.Replace(source, old, new, 1), nil
}

func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}

// lackingProblems lists every way a client without the feature's read does not
// show it: it must still read the control, refuse the feature package with the
// fixed refusal (not for its capability, not as too new), and fail admit A.
func lackingProblems(lacking floorVerify, set floorFixtures, feature clientFloorFeature, want lackingRead) (problems []string) {
	if run := lacking(set, set.control()); !verified(run) {
		problems = append(problems, "the modified client does not admit the control: "+describeRun(run))
	}
	pkg, ok := set.feature(feature.name)
	if !ok {
		return append(problems, "no feature package")
	}
	run := lacking(set, pkg)
	// The whole message is compared, so it names neither a capability nor a
	// minimum client.
	if run.code != want.exit || strings.TrimSpace(run.stderr) != want.message {
		problems = append(problems, fmt.Sprintf("the modified client must refuse the feature with exit %d %q: %s", want.exit, want.message, describeRun(run)))
	}
	if admitA(lacking, set, feature) == nil {
		problems = append(problems, "admit A passed for the modified client")
	}
	return problems
}

// TestAdmitCheckRefusesClientLackingFeature proves admit A is not vacuous: a
// client that lost the read of one feature fails it.
func TestAdmitCheckRefusesClientLackingFeature(t *testing.T) {
	cfg, unmodified := admitRun(t)
	if cfg.mode != floorRunHead {
		t.Fatalf("this check belongs to the %s run, not %s", floorRunHead, cfg.mode)
	}
	set, err := loadFloorFixtures(cfg.fixtures)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	cli := filepath.Join(work, "cli")
	if err := copyTree(filepath.Join(cfg.source, "cli"), cli); err != nil {
		t.Fatal(err)
	}
	reads := map[string]lackingRead{}
	for _, read := range lackingReads() {
		reads[read.floor] = read
	}
	for _, feature := range floorFeatures() {
		if feature.name == floorProviderFacts {
			continue // no content a client reads
		}
		read, ok := reads[feature.name]
		if !ok {
			t.Fatalf("no removable read for %s", feature.name)
		}
		if err := admitA(unmodified, set, feature); err != nil {
			t.Fatalf("the unmodified client: %v", err)
		}
		path := filepath.Join(cli, filepath.FromSlash(read.file))
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited, err := replaceOnce(string(original), read.old, read.new)
		if err != nil {
			t.Fatalf("%s: %s: %v", feature.name, read.file, err)
		}
		if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(work, "lacking-"+feature.name)
		buildClient(t, cli, "prufyx-community", cfg.version, binary)
		if err := os.WriteFile(path, original, 0o644); err != nil {
			t.Fatal(err)
		}
		if problems := lackingProblems(verifyWith(t, binary), set, feature, read); len(problems) != 0 {
			t.Fatalf("%s:\n%s", feature.name, strings.Join(problems, "\n"))
		}
		t.Logf("%s: a client without the read is refused", feature.name)
	}
}

// Each removable read is one exact place in this tree, for every floor with
// client-read content and no other.
func TestLackingReadsMatchThisTreeExactlyOnce(t *testing.T) {
	reads := map[string]bool{}
	for _, read := range lackingReads() {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", filepath.FromSlash(read.file)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := replaceOnce(string(raw), read.old, read.new); err != nil {
			t.Errorf("%s: %s: %v", read.floor, read.file, err)
		}
		reads[read.floor] = true
	}
	for _, feature := range floorFeatures() {
		if reads[feature.name] == (feature.name == floorProviderFacts) {
			t.Errorf("%s: removable read present=%v", feature.name, reads[feature.name])
		}
	}
	for _, c := range []struct{ source, old string }{{"a b", "c"}, {"a a", "a"}, {"a", ""}} {
		if _, err := replaceOnce(c.source, c.old, "x"); err == nil {
			t.Errorf("%q in %q replaced", c.old, c.source)
		}
	}
}

// The mismatch text and exit code are the ones this tree's client prints.
func TestCapabilityMismatchTextIsTheClients(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "communityapp", "knowledge.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `return r.fail(message+"; `+capabilityMismatchText+`: "+capabilityMismatchAdvice, ExitKnowledgeTooNew)`) {
		t.Fatalf("the client no longer prints %q with the too-new exit: the text is frozen once a pinned tag holds it", capabilityMismatchText)
	}
}

func TestCarryAssertionRefuses(t *testing.T) {
	features := map[string]clientFloorFeature{}
	for _, f := range floorFeatures() {
		features[f.name] = f
	}
	index := func(f clientFloorFeature) []byte { return []byte(`{"minClientVersion":"` + f.version + `"}`) }
	good := map[string]string{
		floorProviderFacts: `{}`,
		floorListedFamily:  `{"pack":{"lineAttestations":[{"factFamily":"changelog.listed_entries"}]}}`,
		floorOptInLevel:    `{"pack":{"schema":"prufyx.io/cncf-source-rule-pack/v1alpha16"}}`,
		floorPinnedLease:   `{"pack":{"entries":[{"rule":{"evidence":{"lease":"pinned"}}}]}}`,
	}
	for name, target := range good {
		f := features[name]
		if err := carryAssertion(f, index(f), [][]byte{[]byte(target)}); err != nil {
			t.Fatalf("%s: control: %v", name, err)
		}
		// The minimum: absent, unreadable, wrong type, other value. This binds
		// the exempt floor too.
		for _, bad := range []string{"", "junk", "[]", "{}", `{"minClientVersion":null}`, `{"minClientVersion":1}`, `{"minClientVersion":"v0.1.0-beta.0"}`, `{"MinClientVersion":"` + f.version + `"}`} {
			if err := carryAssertion(f, []byte(bad), [][]byte{[]byte(target)}); err == nil {
				t.Errorf("%s: index %q accepted", name, bad)
			}
		}
	}
	bad := map[string][]string{
		floorListedFamily: {`{"pack":{}}`, `{"pack":{"lineAttestations":[]}}`, `{"pack":{"lineAttestations":null}}`, `{"pack":{"lineAttestations":{}}}`, `{"pack":{"lineAttestations":[1]}}`,
			`{"pack":{"lineAttestations":[{}]}}`, `{"pack":{"lineAttestations":[{"factFamily":1}]}}`, `{"pack":{"lineAttestations":[{"factFamily":"other"}]}}`, `{"pack":{"lineAttestations":[{"FactFamily":"changelog.listed_entries"}]}}`},
		floorOptInLevel: {`{"pack":{}}`, `{"pack":{"schema":null}}`, `{"pack":{"schema":16}}`, `{"pack":{"schema":"prufyx.io/cncf-source-rule-pack/v1alpha11"}}`, `{"pack":{"Schema":"prufyx.io/cncf-source-rule-pack/v1alpha16"}}`},
		floorPinnedLease: {`{"pack":{}}`, `{"pack":{"entries":[]}}`, `{"pack":{"entries":null}}`, `{"pack":{"entries":{}}}`, `{"pack":{"entries":[{}]}}`, `{"pack":{"entries":[{"rule":{}}]}}`,
			`{"pack":{"entries":[{"rule":{"evidence":{}}}]}}`, `{"pack":{"entries":[{"rule":{"evidence":{"lease":true}}}]}}`, `{"pack":{"entries":[{"rule":{"evidence":{"lease":"time"}}}]}}`},
	}
	for name, targets := range bad {
		f := features[name]
		for _, target := range append(targets, "", "junk", "{}", `{"pack":null}`, `{"pack":[]}`) {
			if err := carryAssertion(f, index(f), [][]byte{[]byte(target)}); err == nil {
				t.Errorf("%s: target %q accepted", name, target)
			}
			// One unreadable target fails the package even beside a good one.
			if !json.Valid([]byte(target)) {
				if err := carryAssertion(f, index(f), [][]byte{[]byte(good[name]), []byte(target)}); err == nil {
					t.Errorf("%s: unreadable target %q accepted beside a good one", name, target)
				}
			}
		}
		if err := carryAssertion(f, index(f), nil); err == nil {
			t.Errorf("%s: no target accepted", name)
		}
	}
	// Only the exact provider-facts name is exempt.
	for _, name := range []string{"", "providerfactsminclientversion", "ProviderFactsMinClientVersion2", "SomeLaterFloor"} {
		f := clientFloorFeature{name, "v0.1.0-beta.1"}
		if err := carryAssertion(f, index(f), [][]byte{[]byte(`{"pack":{}}`)}); err == nil {
			t.Errorf("floor %q without a carry assertion accepted", name)
		}
	}
}

func TestJudgeBAcceptsOnlyTwoOutcomes(t *testing.T) {
	ok := clientRun{code: 0, stdout: `{"status":"VERIFIED"}`}
	mismatch := clientRun{code: 15, stderr: "x; " + capabilityMismatchText + ": the feed"}
	for _, mode := range []string{floorRunHead, floorRunPin} {
		if err := judgeB(ok, mode, "sha256:a", "sha256:a", nil); err != nil {
			t.Fatalf("%s: verified refused: %v", mode, err)
		}
	}
	if err := judgeB(mismatch, floorRunPin, "sha256:a", "sha256:b", nil); err != nil {
		t.Fatalf("capability branch refused: %v", err)
	}
	for name, c := range map[string]struct {
		run          clientRun
		mode         string
		head, client string
		a            error
	}{
		"mismatch in the head run": {mismatch, floorRunHead, "sha256:a", "sha256:b", nil},
		"equal capability":         {mismatch, floorRunPin, "sha256:a", "sha256:a", nil},
		"no head capability":       {mismatch, floorRunPin, "", "sha256:b", nil},
		"no client capability":     {mismatch, floorRunPin, "sha256:a", "", nil},
		"A failed":                 {mismatch, floorRunPin, "sha256:a", "sha256:b", errors.New("A")},
		"names a minimum":          {clientRun{code: 15, stderr: mismatch.stderr + " " + upgradeToText + " v1.0.0"}, floorRunPin, "sha256:a", "sha256:b", nil},
		"too new, no mismatch":     {clientRun{code: 15, stderr: "too new"}, floorRunPin, "sha256:a", "sha256:b", nil},
		"integrity":                {clientRun{code: 3, stderr: mismatch.stderr}, floorRunPin, "sha256:a", "sha256:b", nil},
		"another code":             {clientRun{code: 2, stderr: mismatch.stderr}, floorRunPin, "sha256:a", "sha256:b", nil},
		"exit 0 without VERIFIED":  {clientRun{code: 0, stdout: `{"status":"REFUSED"}`}, floorRunPin, "sha256:a", "sha256:b", nil},
		"exit 0 not JSON":          {clientRun{code: 0, stdout: `VERIFIED`}, floorRunPin, "sha256:a", "sha256:b", nil},
	} {
		if err := judgeB(c.run, c.mode, c.head, c.client, c.a); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// fakeSet writes a fixture set whose packages are real signed packages of this
// tree, for the checks that need no built client.
func fakeSets(t *testing.T) (client, head floorFixtures) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "fixtures")
	writeFloorFixtures(t, dir, time.Now())
	set, err := loadFloorFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	return set, set
}

func TestAdmitFloorsRefusesMissingOrFailingInputs(t *testing.T) {
	client, head := fakeSets(t)
	features := floorFeatures()
	highest, err := highestFloor(features)
	if err != nil {
		t.Fatal(err)
	}
	good := clientRun{code: 0, stdout: `{"status":"VERIFIED"}`}
	all := func(floorFixtures, string) clientRun { return good }
	if p := admitFloors(all, client, head, features, highest, floorRunHead); len(p) != 0 {
		t.Fatalf("control: %q", p)
	}
	refused := func(name string, p []string, want string) {
		t.Helper()
		if !strings.Contains(strings.Join(p, "\n"), want) {
			t.Errorf("%s: problems %q do not name %q", name, p, want)
		}
	}
	without := func(set floorFixtures, floor string) floorFixtures {
		kept := []floorManifestFeature{}
		for _, f := range set.manifest.Features {
			if f.Floor != floor {
				kept = append(kept, f)
			}
		}
		set.manifest.Features = kept
		return set
	}
	for _, f := range features {
		refused("client lacks "+f.name, admitFloors(all, without(client, f.name), head, features, highest, floorRunHead), "A: "+f.name+": the writer made no package")
		refused("head lacks "+f.name, admitFloors(all, client, without(head, f.name), features, highest, floorRunHead), "head: "+f.name)
		pkg, _ := client.feature(f.name)
		failing := func(code int) floorVerify {
			return func(_ floorFixtures, p string) clientRun {
				if p == pkg {
					return clientRun{code: code, stderr: capabilityMismatchText}
				}
				return good
			}
		}
		refused("integrity on "+f.name, admitFloors(failing(3), client, head, features, highest, floorRunPin), "A: "+f.name)
		refused("head-run exit 15 on "+f.name, admitFloors(failing(15), client, head, features, highest, floorRunHead), "B: "+f.name)
	}
	noControl := func(_ floorFixtures, p string) clientRun {
		if p == client.control() {
			return clientRun{code: 3}
		}
		return good
	}
	refused("control refused", admitFloors(noControl, client, head, features, highest, floorRunHead), "control:")
	refused("head run below a floor", admitFloors(all, client, head, features, "v0.1.0-beta.1", floorRunHead), "the head run must reach every floor")
	refused("unknown run", admitFloors(all, client, head, features, highest, "other"), "unknown run")
	refused("no version", admitFloors(all, client, head, features, "latest", floorRunPin), "not a version")
	refused("no floor", admitFloors(all, client, head, nil, highest, floorRunPin), "there is no floor")

	// A swapped package does not pass the carry assertion.
	swapped := client
	swapped.manifest.Features = append([]floorManifestFeature(nil), client.manifest.Features...)
	for i := range swapped.manifest.Features {
		swapped.manifest.Features[i].Package = client.manifest.Control
	}
	refused("control in place of features", admitFloors(all, swapped, head, features, highest, floorRunHead), "A: "+floorListedFamily)

	// A pinned client below the later floors: this tree's packages for them
	// must be refused as too new, with the floor named.
	below := "v0.1.0-beta.1"
	tooNew := func(set floorFixtures, p string) clientRun {
		for _, f := range features {
			if pkg, _ := set.feature(f.name); pkg == p && !buildidentity.AtLeast(below, f.version) {
				return clientRun{code: 15, stderr: "too new: " + upgradeToText + " " + f.version}
			}
		}
		return good
	}
	if p := admitFloors(tooNew, client, head, features, below, floorRunPin); len(p) != 0 {
		t.Fatalf("control below the later floors: %q", p)
	}
	refused("unreached floor admitted", admitFloors(all, client, head, features, below, floorRunPin), floorListedFamily+": unreached floor")
	for name, run := range map[string]clientRun{
		"integrity":       {code: 3, stderr: "too new: " + upgradeToText + " v0.1.0-beta.2"},
		"no floor named":  {code: 15, stderr: "too new"},
		"other floor":     {code: 15, stderr: "too new: " + upgradeToText + " v0.1.0-beta.1"},
		"capability only": {code: 15, stderr: capabilityMismatchText},
	} {
		if err := refusedAsTooNew(run, "v0.1.0-beta.2"); err == nil {
			t.Errorf("%s accepted as too new", name)
		}
	}
}

func TestLackingProblemsRefusesOtherAnswers(t *testing.T) {
	set, _ := fakeSets(t)
	feature := floorFeatures()[2]
	want := lackingReads()[1]
	pkg, _ := set.feature(feature.name)
	good := clientRun{code: 0, stdout: `{"status":"VERIFIED"}`}
	answer := func(control, onFeature clientRun) floorVerify {
		return func(_ floorFixtures, p string) clientRun {
			if p == pkg {
				return onFeature
			}
			return control
		}
	}
	refusal := clientRun{code: 3, stderr: integrityRefusal + "\n"}
	if p := lackingProblems(answer(good, refusal), set, feature, want); len(p) != 0 {
		t.Fatalf("control: %q", p)
	}
	for name, v := range map[string]floorVerify{
		"control refused":     answer(refusal, refusal),
		"feature admitted":    answer(good, good),
		"another exit":        answer(good, clientRun{code: 15, stderr: integrityRefusal}),
		"another message":     answer(good, clientRun{code: 3, stderr: "other"}),
		"capability mismatch": answer(good, clientRun{code: 3, stderr: integrityRefusal + "; " + capabilityMismatchText}),
		"names a minimum":     answer(good, clientRun{code: 3, stderr: integrityRefusal + "; " + upgradeToText}),
	} {
		if p := lackingProblems(v, set, feature, want); len(p) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLoadFloorFixturesRefuses(t *testing.T) {
	set, _ := fakeSets(t)
	original, err := os.ReadFile(filepath.Join(set.dir, floorManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadFloorFixtures(t.TempDir()); err == nil {
		t.Fatal("a directory without a manifest accepted")
	}
	for name, edit := range map[string]func(m *floorManifest){
		"another schema":    func(m *floorManifest) { m.Schema += "x" },
		"no capability":     func(m *floorManifest) { m.CapabilityDigest = "" },
		"no root digest":    func(m *floorManifest) { m.RootDigest = "" },
		"no revision":       func(m *floorManifest) { m.Revision = "" },
		"no control":        func(m *floorManifest) { m.Control = "" },
		"absent control":    func(m *floorManifest) { m.Control = "absent.tar" },
		"escaping root":     func(m *floorManifest) { m.Root = "../root.json" },
		"repeated floor":    func(m *floorManifest) { m.Features = append(m.Features, m.Features[0]) },
		"empty floor":       func(m *floorManifest) { m.Features[0].Floor = "" },
		"absent package":    func(m *floorManifest) { m.Features[0].Package = "absent.tar" },
		"directory package": func(m *floorManifest) { m.Features[0].Package = "." },
	} {
		m := set.manifest
		m.Features = append([]floorManifestFeature(nil), set.manifest.Features...)
		edit(&m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(set.dir, floorManifestName), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadFloorFixtures(set.dir); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, raw := range [][]byte{[]byte("junk"), append([]byte(`{"extra":1,`), original[1:]...)} {
		if err := os.WriteFile(filepath.Join(set.dir, floorManifestName), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadFloorFixtures(set.dir); err == nil {
			t.Errorf("%.20q accepted", raw)
		}
	}
}

func TestAdmitConfigRefusesPartialRuns(t *testing.T) {
	env := func(mode, source, fixtures string) func(string) string {
		return func(name string) string {
			return map[string]string{floorRunEnv: mode, pinnedClientSourceEnv: source, floorFixtureDirEnv: fixtures}[name]
		}
	}
	legacy := []byte(knowledgepinguard.LegacyPin)
	moved := []byte("ref=" + strings.Repeat("a", 40) + "\nversion=v0.1.0-beta.3\n")
	if _, skip, err := admitConfigFrom(env("", "", ""), legacy); !skip || err != nil {
		t.Fatalf("nothing set: %v %v", skip, err)
	}
	highest, err := highestFloor(floorFeatures())
	if err != nil || highest != "v0.1.0-beta.2" {
		t.Fatalf("highest floor %q %v", highest, err)
	}
	if cfg, skip, err := admitConfigFrom(env(floorRunHead, "/s", "/f"), legacy); skip || err != nil || cfg.version != highest {
		t.Fatalf("head: %+v %v %v", cfg, skip, err)
	}
	if cfg, skip, err := admitConfigFrom(env(floorRunPin, "/s", "/f"), moved); skip || err != nil || cfg.version != "v0.1.0-beta.3" {
		t.Fatalf("pin: %+v %v %v", cfg, skip, err)
	}
	for name, c := range map[string]struct {
		env func(string) string
		pin []byte
	}{
		"head without source":   {env(floorRunHead, "", "/f"), legacy},
		"head without fixtures": {env(floorRunHead, "/s", ""), legacy},
		"source without a run":  {env("", "/s", "/f"), legacy},
		"source only":           {env("", "/s", ""), legacy},
		"fixtures only":         {env("", "", "/f"), legacy},
		"run only":              {env(floorRunHead, "", ""), legacy},
		"unknown run":           {env("other", "/s", "/f"), legacy},
		"legacy pin run":        {env(floorRunPin, "/s", "/f"), legacy},
		"unreadable pin":        {env(floorRunPin, "/s", "/f"), []byte("junk")},
	} {
		if _, skip, err := admitConfigFrom(c.env, c.pin); skip || err == nil {
			t.Errorf("%s: skip=%v err=%v", name, skip, err)
		}
	}
	for _, bad := range [][]clientFloorFeature{nil, {{"x", "latest"}}} {
		if _, err := highestFloor(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
