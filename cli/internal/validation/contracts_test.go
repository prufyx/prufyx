// SPDX-License-Identifier: AGPL-3.0-only

package validation

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testPolicy() PolicyReference {
	return PolicyReference{APIVersion: APIVersion, Kind: PolicyReferenceKind, SchemaVersion: SchemaVersion, PolicyID: "community-test", Revision: "revision-1", Digest: testDigest}
}

func testBundle() ProposedBundle {
	return ProposedBundle{APIVersion: APIVersion, Kind: ProposedBundleKind, SchemaVersion: SchemaVersion, BundleID: "proposal-1", PolicyRef: testPolicy(), Components: []ProposedTarget{{Component: "pkg:oci/example/widget", Version: "1.3.0", Profile: "generic-managed-v1"}}}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadContracts_ValidAndClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "proposed.json")
	policyPath := filepath.Join(dir, "policy.json")
	writeJSON(t, bundlePath, testBundle())
	writeJSON(t, policyPath, testPolicy())
	gotBundle, err := ReadProposedBundle(bundlePath)
	if err != nil {
		t.Fatalf("ReadProposedBundle() error = %v", err)
	}
	gotPolicy, err := ReadPolicyReference(policyPath)
	if err != nil {
		t.Fatalf("ReadPolicyReference() error = %v", err)
	}
	if gotBundle.PolicyRef != gotPolicy || len(gotBundle.Components) != 1 {
		t.Fatalf("references = %#v/%#v", gotBundle.PolicyRef, gotPolicy)
	}
}

func TestObservedVersionAcceptsManagedProviderSuffixes(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"1.35.6-gke.1710000", true},
		{"1.35.6-eks.7", true},
		{"1.35.6+build.7", true},
		{"1.35.6-01", false},
		{"v1.35.6", false},
		{"1.35.6-", false},
	} {
		if got := validObservedVersion(tc.value); got != tc.want {
			t.Fatalf("validObservedVersion(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestCandidateExplainabilityRejectsTerminalControlsAndUnsafeBlobURLs(t *testing.T) {
	validDetail := []RequirementDetail{{Code: "CONFIGURATION_MISSING", Reason: "bounded explanation", NextAction: "capture bounded fact"}}
	for _, value := range []string{"line\nfeed", "tab\tvalue", "\x1b[31mred", "\u0085", string([]byte{0xff, 0xfe})} {
		details := append([]RequirementDetail(nil), validDetail...)
		details[0].Reason = value
		if err := canonicalRequirementDetails(&details, []string{"CONFIGURATION_MISSING"}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe explanation %q error = %v, want ErrInvalid", value, err)
		}
	}

	valid := SourceEvidence{SourceID: "fixture-source", URL: "https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md", ContentDigest: testDigest, StartLine: 1, EndLine: 2}
	for _, url := range []string{
		"https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md?download=1",
		"https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md#L1",
		"https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference/",
		"https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/%2e%2e/secret",
		"https://user@github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md",
		"https://github.com/prufyx/fixtures/blob/0123456789abcdef0123456789abcdef01234567/../secret",
		"https://github.com/prufyx/fixtures/blob/not-a-commit/docs/reference.md",
		"https://github.com//fixtures/blob/0123456789abcdef0123456789abcdef01234567/docs/reference.md",
		"https://github.com/prufyx/fixtures/tree/0123456789abcdef0123456789abcdef01234567/docs/reference.md",
	} {
		evidence := valid
		evidence.URL = url
		if err := canonicalSourceEvidence(&[]SourceEvidence{evidence}, false); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe evidence URL %q error = %v, want ErrInvalid", url, err)
		}
	}
	if err := canonicalSourceEvidence(&[]SourceEvidence{valid}, false); err != nil {
		t.Fatalf("valid blob evidence rejected: %v", err)
	}
}

func TestReadContracts_RejectsAncestorSymlinkAndLeafSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(realDir, "bundle.json")
	writeJSON(t, realPath, testBundle())
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProposedBundle(filepath.Join(linkedDir, "bundle.json")); !errors.Is(err, ErrIO) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("ancestor symlink error = %v, want fail-closed path error", err)
	}
	leafLink := filepath.Join(root, "leaf.json")
	if err := os.Symlink(realPath, leafLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProposedBundle(leafLink); !errors.Is(err, ErrIO) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("leaf symlink error = %v, want fail-closed path error", err)
	}
}

func TestReadContracts_RejectsHardLinkedProposalAndPolicy(t *testing.T) {
	dir := t.TempDir()
	proposal := filepath.Join(dir, "proposal.json")
	writeJSON(t, proposal, testBundle())
	proposalLink := filepath.Join(dir, "proposal-link.json")
	if err := os.Link(proposal, proposalLink); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if _, err := ReadProposedBundle(proposalLink); !errors.Is(err, ErrIO) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("hard-linked proposal error = %v, want fail-closed error", err)
	}
	policy := filepath.Join(dir, "policy.json")
	writeJSON(t, policy, testPolicy())
	policyLink := filepath.Join(dir, "policy-link.json")
	if err := os.Link(policy, policyLink); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	if _, err := ReadPolicyReference(policyLink); !errors.Is(err, ErrIO) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("hard-linked policy error = %v, want fail-closed error", err)
	}
}

func TestReadContracts_RejectsDuplicateUnknownAndBounds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	valid := testBundle()
	validJSON, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.TrimSuffix(string(validJSON), "}") + `,"unexpected":true}`
	duplicate := `{"apiVersion":"` + APIVersion + `","kind":"PolicyReference","schemaVersion":"` + SchemaVersion + `","policyId":"community-test","revision":"revision-1","digest":"` + testDigest + `","digest":"` + testDigest + `"}`
	cases := []struct {
		name string
		raw  string
		read func(string) error
	}{
		{name: "unknown field", raw: unknown, read: func(path string) error { _, err := ReadProposedBundle(path); return err }},
		{name: "duplicate nested field", raw: duplicate, read: func(path string) error { _, err := ReadPolicyReference(path); return err }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.read(path); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
	tooMany := valid
	tooMany.Components = make([]ProposedTarget, MaxComponents+1)
	for index := range tooMany.Components {
		tooMany.Components[index] = ProposedTarget{Component: "pkg:oci/example/widget-" + strings.Repeat("a", 1) + string(rune('a'+index%26)), Version: "1.3.0", Profile: "generic-managed-v1"}
	}
	path := filepath.Join(dir, "too-many.json")
	writeJSON(t, path, tooMany)
	if _, err := ReadProposedBundle(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too-many error = %v, want ErrInvalid", err)
	}
	for name, raw := range map[string]json.RawMessage{
		"oversized string": json.RawMessage(`"` + strings.Repeat("x", MaxStringBytes+1) + `"`),
		"unsafe integer":   json.RawMessage(`9007199254740992`),
		"too deep":         json.RawMessage(strings.Repeat(`[`, MaxJSONDepth+2) + `0` + strings.Repeat(`]`, MaxJSONDepth+2)),
	} {
		name, raw := name, raw
		t.Run(name, func(t *testing.T) {
			bounded := testBundle()
			bounded.Components[0].Configuration = map[string]json.RawMessage{"config": raw}
			path := filepath.Join(dir, name+".json")
			writeJSON(t, path, bounded)
			if _, err := ReadProposedBundle(path); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestPrepareOutputRoot_RefusesReuseAndWritesExclusiveFiles(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "report")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if _, err := os.Stat(root.Path()); !os.IsNotExist(err) {
		t.Fatalf("staging must not publish final root before commit: %v", err)
	}
	report := IncompleteReport{Now: "2026-08-26T00:00:00Z", ProposedBundleDigest: testDigest, PolicyDigest: testDigest, ComponentCount: 1}
	if _, err := root.WriteIncompleteReport(report); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("output root mode = %o, want 700", info.Mode().Perm())
	}
	if err := root.Write("report.json", []byte("again")); !errors.Is(err, ErrIO) {
		t.Fatalf("overwrite error = %v, want ErrIO", err)
	}
	if _, err := PrepareOutputRoot(path); !errors.Is(err, ErrIO) {
		t.Fatalf("reuse error = %v, want ErrIO", err)
	}
	link := filepath.Join(t.TempDir(), "output-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareOutputRoot(link); !errors.Is(err, ErrIO) && !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink output error = %v, want refusal", err)
	}
	if err := root.Write("../escape", []byte("nope")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("traversal output error = %v, want ErrInvalid", err)
	}
}

func TestWriteIncompleteReport_ValidatesCallerSuppliedFields(t *testing.T) {
	t.Parallel()
	root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "report"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	valid := IncompleteReport{Now: "2026-08-26T00:00:00Z", ProposedBundleDigest: testDigest, PolicyDigest: testDigest, ComponentCount: 1}
	cases := []struct {
		name   string
		mutate func(*IncompleteReport)
	}{
		{"wrong api version", func(r *IncompleteReport) { r.APIVersion = "wrong" }},
		{"wrong kind", func(r *IncompleteReport) { r.Kind = "Other" }},
		{"wrong schema", func(r *IncompleteReport) { r.SchemaVersion = "0" }},
		{"invalid proposed digest", func(r *IncompleteReport) { r.ProposedBundleDigest = "not-a-digest" }},
		{"invalid policy digest", func(r *IncompleteReport) { r.PolicyDigest = "not-a-digest" }},
		{"oversized reason", func(r *IncompleteReport) { r.ReasonCode = strings.Repeat("x", 129) }},
		{"invalid reason", func(r *IncompleteReport) { r.ReasonCode = "NOT-ALLOWLISTED" }},
		{"negative component count", func(r *IncompleteReport) { r.ComponentCount = -1 }},
		{"excessive component count", func(r *IncompleteReport) { r.ComponentCount = MaxComponents + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := valid
			tc.mutate(&candidate)
			if _, err := root.WriteIncompleteReport(candidate); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestReportPublicationRollsBackOnSecondAndThirdWriteFailures(t *testing.T) {
	for _, failName := range []string{"report.sha256", "replay.json"} {
		t.Run(failName, func(t *testing.T) {
			root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "report"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.Close() })
			outputWriteFaultHook = func(name string) error {
				if name == failName {
					return errors.New("synthetic write failure")
				}
				return nil
			}
			t.Cleanup(func() { outputWriteFaultHook = nil })
			report := IncompleteReport{Now: "2026-08-26T00:00:00Z", ProposedBundleDigest: testDigest, PolicyDigest: testDigest, ComponentCount: 1}
			if _, err := root.WriteIncompleteReport(report); err == nil {
				t.Fatal("fault-injected report publication succeeded")
			}
			for _, name := range []string{"report.json", "report.sha256", "replay.json"} {
				if _, err := os.Stat(filepath.Join(root.Path(), name)); !os.IsNotExist(err) {
					t.Fatalf("public output %s remained after rollback: %v", name, err)
				}
			}
		})
	}
}

func TestOutputRoot_AtomicDirectoryPublicationAndPreCommitFaults(t *testing.T) {
	newReport := func(t *testing.T, path string) (OutputRoot, IncompleteReport) {
		t.Helper()
		root, err := PrepareOutputRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		report := IncompleteReport{Now: "2026-08-26T00:00:00Z", ProposedBundleDigest: testDigest, PolicyDigest: testDigest, ComponentCount: 1}
		return root, report
	}

	t.Run("directory rename fault leaves no public root", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report")
		root, report := newReport(t, path)
		defer root.Close()
		outputCommitHook = func(string) error { return errors.New("synthetic pre-commit failure") }
		defer func() { outputCommitHook = nil }()
		if _, err := root.WriteIncompleteReport(report); err == nil {
			t.Fatal("fault-injected commit succeeded")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("public root remained after pre-commit failure: %v", err)
		}
	})

	t.Run("successful commit publishes all files together", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report")
		root, report := newReport(t, path)
		defer root.Close()
		if _, err := root.WriteIncompleteReport(report); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 3 {
			t.Fatalf("published file count = %d, want 3", len(entries))
		}
		for _, name := range []string{"report.json", "report.sha256", "replay.json"} {
			if _, err := os.Stat(filepath.Join(path, name)); err != nil {
				t.Fatalf("published %s missing: %v", name, err)
			}
		}
	})
}

func TestOutputRoot_ConcurrentCreatorIsNeverReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	outputCommitHook = func(string) error {
		// This models another creator winning immediately before the atomic
		// publication primitive. The creator's bytes must survive unchanged.
		return os.WriteFile(path, []byte("external creator"), 0o600)
	}
	defer func() { outputCommitHook = nil }()
	report := IncompleteReport{Now: "2026-08-26T00:00:00Z", ProposedBundleDigest: testDigest, PolicyDigest: testDigest, ComponentCount: 1}
	if _, err := root.WriteIncompleteReport(report); err == nil {
		t.Fatal("publication succeeded over a concurrent creator")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "external creator" {
		t.Fatalf("concurrent creator was replaced: %q/%v", data, readErr)
	}
}

func TestOutputRoot_DarwinPerFileCreatorIsNeverRemoved(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin per-file publication primitive")
	}
	path := filepath.Join(t.TempDir(), "report")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	hookRan := false
	outputFileCommitHook = func(directory *os.File, name string) error {
		if name != "report.json" {
			return nil
		}
		hookRan = true
		creator, err := openRelativeExclusive(directory, name, 0o600)
		if err != nil {
			return err
		}
		if _, err := creator.Write([]byte("external creator")); err != nil {
			_ = creator.Close()
			return err
		}
		if err := creator.Sync(); err != nil {
			_ = creator.Close()
			return err
		}
		check, err := openRelativeFile(directory, name, 0, 0)
		if err != nil {
			_ = creator.Close()
			return err
		}
		checkData, err := io.ReadAll(check)
		_ = check.Close()
		if err != nil || string(checkData) != "external creator" {
			_ = creator.Close()
			return errors.New("creator write was not visible")
		}
		if err := creator.Close(); err != nil {
			return err
		}
		return errors.New("synthetic per-file creator race")
	}
	defer func() { outputFileCommitHook = nil }()
	report := IncompleteReport{Now: "2026-08-26T00:00:00Z", ProposedBundleDigest: testDigest, PolicyDigest: testDigest, ComponentCount: 1}
	if _, err := root.WriteIncompleteReport(report); err == nil {
		t.Fatal("publication succeeded over a concurrent per-file creator")
	}
	t.Logf("per-file hook ran=%v", hookRan)
	data, readErr := os.ReadFile(filepath.Join(path, "report.json"))
	if readErr != nil || string(data) != "external creator" {
		t.Fatalf("concurrent per-file creator was removed or replaced: %q/%v", data, readErr)
	}
}

func TestOutputRoot_PreCommitParentSyncFaultLeavesNoPublicRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	outputParentSyncHook = func(*os.File) error { return errors.New("synthetic parent fsync failure") }
	defer func() { outputParentSyncHook = nil }()
	if _, err := PrepareOutputRoot(path); err == nil {
		t.Fatal("fault-injected parent fsync succeeded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("public root remained after parent fsync failure: %v", err)
	}
}

func TestPublishExclusiveCanonicalFile_ParentReplacementIsRejected(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "receipts")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "receipt.json")
	exclusiveFilePublicationHook = func(path string) error {
		moved := path + "-moved"
		if err := os.Rename(path, moved); err != nil {
			return err
		}
		return os.Symlink(moved, path)
	}
	defer func() { exclusiveFilePublicationHook = nil }()
	if err := PublishExclusiveCanonicalFile(destination, []byte(`{"status":"UNKNOWN"}`)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("parent replacement error = %v, want ErrIntegrity", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("receipt was published through replaced parent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent+"-moved", "receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("receipt was published into replaced parent: %v", err)
	}
}

func TestPublishExclusiveCanonicalFile_FsyncFailureLeavesDurableVisibleReceipt(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "receipt.json")
	outputParentSyncHook = func(*os.File) error { return errors.New("synthetic crash-point fsync failure") }
	defer func() { outputParentSyncHook = nil }()
	if err := PublishExclusiveCanonicalFile(destination, []byte(`{"status":"UNKNOWN"}`)); !errors.Is(err, ErrIO) {
		t.Fatalf("parent fsync error = %v, want ErrIO", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("published receipt missing after fsync failure: %v", err)
	}
	if string(data) != "{\"status\":\"UNKNOWN\"}\n" {
		t.Fatalf("published receipt = %q", data)
	}
}

func TestIncompleteReportDigestHashesExactBytes(t *testing.T) {
	root, err := PrepareOutputRoot(filepath.Join(t.TempDir(), "report"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	report := IncompleteReport{Now: "2026-08-26T00:00:00Z", ProposedBundleDigest: testDigest, PolicyDigest: testDigest, ComponentCount: 1}
	digest, err := root.WriteIncompleteReport(report)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root.Path(), "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digest != DigestBytes(raw) {
		t.Fatalf("returned digest = %s, exact report digest = %s", digest, DigestBytes(raw))
	}
	checksum, err := os.ReadFile(filepath.Join(root.Path(), "report.sha256"))
	if err != nil || strings.TrimSpace(string(checksum)) != digest {
		t.Fatalf("checksum = %q, digest = %s, error = %v", checksum, digest, err)
	}
}

func TestOutputRootWriteRemainsAnchoredAfterPathReplacement(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	path := filepath.Join(parent, "report")
	root, err := PrepareOutputRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	moved := filepath.Join(parent, "moved-report")
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.Write("anchored.json", []byte("bound")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "anchored.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement path received output: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(moved, "anchored.json"))
	if err != nil || string(data) != "bound" {
		t.Fatalf("retained directory output = %q/%v", data, err)
	}
}

func TestReduceDecision_PrecedenceAndPassBoundary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input DecisionInput
		want  Decision
	}{
		{name: "verified applicable blocker outranks unknown", input: DecisionInput{Blockers: []VerifiedBlocker{{Verified: true, Applicable: true}}, UnknownEvidence: true}, want: DecisionBlocked},
		{name: "unverified blocker remains unknown", input: DecisionInput{Blockers: []VerifiedBlocker{{Verified: false, Applicable: true}}, RequiredEvidence: 1, VerifiedEvidence: 1, ApplicableEvidence: 1}, want: DecisionSafe},
		{name: "inapplicable blocker remains unknown", input: DecisionInput{Blockers: []VerifiedBlocker{{Verified: true, Applicable: false}}, RequiredEvidence: 1, VerifiedEvidence: 0}, want: DecisionUnknown},
		{name: "zero evidence is never vacuous safe", input: DecisionInput{}, want: DecisionUnknown},
		{name: "unknown outranks safe", input: DecisionInput{RequiredEvidence: 1, VerifiedEvidence: 0}, want: DecisionUnknown},
		{name: "complete applicable evidence is safe", input: DecisionInput{RequiredEvidence: 1, VerifiedEvidence: 1, ApplicableEvidence: 1}, want: DecisionSafe},
		{name: "pass cannot directly become safe", input: DecisionInput{TestRecords: []TestRecord{{Outcome: "PASS", Verified: true, Scoped: true}}}, want: DecisionUnknown},
		{name: "verified scoped pass supports safe", input: DecisionInput{RequiredEvidence: 1, VerifiedEvidence: 1, ApplicableEvidence: 1, TestsRequired: true, TestRecords: []TestRecord{{Outcome: "PASS", Verified: true, Scoped: true}}}, want: DecisionSafe},
		{name: "unverified pass remains unknown", input: DecisionInput{RequiredEvidence: 1, VerifiedEvidence: 1, ApplicableEvidence: 1, TestsRequired: true, TestRecords: []TestRecord{{Outcome: "PASS", Verified: false, Scoped: true}}}, want: DecisionUnknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReduceDecision(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("decision = %q, want %q", got, tc.want)
			}
		})
	}
}
