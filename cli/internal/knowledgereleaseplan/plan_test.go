// SPDX-License-Identifier: AGPL-3.0-only

package knowledgereleaseplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestPlanCanonicalRoundTripAndAssertions(t *testing.T) {
	plan := validPlan()
	first, err := Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Marshal(plan)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("non-deterministic plan: equal=%t err=%v", bytes.Equal(first, second), err)
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	assertions := parsed.VerificationAssertions()
	if assertions.PublisherInitialRootDigest != testDigest || assertions.TargetPath != knowledge.ConstraintsTargetPath || assertions.Purpose != "operator_provided" || assertions.EngineCapabilityDigest != testDigest || len(assertions.RootHistory) != 1 {
		t.Fatalf("lost verification assertions: %+v", assertions)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err != nil {
		t.Fatal(err)
	}
}

func TestPlanRejectsOpenNonCanonicalAndInvalidInputs(t *testing.T) {
	valid, err := Marshal(validPlan())
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(*Plan)) []byte {
		p := validPlan()
		change(&p)
		raw, _ := json.Marshal(p)
		return raw
	}
	tests := map[string][]byte{
		"duplicate": bytes.Replace(valid, []byte(`"schema":`), []byte(`"schema":"prufyx.io/knowledge-release-plan/v1","schema":`), 1),
		"unknown":   append(valid[:len(valid)-1], []byte(`,"unexpected":true}`)...),
		"spacing":   append([]byte(" "), valid...),
		"trailing":  append(append([]byte(nil), valid...), '\n'),
		"oversized": bytes.Repeat([]byte{'x'}, MaxBytes+1),
		"profile":   mutate(func(p *Plan) { p.Profile = "cert-manager" }),
		"authority": mutate(func(p *Plan) { p.Authority = "TRUSTED" }),
		"url query": mutate(func(p *Plan) { p.Package.URL += "?secret=value" }),
		"rotation": mutate(func(p *Plan) {
			p.PublisherVerification.RootHistory = append(p.PublisherVerification.RootHistory, knowledge.RootHistoryEntry{Version: 2, Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
		}),
		"wrong target path": mutate(func(p *Plan) { p.Target.Path = "knowledge/other.json" }),
		"invalid expiry":    mutate(func(p *Plan) { p.PublisherVerification.Timestamp.Expires = "2030-01-01T00:00:00+00:00" }),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); !errors.Is(err, ErrRejected) {
				t.Fatalf("Parse accepted rejected input: %v", err)
			}
		})
	}
}

func TestPlanReadRejectsNonRegularAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(dir); !errors.Is(err, ErrRejected) {
		t.Fatalf("directory accepted: %v", err)
	}
	large := filepath.Join(dir, "large.json")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", MaxBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(large); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized file accepted: %v", err)
	}
}

func validPlan() Plan {
	role := knowledge.RoleReceipt{Version: 1, Digest: testDigest, Expires: "2030-01-01T00:00:00Z"}
	return Plan{
		Schema:    Schema,
		Authority: Authority,
		Profile:   "cncf",
		Package:   Package{URL: "https://metadata.example.test/knowledge.tar", Digest: testDigest},
		Target: Target{
			Path: knowledge.ConstraintsTargetPath, Revision: "1", Digest: testDigest,
			Purpose: "operator_provided", EngineCapabilityDigest: testDigest,
		},
		PublisherVerification: PublisherVerification{
			Mode: RootMode, PublisherInitialRootDigest: testDigest,
			RootHistory: []knowledge.RootHistoryEntry{{Version: 1, Digest: testDigest}},
			Root:        role, Timestamp: role, Snapshot: role, Targets: role,
		},
	}
}
