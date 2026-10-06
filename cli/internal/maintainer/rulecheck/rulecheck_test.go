// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realEntries loads every entry from a real published pack, so tests can
// mutate a genuine reviewed entry rather than a hand-built approximation.
func realEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Entries) == 0 {
		t.Fatalf("%s has no entries", path)
	}
	return doc.Entries
}

func firstRealEntry(t *testing.T) map[string]any {
	t.Helper()
	return clone(t, realEntries(t, filepath.Join("..", "..", "projectcheck", "data", "rules.json"))[0])
}

func clone(t *testing.T, entry map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	var copyOf map[string]any
	if err := json.Unmarshal(raw, &copyOf); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	return copyOf
}

func rule(entry map[string]any) map[string]any {
	return entry["rule"].(map[string]any)
}

func sources(entry map[string]any) []any {
	return rule(entry)["evidence"].(map[string]any)["sources"].([]any)
}

func candidateFile(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal candidate file: %v", err)
	}
	return raw
}

func setRuleID(t *testing.T, entry map[string]any, id string) {
	t.Helper()
	rule(entry)["id"] = id
}

// --- Valid fixture -----------------------------------------------------

func TestValidate_ValidFixtureCopiedFromRealRule(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke-test.valid-fixture.1-0-0-to-2-0-0")
	result, err := Validate(candidateFile(t, entry), Options{})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected a valid fixture copied from a real rule to validate cleanly, findings: %+v", result.Findings)
	}
}

// --- Failing cases, one per offline check -------------------------------

func TestValidate_UnknownFieldRejected(t *testing.T) {
	raw := []byte(`[{"project":"x","description":"d","requiredFacts":[],"rule":{},"extra":"nope"}]`)
	if _, err := Validate(raw, Options{}); err == nil {
		t.Fatal("expected an error for an unknown top-level field")
	}
}

func TestValidate_RuleIDPattern(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "Not_A_Valid_ID!!")
	assertFinding(t, entry, "rule-id")
}

func TestValidate_RevisionNot40Hex(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.bad-revision.1-0-0-to-2-0-0")
	sources(entry)[0].(map[string]any)["revision"] = "not-hex"
	assertFinding(t, entry, "revision")
}

func TestValidate_URLNotGitHubBlob(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.bad-url.1-0-0-to-2-0-0")
	source := sources(entry)[0].(map[string]any)
	source["url"] = "https://example.com/not/a/blob/url"
	assertFinding(t, entry, "url")
}

func TestValidate_URLCommitMismatch(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.url-mismatch.1-0-0-to-2-0-0")
	source := sources(entry)[0].(map[string]any)
	source["revision"] = "111111111111111111111111111111111111111a"
	assertFinding(t, entry, "url")
}

func TestValidate_StartLineAfterEndLine(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.bad-lines.1-0-0-to-2-0-0")
	source := sources(entry)[0].(map[string]any)
	source["startLine"] = 50
	source["endLine"] = 10
	assertFinding(t, entry, "line-range")
}

func TestValidate_NextActionOverLimitOrControlChars(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.bad-next-action.1-0-0-to-2-0-0")
	rule(entry)["nextAction"] = strings.Repeat("a", 300)
	assertFinding(t, entry, "next-action")
}

func TestValidate_NextActionControlCharacter(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.control-char.1-0-0-to-2-0-0")
	rule(entry)["nextAction"] = "line one\x01line two"
	assertFinding(t, entry, "next-action")
}

func TestValidate_VersionNotStrictSemver(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.bad-semver.1-0-0-to-2-0-0")
	rule(entry)["subject"].(map[string]any)["from"] = "v1.0"
	assertFinding(t, entry, "version")
}

func TestValidate_FromEqualsTo(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.same-version.1-0-0-to-1-0-0")
	subject := rule(entry)["subject"].(map[string]any)
	subject["to"] = subject["from"]
	assertFinding(t, entry, "version")
}

func TestValidate_ConditionFactNotInRequiredFacts(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.missing-fact.1-0-0-to-2-0-0")
	rule(entry)["condition"].(map[string]any)["factId"] = "component.argo-workflows.never_declared"
	assertFinding(t, entry, "fact-reference")
}

// TestValidate_CommunityContributionRejectsWithdrawnEvidence: a brand-new
// community candidate must always declare active evidence. Submitting a
// rule that is already withdrawn makes no sense, so the default (community)
// mode refuses it.
func TestValidate_CommunityContributionRejectsWithdrawnEvidence(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.withdrawn.1-0-0-to-2-0-0")
	rule(entry)["evidence"].(map[string]any)["state"] = "withdrawn"
	assertFinding(t, entry, "evidence-state")
}

// TestValidate_MaintainerSelfCheckAcceptsWithdrawnEvidence: a rule already
// published may later be withdrawn (unverifiable evidence discovered after
// publication). The maintainer self-check against an already-published pack
// (AllowRange: true, mirroring the range distinction above) accepts it.
func TestValidate_MaintainerSelfCheckAcceptsWithdrawnEvidence(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.withdrawn.1-0-0-to-2-0-0")
	rule(entry)["evidence"].(map[string]any)["state"] = "withdrawn"
	result, err := Validate(candidateFile(t, entry), Options{AllowRange: true})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	for _, f := range result.Findings {
		if f.Check == "evidence-state" {
			t.Fatalf("expected no evidence-state finding for a maintainer self-check of withdrawn evidence, got: %+v", result.Findings)
		}
	}
}

func TestValidate_RuleIDCollidesWithExistingPack(t *testing.T) {
	entry := firstRealEntry(t) // keeps the real, already-published rule id
	packPath := filepath.Join("..", "..", "projectcheck", "data", "rules.json")
	result, err := Validate(candidateFile(t, entry), Options{ExistingRulesPaths: []string{packPath}})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if result.Valid {
		t.Fatal("expected a collision finding for a rule id that already exists in the published pack")
	}
	found := false
	for _, f := range result.Findings {
		if f.Check == "rule-id-collision" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a rule-id-collision finding, got: %+v", result.Findings)
	}
}

func TestValidate_RuleIDCollidesWithinSameBatch(t *testing.T) {
	entryA := firstRealEntry(t)
	setRuleID(t, entryA, "smoke.duplicate.1-0-0-to-2-0-0")
	entryB := firstRealEntry(t)
	setRuleID(t, entryB, "smoke.duplicate.1-0-0-to-2-0-0")
	result, err := Validate(candidateFile(t, entryA, entryB), Options{})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if result.Valid {
		t.Fatal("expected a collision finding for two candidate entries sharing a rule id")
	}
}

func TestValidate_ReasonCodePattern(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.bad-reason-code.1-0-0-to-2-0-0")
	rule(entry)["reasonCode"] = "not_upper_case"
	assertFinding(t, entry, "reason-code")
}

func TestValidate_ContentDigestShape(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.bad-digest.1-0-0-to-2-0-0")
	sources(entry)[0].(map[string]any)["contentDigest"] = "md5:deadbeef"
	assertFinding(t, entry, "content-digest")
}

func TestValidate_EmptyCandidateFile(t *testing.T) {
	if _, err := Validate([]byte(`[]`), Options{}); err == nil {
		t.Fatal("expected an error for a candidate file with zero entries")
	}
}

func assertFinding(t *testing.T, entry map[string]any, check string) {
	t.Helper()
	result, err := Validate(candidateFile(t, entry), Options{})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if result.Valid {
		t.Fatalf("expected a %q finding, got none", check)
	}
	for _, f := range result.Findings {
		if f.Check == check {
			return
		}
	}
	t.Fatalf("expected a finding with check %q, got: %+v", check, result.Findings)
}

// --- Table test: every real published entry validates cleanly ----------

func TestValidate_EveryPublishedEntryValidatesCleanly(t *testing.T) {
	for _, packPath := range []string{
		filepath.Join("..", "..", "projectcheck", "data", "rules.json"),
		filepath.Join("..", "..", "cncfcheck", "data", "rules.json"),
	} {
		packPath := packPath
		t.Run(packPath, func(t *testing.T) {
			for i, entry := range realEntries(t, packPath) {
				entry := entry
				name := fmt.Sprintf("entry-%d", i)
				if id, ok := rule(entry)["id"].(string); ok {
					name = id
				}
				t.Run(name, func(t *testing.T) {
					// ExistingRulesPaths deliberately omitted: this proves each
					// entry's own structure and evidence are well-formed, not
					// that it is unique against the pack it was taken from.
					// AllowRange: true because this is the maintainer's own
					// self-check against already-published, reviewed packs,
					// which may carry a range; the public CLI a community
					// contributor runs never sets it.
					result, err := Validate(candidateFile(t, entry), Options{AllowRange: true})
					if err != nil {
						t.Fatalf("Validate returned error: %v", err)
					}
					if !result.Valid {
						t.Fatalf("real published entry did not validate cleanly: %+v", result.Findings)
					}
				})
			}
		})
	}
}

// --- Range: community-contribution refusal, maintainer self-check accepts --

// firstRangedEntry returns the first entry in the cncfcheck pack that
// carries a rule.range, so tests exercise a genuine reviewed range rather
// than a hand-built approximation.
func firstRangedEntry(t *testing.T) map[string]any {
	t.Helper()
	for _, entry := range realEntries(t, filepath.Join("..", "..", "cncfcheck", "data", "rules.json")) {
		if _, ok := rule(entry)["range"]; ok {
			return clone(t, entry)
		}
	}
	t.Fatal("cncfcheck rules.json has no entry with a range")
	return nil
}

// A community contribution may carry a range only in the validated
// release-boundary shape; the published reviewed range has exactly that shape.
func TestValidate_CommunityContributionAcceptsWellFormedRange(t *testing.T) {
	result, err := Validate(candidateFile(t, firstRangedEntry(t)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("well-formed cited range rejected: %+v", result.Findings)
	}
}

func TestValidate_CommunityRangeRejections(t *testing.T) {
	bound := func(rng map[string]any, i int) map[string]any { return rng["bounds"].([]any)[i].(map[string]any) }
	side := func(rng map[string]any, name string) map[string]any { return rng[name].(map[string]any) }
	setBases := func(rng map[string]any, bases ...string) {
		for i, b := range bases {
			bound(rng, i)["basis"] = b
		}
	}
	type mutation struct {
		fragment   string // must appear in a Check=="range" finding (or the engine finding for engineOnly)
		engineOnly bool   // the engine, not the contribution gate, owns this rule
		gateOnly   bool   // the engine accepts it; only the gate rejects it
		mutate     func(rng map[string]any)
	}
	cases := map[string]mutation{
		"open-ended: empty to.lt":       {fragment: "open-ended", mutate: func(rng map[string]any) { side(rng, "to")["lt"] = "" }},
		"open-ended: empty from.gte":    {fragment: "open-ended", mutate: func(rng map[string]any) { side(rng, "from")["gte"] = "" }},
		"open-ended: wildcard":          {fragment: "open-ended", mutate: func(rng map[string]any) { side(rng, "to")["lt"] = "*" }},
		"open-ended: pre-release":       {fragment: "open-ended", mutate: func(rng map[string]any) { side(rng, "to")["lt"] = "1.23.0-rc.1" }},
		"uncited: empty source":         {fragment: "uncited", mutate: func(rng map[string]any) { bound(rng, 2)["sourceId"] = "" }},
		"uncited: source not in rule":   {fragment: "uncited", mutate: func(rng map[string]any) { bound(rng, 3)["sourceId"] = "invented-source" }},
		"uncited: bounds missing":       {fragment: "cite all four", mutate: func(rng map[string]any) { rng["bounds"] = []any{} }},
		"boundary not a release basis":  {fragment: "REMOVED_IN_RELEASE or CHANGED_IN_RELEASE", mutate: func(rng map[string]any) { bound(rng, 1)["basis"] = "UPGRADE_FROM_SERIES" }},
		"boundary bases differ":         {fragment: "REMOVED_IN_RELEASE or CHANGED_IN_RELEASE", mutate: func(rng map[string]any) { bound(rng, 2)["basis"] = "CHANGED_IN_RELEASE" }},
		"from.lt and to.gte differ":     {fragment: "same change version", mutate: func(rng map[string]any) { side(rng, "from")["lt"] = "1.21.5" }},
		"anchor outside range":          {fragment: "anchor", mutate: func(rng map[string]any) { side(rng, "from")["gte"] = "1.21.1" }},
		"wider than one minor per side": {fragment: "wider than one minor", engineOnly: true, mutate: func(rng map[string]any) { side(rng, "to")["lt"] = "1.25.0" }},
		"series shape on all four bounds (no release C)": {fragment: "REMOVED_IN_RELEASE or CHANGED_IN_RELEASE", gateOnly: true, mutate: func(rng map[string]any) {
			setBases(rng, "UPGRADE_FROM_SERIES", "UPGRADE_FROM_SERIES", "TARGET_SERIES", "TARGET_SERIES")
		}},
		"ANCHOR_ONLY on all four bounds": {fragment: "REMOVED_IN_RELEASE or CHANGED_IN_RELEASE", gateOnly: true, mutate: func(rng map[string]any) {
			setBases(rng, "ANCHOR_ONLY", "ANCHOR_ONLY", "ANCHOR_ONLY", "ANCHOR_ONLY")
			side(rng, "from")["gte"], side(rng, "from")["lt"] = "1.21.0", "1.21.1"
			side(rng, "to")["gte"], side(rng, "to")["lt"] = "1.22.0", "1.22.1"
		}},
	}
	for name, c := range cases {
		entry := firstRangedEntry(t)
		c.mutate(rule(entry)["range"].(map[string]any))
		result, err := Validate(candidateFile(t, entry), Options{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if result.Valid {
			t.Errorf("%s: mutated community range was accepted", name)
			continue
		}
		var gate, engine bool
		for _, f := range result.Findings {
			if f.Check == "range" && strings.Contains(f.Message, c.fragment) {
				gate = true
			}
			if f.Check == "engine-rejected" {
				engine = true
			}
		}
		switch {
		case c.engineOnly && (!engine || gate):
			t.Errorf("%s: want engine-only rejection, gate=%v engine=%v: %+v", name, gate, engine, result.Findings)
		case !c.engineOnly && !gate:
			t.Errorf("%s: no range finding containing %q: %+v", name, c.fragment, result.Findings)
		case c.gateOnly && engine:
			t.Errorf("%s: expected the gate alone to reject, engine also did: %+v", name, result.Findings)
		}
	}
}

func TestValidate_MaintainerSelfCheckAcceptsPublishedRange(t *testing.T) {
	entry := firstRangedEntry(t)
	result, err := Validate(candidateFile(t, entry), Options{AllowRange: true})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected a real published ranged entry to validate cleanly with AllowRange, findings: %+v", result.Findings)
	}
}

// --- Online (--fetch) path, injected fetcher only -----------------------

type fakeFetcher struct {
	content map[string][]byte
	err     map[string]error
}

func (f fakeFetcher) FetchRawBlob(_ context.Context, rawURL string) ([]byte, error) {
	if err, ok := f.err[rawURL]; ok {
		return nil, err
	}
	if content, ok := f.content[rawURL]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("fakeFetcher: no fixture for %s", rawURL)
}

func TestValidate_FetchDigestMatches(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.fetch-ok.1-0-0-to-2-0-0")
	source := sources(entry)[0].(map[string]any)
	source["url"] = "https://github.com/example/repo/blob/111111111111111111111111111111111111111a/file.go"
	source["revision"] = "111111111111111111111111111111111111111a"
	content := []byte("line1\nline2\nline3\n")
	source["contentDigest"] = digestOf(content)
	source["startLine"] = 1
	source["endLine"] = 2

	fetcher := fakeFetcher{content: map[string][]byte{
		"https://raw.githubusercontent.com/example/repo/111111111111111111111111111111111111111a/file.go": content,
	}}
	result, err := Validate(candidateFile(t, entry), Options{Fetch: true, Fetcher: fetcher})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	for _, f := range result.Findings {
		if f.Check == "content-digest-mismatch" || f.Check == "line-range-fetched" {
			t.Fatalf("unexpected online finding for a matching fixture: %+v", f)
		}
	}
}

func TestValidate_FetchDigestMismatch(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.fetch-mismatch.1-0-0-to-2-0-0")
	source := sources(entry)[0].(map[string]any)
	source["url"] = "https://github.com/example/repo/blob/222222222222222222222222222222222222222b/file.go"
	source["revision"] = "222222222222222222222222222222222222222b"
	source["contentDigest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	source["startLine"] = 1
	source["endLine"] = 1

	fetcher := fakeFetcher{content: map[string][]byte{
		"https://raw.githubusercontent.com/example/repo/222222222222222222222222222222222222222b/file.go": []byte("actual content\n"),
	}}
	result, err := Validate(candidateFile(t, entry), Options{Fetch: true, Fetcher: fetcher})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Check == "content-digest-mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a content-digest-mismatch finding, got: %+v", result.Findings)
	}
}

func TestValidate_FetchEndLineExceedsFileLength(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.fetch-overrun.1-0-0-to-2-0-0")
	source := sources(entry)[0].(map[string]any)
	source["url"] = "https://github.com/example/repo/blob/333333333333333333333333333333333333333c/file.go"
	source["revision"] = "333333333333333333333333333333333333333c"
	content := []byte("only one line\n")
	source["contentDigest"] = digestOf(content)
	source["startLine"] = 1
	source["endLine"] = 5

	fetcher := fakeFetcher{content: map[string][]byte{
		"https://raw.githubusercontent.com/example/repo/333333333333333333333333333333333333333c/file.go": content,
	}}
	result, err := Validate(candidateFile(t, entry), Options{Fetch: true, Fetcher: fetcher})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Check == "line-range-fetched" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a line-range-fetched finding, got: %+v", result.Findings)
	}
}

func TestValidate_FetchFailurePropagatesAsFinding(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.fetch-failure.1-0-0-to-2-0-0")
	source := sources(entry)[0].(map[string]any)
	source["url"] = "https://github.com/example/repo/blob/444444444444444444444444444444444444444d/file.go"
	source["revision"] = "444444444444444444444444444444444444444d"

	fetcher := fakeFetcher{err: map[string]error{
		"https://raw.githubusercontent.com/example/repo/444444444444444444444444444444444444444d/file.go": fmt.Errorf("404 not found"),
	}}
	result, err := Validate(candidateFile(t, entry), Options{Fetch: true, Fetcher: fetcher})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.Check == "fetch-failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a fetch-failed finding, got: %+v", result.Findings)
	}
}

func TestValidate_OfflineDefaultNeverCallsFetcher(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.offline-default.1-0-0-to-2-0-0")
	result, err := Validate(candidateFile(t, entry), Options{})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected offline validation to pass without a fetcher: %+v", result.Findings)
	}
}

// TestValidate_RangeNotAcceptedInContributions: a reviewed version range is
// a maintainer-reviewed widening, never part of a community candidate. The
// default (community) mode refuses the field with a clear, actionable
// message, rather than the engine's own generic rejection.
func TestValidate_RangeNotAcceptedInContributions(t *testing.T) {
	entry := firstRealEntry(t)
	setRuleID(t, entry, "smoke.ranged.1-0-0-to-2-0-0")
	rule(entry)["range"] = map[string]any{
		"from":   map[string]any{"gte": "1.0.0", "lt": "1.1.0"},
		"to":     map[string]any{"gte": "2.0.0", "lt": "2.1.0"},
		"bounds": []any{},
	}
	assertFinding(t, entry, "range")
}

// --- Evidence basis ------------------------------------------------------

const basisCodeDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func setMechanical(entry map[string]any) {
	evidence := rule(entry)["evidence"].(map[string]any)
	evidence["basis"] = "mechanical"
	evidence["extractor"] = map[string]any{"id": "example.removal", "version": "1.0.0", "codeDigest": basisCodeDigest}
	evidence["derivedAt"] = evidence["reviewedAt"]
}

func basisFindings(t *testing.T, entry map[string]any, opts Options) []Finding {
	t.Helper()
	result, err := Validate(candidateFile(t, entry), opts)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	var out []Finding
	for _, f := range result.Findings {
		if f.Check == "evidence-basis" || f.Check == "engine-rejected" || f.Check == "rule-schema" {
			out = append(out, f)
		}
	}
	return out
}

func TestValidate_EvidenceBasisTable(t *testing.T) {
	for _, test := range []struct {
		name       string
		mutate     func(map[string]any)
		maintainer bool
		wantClean  bool
	}{
		{"reviewed explicit, community", func(e map[string]any) { rule(e)["evidence"].(map[string]any)["basis"] = "reviewed" }, false, true},
		{"mechanical, maintainer self-check", setMechanical, true, true},
		{"mechanical, community contribution", setMechanical, false, false},
		{"unknown basis", func(e map[string]any) { rule(e)["evidence"].(map[string]any)["basis"] = "automatic" }, true, false},
		{"mechanical without extractor", func(e map[string]any) {
			setMechanical(e)
			delete(rule(e)["evidence"].(map[string]any), "extractor")
		}, true, false},
		{"mechanical without derivedAt", func(e map[string]any) {
			setMechanical(e)
			delete(rule(e)["evidence"].(map[string]any), "derivedAt")
		}, true, false},
		{"extractor without mechanical basis", func(e map[string]any) {
			setMechanical(e)
			delete(rule(e)["evidence"].(map[string]any), "basis")
		}, true, false},
		{"bad extractor digest", func(e map[string]any) {
			setMechanical(e)
			rule(e)["evidence"].(map[string]any)["extractor"].(map[string]any)["codeDigest"] = "sha256:abc"
		}, true, false},
		{"unknown extractor key", func(e map[string]any) {
			setMechanical(e)
			rule(e)["evidence"].(map[string]any)["extractor"].(map[string]any)["extra"] = "x"
		}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			entry := firstRealEntry(t)
			setRuleID(t, entry, "smoke.basis.1-0-0-to-2-0-0")
			test.mutate(entry)
			findings := basisFindings(t, entry, Options{AllowRange: test.maintainer})
			if test.wantClean && len(findings) != 0 {
				t.Fatalf("unexpected findings: %+v", findings)
			}
			if !test.wantClean && len(findings) == 0 {
				t.Fatal("expected a finding")
			}
		})
	}
}
