// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// futureFeed turns the embedded per-project feed into a synthetic feed from
// a later release: one fact that a reviewed rule of project reads is
// renamed to a fact this build never registered, the capability digest is
// another one, and the index lists one project this build does not know.
// The base capability is this build's, as a later release of the same
// engine contract and policy would carry it.
type futureFeed struct {
	index    []byte
	targets  map[string][]byte
	project  string
	ruleID   string
	oldFact  string
	newFact  string
	input    json.RawMessage
	unknown  string
	capacity string
}

func buildFutureFeed(t *testing.T) futureFeed {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	index, targets := buildSplit(t, "9")
	feed := futureFeed{targets: map[string][]byte{}, unknown: "zz-future-project"}
	for _, vector := range reviewedVectors(t) {
		for _, entry := range base.pack.Entries {
			id, _ := ruleEntryID(entry)
			if entry.Project == vector.Project && id == vector.RuleID && len(entry.RequiredFacts) > 0 && len(vector.Cases) > 0 {
				feed.project, feed.ruleID, feed.oldFact = entry.Project, id, entry.RequiredFacts[0].ID
				feed.input = vector.Cases[0].Input
			}
		}
		if feed.project != "" {
			break
		}
	}
	if feed.project == "" {
		t.Fatal("no reviewed rule with a required fact")
	}
	feed.newFact = feed.oldFact + "_future"
	feed.capacity = digest([]byte("a later engine capability"))
	oldCapability, err := externalCapabilityDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	for project, raw := range targets {
		if project == feed.project {
			raw = bytes.ReplaceAll(raw, []byte(`"`+feed.oldFact+`"`), []byte(`"`+feed.newFact+`"`))
		}
		feed.targets[project] = bytes.ReplaceAll(raw, []byte(oldCapability), []byte(feed.capacity))
	}
	var document externalIndexDocument
	if err := json.Unmarshal(index.Bytes, &document); err != nil {
		t.Fatal(err)
	}
	document.EngineCapabilityDigest, document.BaseCapabilityDigest = feed.capacity, baseCapabilityDigest(base)
	for i, entry := range document.Projects {
		raw := feed.targets[entry.Project]
		document.Projects[i].Length, document.Projects[i].Digest = int64(len(raw)), digest(raw)
	}
	unknownBytes := []byte(`{"a":"target of a project this build does not know"}`)
	feed.targets[feed.unknown] = unknownBytes
	document.Projects = append(document.Projects, ExternalIndexEntry{Project: feed.unknown, TargetPath: ProjectTargetPath(feed.unknown), Revision: "9", Length: int64(len(unknownBytes)), Digest: digest(unknownBytes), RuleDigest: digest([]byte("r")), EvidenceExpiresAt: "2027-01-01T00:00:00Z"})
	feed.index, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return feed
}

// TestFutureFeedIsReadInCompatMode: a signed feed that registers a fact this
// build does not know and lists a project it does not know is read; the rule
// that needs the fact is deferred, the unknown project is not read, and every
// other project is admitted exactly as before.
func TestFutureFeedIsReadInCompatMode(t *testing.T) {
	t.Parallel()
	feed := buildFutureFeed(t)
	index, err := ParseExternalIndex(feed.index)
	if err != nil {
		t.Fatalf("future index: %v", err)
	}
	if !index.Compat() || index.Readable(feed.unknown) || !index.Readable(feed.project) {
		t.Fatalf("compat %v, unknown readable %v", index.Compat(), index.Readable(feed.unknown))
	}
	if _, err := AdmitExternalProjectTarget(index, feed.unknown, feed.targets[feed.unknown]); !errors.Is(err, ErrUnreadableTarget) {
		t.Fatalf("unknown project target: %v", err)
	}
	deferred := 0
	for _, entry := range index.Entries() {
		if !index.Readable(entry.Project) {
			continue
		}
		bundle, err := AdmitExternalProjectTarget(index, entry.Project, feed.targets[entry.Project])
		if err != nil {
			t.Fatalf("%s: %v", entry.Project, err)
		}
		if (entry.Project == feed.project) != bundle.hasDeferred() {
			t.Fatalf("%s: deferred %v", entry.Project, bundle.hasDeferred())
		}
		for _, rule := range bundle.DeferredRules() {
			deferred++
			if len(rule.MissingFacts) != 1 || rule.MissingFacts[0] != feed.newFact {
				t.Fatalf("deferred %+v", rule)
			}
		}
	}
	if deferred == 0 {
		t.Fatal("no rule was deferred")
	}
	// The exact readers still refuse the same bytes.
	if _, err := ParseExternalBundle(feed.targets[feed.project]); !errors.Is(err, ErrCapabilityMismatch) {
		t.Fatalf("exact parse of a future target: %v", err)
	}
}

// TestDeferredRuleNeverProducesAClaim: the rule whose fact the build cannot
// evaluate yields no claim, so no PASS, and the report says it was not
// evaluated; the unmodified feed gives the claim.
func TestDeferredRuleNeverProducesAClaim(t *testing.T) {
	t.Parallel()
	feed := buildFutureFeed(t)
	now := reviewClock(t)
	index, err := ParseExternalIndex(feed.index)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := AdmitExternalProjectTarget(index, feed.project, feed.targets[feed.project])
	if err != nil {
		t.Fatal(err)
	}
	report, err := bundle.EvaluateRule(feed.project, feed.ruleID, feed.input, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Claims) != 0 || report.Assessment != "UNKNOWN" || len(report.DeferredRules) == 0 || !strings.HasPrefix(report.NextAction, deferredNextAction) {
		t.Fatalf("deferred rule report: claims %d, deferred %v, next %q", len(report.Check.Claims), report.DeferredRules, report.NextAction)
	}
	if _, err := MarshalReport(report); err != nil {
		t.Fatalf("report refused: %v", err)
	}
	_, plain := buildSplit(t, "9")
	exact, err := ParseExternalBundle(plain[feed.project])
	if err != nil {
		t.Fatal(err)
	}
	control, err := exact.EvaluateRule(feed.project, feed.ruleID, feed.input, now)
	if err != nil || len(control.Check.Claims) == 0 || len(control.DeferredRules) != 0 {
		t.Fatalf("control: %v, claims %d", err, len(control.Check.Claims))
	}
}

// TestCompatModeRefusals: compat mode relaxes the registry and the project
// list only. A different engine contract or policy, an index without the
// base marker, a target of another capability than its index, a target whose
// bytes differ from the signed identity, a malformed future entry and a
// future fact in an exact read are all refused.
func TestCompatModeRefusals(t *testing.T) {
	t.Parallel()
	feed := buildFutureFeed(t)
	reindex := func(mutate func(*externalIndexDocument)) []byte {
		return reencodeIndex(t, feed.index, mutate)
	}
	for name, raw := range map[string][]byte{
		"another base capability": reindex(func(d *externalIndexDocument) { d.BaseCapabilityDigest = digest([]byte("another engine")) }),
		"no base marker":          reindex(func(d *externalIndexDocument) { d.BaseCapabilityDigest = "" }),
		"unknown project with a path of another project": reindex(func(d *externalIndexDocument) {
			d.Projects[len(d.Projects)-1].TargetPath = ProjectTargetPath("zz-other")
		}),
		"unknown project marked community on a cncf path": reindex(func(d *externalIndexDocument) {
			d.Projects[len(d.Projects)-1].Catalog = CatalogCommunity
		}),
	} {
		if _, err := ParseExternalIndex(raw); err == nil {
			t.Errorf("%s: index admitted", name)
		}
	}
	if _, err := ParseExternalIndex(reindex(func(d *externalIndexDocument) { d.BaseCapabilityDigest = digest([]byte("x")) })); !errors.Is(err, ErrCapabilityMismatch) {
		t.Errorf("another base: %v", err)
	}
	index, err := ParseExternalIndex(feed.index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitExternalProjectTarget(index, feed.project, append(append([]byte(nil), feed.targets[feed.project]...), ' ')); !errors.Is(err, ErrIntegrity) {
		t.Errorf("tampered target: %v", err)
	}
	otherCapability := bytes.ReplaceAll(feed.targets[feed.project], []byte(feed.capacity), []byte(digest([]byte("yet another capability"))))
	reentry := reencodeIndex(t, feed.index, func(d *externalIndexDocument) {
		for i := range d.Projects {
			if d.Projects[i].Project == feed.project {
				d.Projects[i].Length, d.Projects[i].Digest = int64(len(otherCapability)), digest(otherCapability)
			}
		}
	})
	relabelled, err := ParseExternalIndex(reentry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitExternalProjectTarget(relabelled, feed.project, otherCapability); !errors.Is(err, ErrIntegrity) {
		t.Errorf("target of another capability than its index: %v", err)
	}
	// An exact index (this build's own capability) never defers: the same
	// unknown fact is an invalid target there.
	exactIndex, exactTargets := buildSplit(t, "9")
	parsed, err := ParseExternalIndex(exactIndex.Bytes)
	if err != nil || parsed.Compat() {
		t.Fatalf("own index: %v compat %v", err, parsed.Compat())
	}
	mutated := bytes.ReplaceAll(exactTargets[feed.project], []byte(`"`+feed.oldFact+`"`), []byte(`"`+feed.newFact+`"`))
	if _, err := ParseExternalBundle(mutated); err == nil {
		t.Error("exact read admitted an unregistered fact")
	}
}

// TestStoreScanKnowledgeDropsProjectWithDeferredRule: a scan could pass a
// hop only because the rule that blocks it is missing, so a project holding
// a deferred rule has no scan knowledge from the store.
func TestStoreScanKnowledgeDropsProjectWithDeferredRule(t *testing.T) {
	t.Parallel()
	feed := buildFutureFeed(t)
	index, err := ParseExternalIndex(feed.index)
	if err != nil {
		t.Fatal(err)
	}
	bundles := map[string]ExternalBundle{}
	for _, entry := range index.Entries() {
		if !index.Readable(entry.Project) || entry.Project == feed.project || len(bundles) > 0 {
			continue
		}
		bundle, err := AdmitExternalProjectTarget(index, entry.Project, feed.targets[entry.Project])
		if err != nil {
			t.Fatal(err)
		}
		bundles[entry.Project] = bundle
	}
	bundles[feed.project], err = AdmitExternalProjectTarget(index, feed.project, feed.targets[feed.project])
	if err != nil {
		t.Fatal(err)
	}
	knowledge, err := NewStoreScanKnowledge(bundles)
	if err != nil {
		t.Fatal(err)
	}
	if len(knowledge.rules[feed.project]) != 0 || len(knowledge.selected) != len(bundles)-1 {
		t.Fatalf("project with a deferred rule kept scan knowledge: %d rules, %d/%d selected", len(knowledge.rules[feed.project]), len(knowledge.selected), len(bundles))
	}
}
