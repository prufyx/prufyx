// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func changedFutureTarget(t *testing.T, feed futureFeed, mutate func(*externalFixtureDocument)) (ExternalIndex, []byte) {
	t.Helper()
	var target externalFixtureDocument
	if err := json.Unmarshal(feed.targets[feed.project], &target); err != nil {
		t.Fatal(err)
	}
	mutate(&target)
	raw, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	indexRaw := reencodeIndex(t, feed.index, func(d *externalIndexDocument) {
		for i := range d.Projects {
			if d.Projects[i].Project == feed.project {
				d.Projects[i].Length = int64(len(raw))
				d.Projects[i].Digest = digest(raw)
			}
		}
	})
	index, err := ParseExternalIndex(indexRaw)
	if err != nil {
		t.Fatal(err)
	}
	return index, raw
}

func TestForwardWholeSemanticDigestCannotBeWaived(t *testing.T) {
	feed := buildFutureFeed(t)
	index, err := ParseExternalIndex(feed.index)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AdmitExternalProjectTarget(index, feed.project, feed.targets[feed.project])
	if err != nil {
		t.Fatal(err)
	}
	admission, err := b.Admission()
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := index.Entry(feed.project)
	if admission.RuleDigest != entry.RuleDigest || !b.hasDeferred() {
		t.Fatal("whole target not bound")
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	base.pack = b.pack
	base.registry = b.registry
	parsed, err := base.parseRulesCorpus(base.packRules(), nil)
	if err != nil {
		t.Fatal(err)
	}
	subset, err := parsed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if b.admission.HasRecords {
		subset, err = knowledgeContentDigest(subset, b.pack)
		if err != nil {
			t.Fatal(err)
		}
	}
	if subset == entry.RuleDigest {
		t.Fatal("test did not distinguish whole and subset")
	}
	for _, wrong := range []string{subset, digest([]byte("wrong whole digest"))} {
		changed := reencodeIndex(t, feed.index, func(d *externalIndexDocument) {
			for i := range d.Projects {
				if d.Projects[i].Project == feed.project {
					d.Projects[i].RuleDigest = wrong
				}
			}
		})
		x, err := ParseExternalIndex(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AdmitExternalProjectTarget(x, feed.project, feed.targets[feed.project]); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("semantic mismatch admitted: %v", err)
		}
	}
}

func TestForwardReservedKnownAndMalformedEntriesRejectBeforeDeferral(t *testing.T) {
	for _, kind := range []string{"reserved-id", "reserved-fact", "known-type", "duplicate-id", "malformed-known-rule", "malformed-id"} {
		t.Run(kind, func(t *testing.T) {
			feed := buildFutureFeed(t)
			x, raw := changedFutureTarget(t, feed, func(d *externalFixtureDocument) {
				e := &d.Pack.Entries[0]
				var rule map[string]any
				if err := json.Unmarshal(e.Rule, &rule); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "reserved-id":
					rule["id"] = MariaDBCanaryRuleID
				case "reserved-fact":
					e.RequiredFacts = append(e.RequiredFacts, Fact{Side: "proposed", ID: "component.mariadb_operator.auto_update_data_plane", Component: "pkg:github/mariadb-operator/mariadb-operator", Type: "bool", Description: "reserved fact"})
				case "known-type":
					base, err := load()
					if err != nil {
						t.Fatal(err)
					}
					f := base.registry.Definitions()[0]
					e.RequiredFacts = append(e.RequiredFacts, Fact{Side: "proposed", ID: f.ID, Component: f.Component, Type: "enum", EnumTokens: []string{"changed"}, Description: "conflicting known fact"})
				case "duplicate-id":
					d.Pack.Entries = append(d.Pack.Entries, *e)
				case "malformed-known-rule":
					rule["unrecognizedField"] = true
				case "malformed-id":
					rule["id"] = "invalid/id"
				}
				e.Rule, _ = json.Marshal(rule)
			})
			if _, err := AdmitExternalProjectTarget(x, feed.project, raw); !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrUnreadableTarget) {
				t.Fatalf("malformed data deferred: %v", err)
			}
		})
	}
}

func TestForwardOpaqueAndProfileBindings(t *testing.T) {
	feed := buildFutureFeed(t)
	missing, missingRaw := changedFutureTarget(t, feed, func(d *externalFixtureDocument) { d.Schema = "" })
	if _, err := AdmitExternalProjectTarget(missing, feed.project, missingRaw); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing schema deferred: %v", err)
	}
	x, raw := changedFutureTarget(t, feed, func(d *externalFixtureDocument) { d.Schema = "prufyx.io/operator-cncf-knowledge/v99" })
	if _, err := AdmitExternalProjectTarget(x, feed.project, raw); !errors.Is(err, ErrUnreadableTarget) {
		t.Fatalf("opaque target: %v", err)
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	canary, err := externalProfile(base, true)
	if err != nil {
		t.Fatal(err)
	}
	wrong := reencodeIndex(t, feed.index, func(d *externalIndexDocument) { d.EngineCapabilityDigest = canary.capability })
	if _, err := ParseExternalIndex(wrong); err == nil {
		t.Fatal("legacy base marker selected canary")
	}
	entry, err := mariaDBCanaryEntry()
	if err != nil {
		t.Fatal(err)
	}
	x, raw = changedFutureTarget(t, feed, func(d *externalFixtureDocument) { d.Pack.Entries = []Entry{entry}; d.Pack.Schema = packSchemaCommunity })
	if _, err := AdmitExternalProjectTarget(x, feed.project, raw); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("canary became future legacy data: %v", err)
	}
	index, err := ParseExternalIndex(feed.index)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := index.EmptyExternalBundle()
	if err != nil {
		t.Fatal(err)
	}
	if !empty.valid() || empty.profile.capability != baseCapabilityProfile(t) || empty.document.EngineCapabilityDigest != feed.capacity || empty.registry.Digest() != base.registry.Digest() {
		t.Fatal("absent target lost selected local/remote profile")
	}
	if _, err := AdmitExternalProjectTarget(index, feed.project, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("missing signed bytes admitted")
	}
}

func baseCapabilityProfile(t *testing.T) string {
	t.Helper()
	p, err := ExternalProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	return p.EngineCapabilityDigest
}

func TestForwardExportIsExplicitAndLegacyBytesStable(t *testing.T) {
	before, targets, err := BuildEmbeddedExternalTargets("9", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before.Bytes, []byte("baseCapabilityDigest")) {
		t.Fatal("legacy publisher silently changed format")
	}
	compatible, compatTargets, err := BuildEmbeddedCompatibleExternalTargets("9", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(compatible.Bytes, []byte("baseCapabilityDigest")) || bytes.Equal(before.Bytes, compatible.Bytes) {
		t.Fatal("explicit export missing marker")
	}
	if len(targets) != len(compatTargets) {
		t.Fatal("changed target set")
	}
	for i := range targets {
		if targets[i].Path != compatTargets[i].Path || !bytes.Equal(targets[i].Bytes, compatTargets[i].Bytes) {
			t.Fatal("changed legacy target bytes")
		}
	}
	after, _, err := BuildEmbeddedExternalTargets("9", nil)
	if err != nil || !bytes.Equal(before.Bytes, after.Bytes) {
		t.Fatal("profile construction changed legacy export")
	}
	index, err := ParseExternalIndex(compatible.Bytes)
	if err != nil || index.Compat() {
		t.Fatal("exact profile did not win")
	}
	if !strings.Contains(deferredNextAction, "UNKNOWN") {
		t.Fatal("missing bounded action")
	}
}

func TestForwardExactBaseMismatchIsIntegrity(t *testing.T) {
	index, _, err := BuildEmbeddedExternalTargets("9", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) {
		d.BaseCapabilityDigest = digest([]byte("inconsistent declared policy"))
	})
	if _, err := ParseExternalIndex(raw); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("inconsistent base marker: %v", err)
	}
}

func TestForwardOpaqueOlderTargetKeepsItsRevision(t *testing.T) {
	feed := buildFutureFeed(t)
	var target externalFixtureDocument
	if json.Unmarshal(feed.targets[feed.project], &target) != nil {
		t.Fatal("target")
	}
	target.Schema = "prufyx.io/operator-cncf-knowledge/v99"
	target.Revision = "8"
	target.Pack.Revision = "8"
	raw, _ := json.Marshal(target)
	indexRaw := reencodeIndex(t, feed.index, func(d *externalIndexDocument) {
		for i := range d.Projects {
			if d.Projects[i].Project == feed.project {
				d.Projects[i].Revision = "8"
				d.Projects[i].Length = int64(len(raw))
				d.Projects[i].Digest = digest(raw)
			}
		}
	})
	index, err := ParseExternalIndex(indexRaw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := index.UnreadableExternalBundle(feed.project, raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := b.Admission()
	if err != nil || a.Revision != "8" || a.RuleDigest != "" || a.HasRule || a.HasRecords {
		t.Fatalf("opaque admission %+v %v", a, err)
	}
	r, err := b.EvaluateRule(feed.project, feed.ruleID, feed.input, reviewClock(t))
	if err != nil || r.KnowledgeRevision != "8" || r.KnowledgePackDigest != digest(raw) || !r.UnverifiedSemanticIdentity || ClaimExit(r) == 0 {
		t.Fatalf("opaque revision binding %+v %v", r, err)
	}
}
