// SPDX-License-Identifier: AGPL-3.0-only

package kamajipredicate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// All authority in this file belongs to synthetic test issuers only. Nothing
// here is compiled into the product, accepts production evidence or signs it.
const (
	oldCommit           = "1756a7bccbcd358edbcfccc88374c328f9537d77"
	newCommit           = "31fed7a654b361ff8332a79184e6b0d2a05eb343"
	oldSource           = "sha256:158c73997c1d43f19eef833831caadee15573b67f9e74a9a0714f095f33df837"
	newSource           = "sha256:093aa5ad520e7a9e65bb634195a8a09cb25ac5273526e4c016a9664a3624995d"
	testPolicy          = "test-only-declared-predicate;no-production-admission;no-whole-upgrade-pass"
	expectedEntryDigest = "sha256:9d84800c2f6f080177396545eccda0e4f144220590d3d6bc726e2f20074ea559"
)

func hash(raw []byte) string { d := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(d[:]) }
func jsonBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func closedEntry() []byte {
	source := func(id, commit, digest string, start, end int) any {
		return map[string]any{"id": id, "url": "https://github.com/clastix/kamaji/blob/" + commit + "/charts/kamaji/crds/kamaji.clastix.io_tenantcontrolplanes.yaml", "revision": commit, "contentDigest": digest, "startLine": start, "endLine": end}
	}
	return jsonBytes(map[string]any{
		"id": RuleID, "operator": "forbid_predicate_value",
		"subject":    map[string]any{"component": Component, "from": "26.6.5", "to": "26.11.2"},
		"condition":  map[string]any{"side": "proposed", "component": Component, "factId": FactID, "boolValue": true},
		"evidence":   map[string]any{"state": "active", "reviewedAt": "2026-11-04T00:00:00Z", "validUntil": "2026-12-01T00:00:00Z", "sources": []any{source("old-raw-crd", oldCommit, oldSource, 8644, 8656), source("target-raw-crd", newCommit, newSource, 9014, 9028)}},
		"reasonCode": "POD_CIDRS_SAME_FAMILY", "nextAction": "Declare one canonical pod CIDR or two of distinct IP families; validate all other target requirements separately.",
	})
}

type testContext struct {
	Schema, Project, Component, Rule, Profile, Capability, EntryDigest string
	FromTag, FromCommit, FromSource, ToTag, ToCommit, ToSource         string
	Group, Version, Kind                                               string
	Selection                                                          int
	Complete                                                           bool
	Mode, Intent, TargetSchema, HostVersion                            string
	CELRecord, OldAcceptanceRecord, TargetInstallRecord                string
	FactDigest, Expires                                                string
	InputDigest                                                        string
	SelectionExplicit, SelectionComplete                               bool
}

type signedTestRecord struct{ Bytes, Signature []byte }
type capturedTestInput struct {
	raw       []byte
	selection Selection
	records   map[string]signedTestRecord
}
type testRecord struct {
	Schema, Role, Old, Target, Host, InputDigest string
	Selection                                    Selection
}
type testProfile struct {
	issuer     ed25519.PublicKey
	key        ed25519.PrivateKey
	registry   constraintengine.Registry
	rules      constraintengine.RuleSet
	entry      []byte
	capability string
}

func newTestProfile(t *testing.T) testProfile {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := constraintengine.NewRegistry([]constraintengine.FactDefinition{{ID: FactID, Component: Component, Type: constraintengine.FactBool}})
	if err != nil {
		t.Fatal(err)
	}
	entry := closedEntry()
	if hash(entry) != expectedEntryDigest {
		t.Fatal("closed test entry changed; independent review required")
	}
	doc := jsonBytes(map[string]any{"schema": constraintengine.RulesSchema, "revision": "test-only", "policyId": Profile, "policyDigest": hash([]byte(testPolicy)), "rules": []json.RawMessage{entry}})
	rules, err := constraintengine.ParseRuleSet(doc, registry)
	if err != nil {
		t.Fatal(err)
	}
	capability := hash(jsonBytes(struct{ Registry, Entry, Policy, Ownership string }{registry.Digest(), hash(entry), hash([]byte(testPolicy)), Profile + "/" + RuleID + "/" + FactID}))
	return testProfile{pub, key, registry, rules, entry, capability}
}

func (p testProfile) capture(raw []byte, selection Selection) capturedTestInput {
	input := capturedTestInput{append([]byte(nil), raw...), selection, map[string]signedTestRecord{}}
	for _, role := range []string{"cel-functions", "old-acceptance", "target-installation"} {
		// Independent immutable fixture records, not context-supplied hashes or
		// a caller success flag. They represent no real Kubernetes execution.
		b := jsonBytes(testRecord{"synthetic-test-record/v1", role, oldSource, newSource, "1.31.0", hash(input.raw), input.selection})
		input.records[role] = signedTestRecord{b, ed25519.Sign(p.key, b)}
	}
	return input
}

func recordDigest(input capturedTestInput, role string) string {
	r, ok := input.records[role]
	if !ok || len(r.Bytes) == 0 {
		return ""
	}
	return hash(r.Bytes)
}

func (p testProfile) context(input capturedTestInput) testContext {
	result, err := Produce(input.raw, input.selection)
	if err != nil {
		panic("invalid test capture")
	}
	return testContext{Schema: "test-only-kamaji-claim-context/v1", Project: "kamaji", Component: Component, Rule: RuleID, Profile: Profile, Capability: p.capability, EntryDigest: hash(p.entry),
		FromTag: "26.6.5-edge", FromCommit: oldCommit, FromSource: oldSource, ToTag: "26.11.2-edge", ToCommit: newCommit, ToSource: newSource,
		Group: "kamaji.clastix.io", Version: "v1alpha1", Kind: "TenantControlPlane", Selection: input.selection.Index, Complete: true, Mode: "raw", Intent: "apply",
		TargetSchema: newSource, HostVersion: "1.31.0", CELRecord: recordDigest(input, "cel-functions"), OldAcceptanceRecord: recordDigest(input, "old-acceptance"), TargetInstallRecord: recordDigest(input, "target-installation"),
		FactDigest: hash(jsonBytes(result)), Expires: "2026-11-05T00:00:00Z", InputDigest: hash(input.raw), SelectionExplicit: input.selection.Explicit, SelectionComplete: input.selection.Complete}
}

var errTestIntegrity = errors.New("test profile integrity refusal")

// evaluate verifies the entire closed test context before invoking the actual
// existing boolean engine. No caller assertion can bypass the fixture issuer.
func (p testProfile) evaluate(captured capturedTestInput, entry, raw, signature []byte, now time.Time) (string, error) {
	if len(raw) == 0 {
		return "UNKNOWN", nil
	}
	if len(raw) > 16384 || !ed25519.Verify(p.issuer, raw, signature) {
		return "", errTestIntegrity
	}
	var ctx testContext
	if strictjson.Decode(raw, &ctx) != nil || !bytes.Equal(jsonBytes(ctx), raw) {
		return "", errTestIntegrity
	}
	if !bytes.Equal(entry, p.entry) {
		return "", errTestIntegrity
	}
	result, err := Produce(captured.raw, captured.selection)
	if err != nil {
		return "", errTestIntegrity
	}
	expires, err := time.Parse(time.RFC3339, ctx.Expires)
	if err != nil {
		return "", errTestIntegrity
	}
	if now.Before(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)) || !expires.After(now) || !ctx.Complete || ctx.HostVersion == "" || ctx.CELRecord == "" || ctx.OldAcceptanceRecord == "" || ctx.TargetInstallRecord == "" {
		return "UNKNOWN", nil
	}
	want := p.context(captured)
	want.Expires = ctx.Expires
	if ctx != want {
		return "", errTestIntegrity
	}
	if len(captured.records) != 3 {
		return "UNKNOWN", nil
	}
	for role, record := range captured.records {
		if !ed25519.Verify(p.issuer, record.Bytes, record.Signature) {
			return "", errTestIntegrity
		}
		var doc testRecord
		if strictjson.Decode(record.Bytes, &doc) != nil || doc.Schema != "synthetic-test-record/v1" || doc.Role != role || doc.Old != oldSource || doc.Target != newSource || doc.Host != ctx.HostVersion || doc.InputDigest != hash(captured.raw) || doc.Selection != captured.selection {
			return "", errTestIntegrity
		}
	}
	if result.FactID != FactID || result.State != "DECLARED" || result.BoolValue == nil {
		return "UNKNOWN", nil
	}
	fact := map[string]any{"id": FactID, "state": "declared", "boolValue": *result.BoolValue}
	inputRaw := jsonBytes(map[string]any{"schema": constraintengine.InputSchema, "authority": constraintengine.InputAuthority,
		"current":  map[string]any{"components": []any{map[string]any{"component": Component, "version": "26.6.5", "facts": []any{}}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": Component, "version": "26.11.2", "facts": []any{fact}}}}})
	input, err := constraintengine.ParseInput(inputRaw, p.registry)
	if err != nil {
		return "", err
	}
	report, err := constraintengine.Evaluate(input, p.rules, now)
	if err != nil {
		return "", err
	}
	if report.Assessment != "UNKNOWN" || len(report.Claims) != 1 {
		return "", errTestIntegrity
	}
	return report.Claims[0].Status, nil
}

func TestClosedTestOnlyProfile(t *testing.T) {
	p := newTestProfile(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	t.Log("test-only canonical entry fingerprint", hash(p.entry), "capability", p.capability)
	for _, tc := range []struct{ list, status string }{{`["10.0.0.0/16","10.0.0.0/16"]`, "BLOCKED"}, {`["10.0.0.0/16","2001:db8::/64"]`, "PASS"}, {`["10.0.0.0/16"]`, "PASS"}, {`null`, "UNKNOWN"}} {
		captured := p.capture(resource(tc.list), selected)
		raw := jsonBytes(p.context(captured))
		status, err := p.evaluate(captured, p.entry, raw, ed25519.Sign(p.key, raw), now)
		if err != nil || status != tc.status {
			t.Fatalf("status=%s err=%v", status, err)
		}
		if status, err = p.evaluate(captured, p.entry, nil, nil, now); err != nil || status != "UNKNOWN" {
			t.Fatal("missing evidence escaped", status, err)
		}
	}
}

func TestContextSubstitutionAndUnavailableEvidence(t *testing.T) {
	p := newTestProfile(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	captured := p.capture(resource(`["10.0.0.0/16","10.1.0.0/16"]`), selected)
	for name, mut := range map[string]func(*testContext){
		"wrong-host-tenant-confusion": func(c *testContext) { c.HostVersion = "1.30.0" },
		"wrong-gvk":                   func(c *testContext) { c.Version = "v1beta1" }, "wrong-component": func(c *testContext) { c.Component = "pkg:github/example/other" },
		"wrong-schema": func(c *testContext) { c.TargetSchema = oldSource }, "chart-mode": func(c *testContext) { c.Mode = "chart" },
		"wrong-intent": func(c *testContext) { c.Intent = "observe" }, "wrong-selection": func(c *testContext) { c.Selection = 1 },
		"wrong-pair": func(c *testContext) { c.FromCommit = newCommit }, "wrong-fact": func(c *testContext) { c.FactDigest = oldSource },
		"wrong-rule": func(c *testContext) { c.Rule = "other" }, "wrong-profile": func(c *testContext) { c.Profile = "other" },
		"wrong-capability": func(c *testContext) { c.Capability = oldSource }, "wrong-entry": func(c *testContext) { c.EntryDigest = oldSource },
		"record-replay": func(c *testContext) { c.OldAcceptanceRecord = c.TargetInstallRecord },
	} {
		t.Run(name, func(t *testing.T) {
			c := p.context(captured)
			mut(&c)
			raw := jsonBytes(c)
			if _, err := p.evaluate(captured, p.entry, raw, ed25519.Sign(p.key, raw), now); !errors.Is(err, errTestIntegrity) {
				t.Fatal("substitution accepted", err)
			}
		})
	}
	for name, mut := range map[string]func(*testContext){"missing-cel": func(c *testContext) { c.CELRecord = "" }, "missing-host": func(c *testContext) { c.HostVersion = "" }, "missing-install": func(c *testContext) { c.TargetInstallRecord = "" }, "missing-old": func(c *testContext) { c.OldAcceptanceRecord = "" }, "incomplete": func(c *testContext) { c.Complete = false }, "stale": func(c *testContext) { c.Expires = "2026-11-03T00:00:00Z" }} {
		t.Run(name, func(t *testing.T) {
			c := p.context(captured)
			mut(&c)
			raw := jsonBytes(c)
			status, err := p.evaluate(captured, p.entry, raw, ed25519.Sign(p.key, raw), now)
			if err != nil || status != "UNKNOWN" {
				t.Fatal(status, err)
			}
		})
	}
	raw := jsonBytes(p.context(captured))
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := p.evaluate(captured, p.entry, raw, ed25519.Sign(otherKey, raw), now); !errors.Is(err, errTestIntegrity) {
		t.Fatal("self-issued context accepted")
	}
	changed := bytes.Replace(p.entry, []byte(`"boolValue":true`), []byte(`"boolValue":false`), 1)
	if _, err := p.evaluate(captured, changed, raw, ed25519.Sign(p.key, raw), now); !errors.Is(err, errTestIntegrity) {
		t.Fatal("conflicting entry accepted")
	}
	duplicate := append([]byte(`{"Schema":"duplicate",`), raw[1:]...)
	if _, err := p.evaluate(captured, p.entry, duplicate, ed25519.Sign(p.key, duplicate), now); !errors.Is(err, errTestIntegrity) {
		t.Fatal("duplicate context accepted")
	}
	record := captured.records["cel-functions"]
	record.Bytes = append(record.Bytes, ' ')
	captured.records["cel-functions"] = record
	if _, err := p.evaluate(captured, p.entry, raw, ed25519.Sign(p.key, raw), now); !errors.Is(err, errTestIntegrity) {
		t.Fatal("unverified record accepted")
	}
}

func TestTenantVersionCannotSupplyHostEvidence(t *testing.T) {
	p := newTestProfile(t)
	var object map[string]any
	if err := json.Unmarshal(resource(`["10.0.0.0/16"]`), &object); err != nil {
		t.Fatal(err)
	}
	object["spec"].(map[string]any)["kubernetes"] = map[string]any{"version": "1.31.0"}
	captured := p.capture(jsonBytes(object), selected)
	ctx := p.context(captured)
	ctx.HostVersion = ""
	raw := jsonBytes(ctx)
	status, err := p.evaluate(captured, p.entry, raw, ed25519.Sign(p.key, raw), time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	if err != nil || status != "UNKNOWN" {
		t.Fatal("tenant version supplied host evidence", status, err)
	}
}

func TestContextCannotReplayAcrossResourceBytesAndSelection(t *testing.T) {
	p := newTestProfile(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	a := resource(`["10.0.0.0/16","10.1.0.0/16"]`)
	b := resource(`["10.2.0.0/16","10.3.0.0/16"]`)
	list := append(append(append([]byte("["), a...), ','), b...)
	list = append(list, ']')
	for name, pair := range map[string][2]capturedTestInput{
		"different-resource-same-predicate":  {p.capture(a, selected), p.capture(b, selected)},
		"different-selection-same-predicate": {p.capture(list, selected), p.capture(list, Selection{Index: 1, Explicit: true, Complete: true})},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := jsonBytes(p.context(pair[0]))
			sig := ed25519.Sign(p.key, ctx)
			if _, err := p.evaluate(pair[1], p.entry, ctx, sig, now); !errors.Is(err, errTestIntegrity) {
				t.Fatal("resource-specific context replay accepted")
			}
			own := jsonBytes(p.context(pair[1]))
			if status, err := p.evaluate(pair[1], p.entry, own, ed25519.Sign(p.key, own), now); err != nil || status != "BLOCKED" {
				t.Fatal("matching capture refused", status, err)
			}
			// Even a valid issuer signature on an old-acceptance record from
			// the other resource cannot be relabelled with fresh self-hashes.
			pair[1].records["old-acceptance"] = pair[0].records["old-acceptance"]
			rebound := jsonBytes(p.context(pair[1]))
			if _, err := p.evaluate(pair[1], p.entry, rebound, ed25519.Sign(p.key, rebound), now); !errors.Is(err, errTestIntegrity) {
				t.Fatal("resource-specific acceptance replay accepted")
			}
		})
	}
}
