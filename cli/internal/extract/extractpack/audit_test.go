// SPDX-License-Identifier: AGPL-3.0-only

package extractpack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func entry(id, state string, extra string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"project":"p","description":"d%s","requiredFacts":[],"rule":{"id":%q,"subject":{"component":"c","from":"1","to":"2"},"evidence":{"state":%q,"basis":"mechanical","extractor":{"id":"x"}}}}`, extra, id, state))
}

func mkPack(entries ...json.RawMessage) *Pack {
	return &Pack{Members: map[string]json.RawMessage{"schema": json.RawMessage(`"s1"`), "revision": json.RawMessage(`"r1"`)}, Entries: entries}
}

// The audit is the last line of defence: whatever a merge does, a result
// that touches a rule the run did not produce, or changes anything but a
// withdrawal in withdraw mode, is refused.
func TestAuditRefusesForeignChanges(t *testing.T) {
	base := mkPack(entry("a", "active", ""), entry("b", "active", ""))
	allow := map[string]bool{"a": true}

	cases := []struct {
		name     string
		head     func() *Pack
		allowed  map[string]bool
		withdraw bool
		want     bool // refused
	}{
		{"unchanged", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "active", "")) }, nil, false, false},
		{"allowed add", func() *Pack {
			return mkPack(entry("a", "active", ""), entry("b", "active", ""), entry("n", "active", ""))
		}, map[string]bool{"n": true}, false, false},
		{"unallowed add", func() *Pack {
			return mkPack(entry("a", "active", ""), entry("b", "active", ""), entry("n", "active", ""))
		}, nil, false, true},
		{"foreign edit", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "active", "!")) }, allow, false, true},
		{"allowed id edited in add mode", func() *Pack { return mkPack(entry("a", "active", "!"), entry("b", "active", "")) }, allow, false, true},
		{"removal", func() *Pack { return mkPack(entry("a", "active", "")) }, allow, false, true},
		{"member edit", func() *Pack {
			h := mkPack(entry("a", "active", ""), entry("b", "active", ""))
			h.Members["revision"] = json.RawMessage(`"r2"`)
			return h
		}, nil, false, true},
		{"new member", func() *Pack {
			h := mkPack(entry("a", "active", ""), entry("b", "active", ""))
			h.Members["policyId"] = json.RawMessage(`"x"`)
			return h
		}, nil, false, true},
		{"unshaped schema move in add mode", func() *Pack {
			h := mkPack(entry("a", "active", ""), entry("b", "active", ""))
			h.Members["schema"] = json.RawMessage(`"s2"`)
			return h
		}, nil, false, true},
		{"schema move in withdraw mode", func() *Pack {
			h := mkPack(entry("a", "withdrawn", ""), entry("b", "active", ""))
			h.Members["schema"] = json.RawMessage(`"s2"`)
			return h
		}, allow, true, true},
		{"withdraw allowed", func() *Pack { return mkPack(entry("a", "withdrawn", ""), entry("b", "active", "")) }, allow, true, false},
		{"withdraw foreign", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "withdrawn", "")) }, allow, true, true},
		{"withdraw plus edit", func() *Pack { return mkPack(entry("a", "withdrawn", "!"), entry("b", "active", "")) }, allow, true, true},
		{"withdraw mode adds a rule", func() *Pack {
			return mkPack(entry("a", "withdrawn", ""), entry("b", "active", ""), entry("n", "active", ""))
		}, map[string]bool{"a": true, "n": true}, true, true},
		{"reactivation", func() *Pack { return mkPack(entry("a", "active", ""), entry("b", "active", "")) }, allow, true, false},
	}
	for _, c := range cases {
		b := base
		if c.name == "reactivation" {
			b = mkPack(entry("a", "withdrawn", ""), entry("b", "active", ""))
			// A withdrawn rule made active again is not a state-only
			// tightening, and is refused even when its id is allowed.
			c.want = true
		}
		err := audit(b, c.head(), c.allowed, nil, c.withdraw)
		if c.want != (err != nil) {
			t.Errorf("%s: err = %v, want refusal %v", c.name, err, c.want)
		}
		if err != nil && !errors.Is(err, ErrForeignChange) {
			t.Errorf("%s: wrong error type: %v", c.name, err)
		}
	}
}

// goldenAttestations reads two valid attestations (different scopes) from
// the served-API golden file.
func goldenAttestations(t *testing.T) (a, b json.RawMessage, keyB string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden", "served-apis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		LineAttestations []json.RawMessage `json:"lineAttestations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.LineAttestations) < 2 {
		t.Fatalf("golden attestations: %v", err)
	}
	atts, err := lineattest.Parse(joinRaw(doc.LineAttestations[1:2]))
	if err != nil {
		t.Fatal(err)
	}
	return doc.LineAttestations[0], doc.LineAttestations[1], atts[0].Key().String()
}

func joinRaw(items []json.RawMessage) []byte {
	out, _ := json.Marshal(items)
	return out
}

// The attestation section may only be extended by the attestations the run
// brought: an unexpected one, a removed one and a changed one are refused.
func TestAuditAttestationRows(t *testing.T) {
	a, b, keyB := goldenAttestations(t)
	withAtts := func(items ...json.RawMessage) *Pack {
		p := mkPack(entry("a", "active", ""))
		if items != nil {
			p.Members[lineattest.PackMember] = joinRaw(items)
		}
		return p
	}
	rows := []struct {
		name    string
		base    *Pack
		head    *Pack
		allowed map[string]bool
		refused bool
	}{
		{"same", withAtts(a), withAtts(a), nil, false},
		{"extension by the run's attestation", withAtts(a), withAtts(a, b), map[string]bool{keyB: true}, false},
		{"first attestations of a pack", withAtts(), withAtts(a, b), map[string]bool{keyB: true, keyOf(t, a): true}, false},
		{"an attestation the run did not bring", withAtts(a), withAtts(a, b), nil, true},
		{"first attestation the run did not bring", withAtts(), withAtts(a), nil, true},
		{"an existing attestation removed", withAtts(a, b), withAtts(b), map[string]bool{keyB: true}, true},
		{"the whole section removed", withAtts(a), withAtts(), nil, true},
		{"an existing attestation replaced", withAtts(a), withAtts(b), map[string]bool{keyB: true}, true},
	}
	for _, r := range rows {
		err := audit(r.base, r.head, nil, r.allowed, false)
		if r.refused != (err != nil) {
			t.Errorf("%s: err = %v, want refusal %v", r.name, err, r.refused)
		}
		if err != nil && !errors.Is(err, ErrForeignChange) {
			t.Errorf("%s: wrong error %v", r.name, err)
		}
	}
}

func keyOf(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	atts, err := lineattest.Parse(joinRaw([]json.RawMessage{raw}))
	if err != nil {
		t.Fatal(err)
	}
	return atts[0].Key().String()
}

// A merge never lowers the pack schema or moves it to another family.
func TestAuditSchemaRows(t *testing.T) {
	const fam = "prufyx.io/cncf-source-rule-pack/v1alpha"
	for _, r := range []struct {
		name, from, to string
		withdraw       bool
		refused        bool
	}{
		{"same", fam + "2", fam + "2", false, false},
		{"raised", fam + "2", fam + "4", false, false},
		{"lowered", fam + "4", fam + "2", false, true},
		{"another family", fam + "2", "prufyx.io/community-project-source-rule-pack/v1alpha3", false, true},
		{"unshaped schemas must be equal", "s1", "s2", false, true},
		{"raised in withdraw mode", fam + "2", fam + "4", true, true},
	} {
		b, h := mkPack(entry("a", "active", "")), mkPack(entry("a", "active", ""))
		b.Members["schema"], _ = json.Marshal(r.from)
		h.Members["schema"], _ = json.Marshal(r.to)
		err := audit(b, h, nil, nil, r.withdraw)
		if r.refused != (err != nil) {
			t.Errorf("%s: err = %v, want refusal %v", r.name, err, r.refused)
		}
	}
}
