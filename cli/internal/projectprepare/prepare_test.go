// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPrepareGrafanaNativeINI(t *testing.T) {
	for _, tc := range []struct {
		name, raw, state string
		value            *bool
		resolved         bool
	}{
		{"blocked", "[server]\nroot_url = https://private.invalid\n[alerting]\nenabled = true\n", "PREPARED", boolPointer(true), true},
		{"fixed", "[unified_alerting]\nenabled = true\n", "PREPARED", boolPointer(false), true},
		{"unresolved", "[alerting]\nenabled = true\n", "UNKNOWN", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareEffectiveConfig(GrafanaProject, []byte(tc.raw), GrafanaFrom, GrafanaTo, true, tc.resolved)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalFact(t, prepared.CanonicalInputJSON, GrafanaFact, tc.value)
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("private.invalid")) {
				t.Fatal("unrelated config leaked")
			}
		})
	}
	if _, err := PrepareEffectiveConfig(GrafanaProject, []byte("[alerting]\nenabled=true\n[alerting]\nenabled=false\n"), GrafanaFrom, GrafanaTo, true, true); err == nil {
		t.Fatal("duplicate relevant section accepted")
	}
	for _, raw := range []string{"[Alerting]\nenabled=true\n", "[alerting]\nEnabled=true\n"} {
		prepared, err := PrepareEffectiveConfig(GrafanaProject, []byte(raw), GrafanaFrom, GrafanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("ambiguous case state=%q err=%v", prepared.State, err)
		}
	}
	blank, err := PrepareEffectiveConfig(GrafanaProject, []byte("[alerting]\nenabled=\n"), GrafanaFrom, GrafanaTo, true, true)
	if err != nil || blank.State != "UNKNOWN" {
		t.Fatalf("blank value state=%q err=%v", blank.State, err)
	}
	if _, err := PrepareEffectiveConfig(GrafanaProject, []byte("[alerting]\nenabled true\n"), GrafanaFrom, GrafanaTo, true, true); err == nil {
		t.Fatal("malformed relevant INI accepted")
	}
}

func TestPrepareKibanaNativeYAMLAndJSON(t *testing.T) {
	inputs := []string{
		"server.host: 0.0.0.0\nxpack.reporting.roles.allow: [reporting_user]\n",
		"xpack.reporting.roles.allow: {reporting_user: true}\n",
		"xpack:\n  reporting:\n    roles:\n      allow:\n        - reporting_user\n",
		`{"server":{"name":"private-canary"},"xpack":{"reporting":{"roles":{"allow":["reporting_user"]}}}}`,
	}
	for index, raw := range inputs {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "PREPARED" {
			t.Fatalf("case %d state=%q err=%v", index, prepared.State, err)
		}
		assertCanonicalFact(t, prepared.CanonicalInputJSON, KibanaFact, boolPointer(true))
		if bytes.Contains(prepared.CanonicalInputJSON, []byte("private-canary")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("reporting_user")) {
			t.Fatal("raw config leaked")
		}
	}
	fixed, err := PrepareEffectiveConfig(KibanaProject, []byte("server.host: localhost\n"), KibanaFrom, KibanaTo, true, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanonicalFact(t, fixed.CanonicalInputJSON, KibanaFact, boolPointer(false))
	unsupported, err := PrepareEffectiveConfig(KibanaProject, []byte("xpack: &defaults\n  reporting: *defaults\n"), KibanaFrom, KibanaTo, true, true)
	if err != nil || unsupported.State != "UNKNOWN" {
		t.Fatalf("unsupported YAML state=%q err=%v", unsupported.State, err)
	}
	assertCanonicalFact(t, unsupported.CanonicalInputJSON, KibanaFact, nil)
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte(`{"xpack.reporting.roles.allow":[],"xpack.reporting.roles.allow":[]}`), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte(`{"xpack.reporting.roles.allow":[],"xpack":{"reporting":{"roles":{"allow":[]}}}}`), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("conflicting dotted and nested JSON accepted")
	}
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte("xpack.reporting.roles.allow: []\nxpack:\n  reporting:\n    roles:\n      allow: []\n"), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("conflicting dotted and nested YAML accepted")
	}
	insideArray, err := PrepareEffectiveConfig(KibanaProject, []byte("xpack:\n  reporting:\n    - roles:\n        allow: []\n"), KibanaFrom, KibanaTo, true, true)
	if err != nil || insideArray.State != "UNKNOWN" {
		t.Fatalf("relevant array state=%q err=%v", insideArray.State, err)
	}
	if _, err := PrepareEffectiveConfig(KibanaProject, []byte(`{"xpack":`), KibanaFrom, KibanaTo, true, true); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	for _, raw := range []string{
		"xpack: []\n",
		"xpack:\n  Reporting:\n    roles:\n      allow: []\n",
		`{"xpack":null}`,
		`{"xpack":{"Reporting":{"roles":{"allow":[]}}}}`,
		`{"XPACK.REPORTING.ROLES.ALLOW":[]}`,
		`{"xpack.reporting":{"roles":{"allow":[]}}}`,
		`{"xpack":{"reporting.roles":{"allow":[]}}}`,
		`{"xpack":{"reporting":{"roles.allow":[]}}}`,
		`{"xpack.reporting.roles.allow.child":true}`,
		`{"xpack":{"reporting":{"roles":{"allow.child":true}}}}`,
	} {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("ambiguous relevant shape %q state=%q err=%v", raw, prepared.State, err)
		}
	}
	for _, raw := range []string{
		"xpack.reporting.roles.allow.child: true\n",
		"xpack:\n  reporting:\n    roles:\n      allow.child: true\n",
	} {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("dotted descendant %q state=%q err=%v", raw, prepared.State, err)
		}
	}
	for _, raw := range []string{
		"defaults: &defaults\n  xpack.reporting.roles.allow: []\nconfig:\n  <<: *defaults\n",
		"defaults: &defaults\n  safe: true\nxpack:\n  reporting:\n    roles:\n      allow: *defaults\n",
		"defaults: !custom value\nserver.host: localhost\n",
	} {
		prepared, err := PrepareEffectiveConfig(KibanaProject, []byte(raw), KibanaFrom, KibanaTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("YAML indirection %q state=%q err=%v", raw, prepared.State, err)
		}
	}
}

func TestPrepareLokiNativeCompactorYAML(t *testing.T) {
	for _, tc := range []struct {
		name, raw, state   string
		value              *bool
		complete, resolved bool
	}{
		{"shared-store-blocked", "auth_enabled: false\ncompactor:\n  working_directory: /var/loki\n  shared_store: filesystem\n", "PREPARED", boolPointer(true), true, true},
		{"prefix-blocked", "compactor:\n  shared_store_key_prefix: index/\n", "PREPARED", boolPointer(true), true, true},
		{"fixed", "compactor:\n  working_directory: /var/loki\n", "PREPARED", boolPointer(false), true, true},
		{"incomplete", "compactor:\n  working_directory: /var/loki\n", "UNKNOWN", nil, false, true},
		{"precedence-unresolved", "compactor:\n  working_directory: /var/loki\n", "UNKNOWN", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareEffectiveConfig(LokiProject, []byte(tc.raw), LokiFrom, LokiTo, tc.complete, tc.resolved)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalFact(t, prepared.CanonicalInputJSON, LokiFact, tc.value)
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("filesystem")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("/var/loki")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("index/")) {
				t.Fatal("raw Loki configuration leaked")
			}
		})
	}
}

func TestPrepareLokiRejectsMalformedAndDeclinesAmbiguousYAML(t *testing.T) {
	for _, raw := range []string{
		"compactor:\n  shared_store: filesystem\n  shared_store: s3\n",
		"compactor:\n  safe: true\n  safe: false\n",
	} {
		if _, err := PrepareEffectiveConfig(LokiProject, []byte(raw), LokiFrom, LokiTo, true, true); err == nil {
			t.Fatalf("duplicate YAML accepted: %q", raw)
		}
	}
	for _, raw := range []string{
		"server:\n  http_listen_port: 3100\n",
		"compactor: null\n",
		"Compactor:\n  shared_store: filesystem\n",
		"compactor.shared_store: filesystem\n",
		"compactor:\n  Shared_Store: filesystem\n",
		"compactor:\n  shared_store.child: filesystem\n",
		"compactor:\n  storage:\n    shared_store: filesystem\n",
		"compactor:\n  storage:\n    'shared_store ': filesystem\n",
		"defaults: &defaults\n  shared_store: filesystem\ncompactor:\n  <<: *defaults\n",
		"compactor: !include compactor.yml\n",
		"compactor:\n  working_directory: ${LOKI_DATA}\n",
		"compactor:\n  working_directory: $LOKI_DATA\n",
		"compactor:\n  working_directory: '{{ .Values.data }}'\n",
		"compactor:\n  shared_store: null\n",
		"compactor:\n  shared_store: true\n",
		"compactor:\n  shared_store: [filesystem]\n",
		"compactor:\n  shared_store: {type: filesystem}\n",
		"compactor:\n  working_directory: /var/loki\n---\ncompactor: {}\n",
	} {
		prepared, err := PrepareEffectiveConfig(LokiProject, []byte(raw), LokiFrom, LokiTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("ambiguous YAML %q state=%q err=%v", raw, prepared.State, err)
		}
		assertCanonicalFact(t, prepared.CanonicalInputJSON, LokiFact, nil)
	}
	malformed, err := PrepareEffectiveConfig(LokiProject, []byte("compactor: [\n"), LokiFrom, LokiTo, true, true)
	if err != nil || malformed.State != "UNKNOWN" {
		// Malformed YAML is admitted only as an UNKNOWN minimized fact; it is
		// never interpreted as key absence.
		t.Fatalf("malformed YAML state=%q err=%v", malformed.State, err)
	}
	for _, raw := range []string{
		"'compactor ':\n  shared_store: filesystem\n",
		"compactor:\n  'shared_store ': filesystem\n",
		"!!map {compactor: {shared_store: filesystem}}\n",
		"compactor: !!map {shared_store: !!str filesystem}\n",
	} {
		prepared, err := PrepareEffectiveConfig(LokiProject, []byte(raw), LokiFrom, LokiTo, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("near-key or tagged YAML state=%q err=%v raw=%q", prepared.State, err, raw)
		}
	}
}

func TestPrepareRejectsIdentityAndShapeErrors(t *testing.T) {
	for _, tc := range []struct {
		project, from, to string
		raw               []byte
	}{
		{"unknown", GrafanaFrom, GrafanaTo, []byte("[server]\n")},
		{GrafanaProject, "10.4", GrafanaTo, []byte("[server]\n")},
		{GrafanaProject, GrafanaFrom, GrafanaFrom, []byte("[server]\n")},
		{GrafanaProject, GrafanaFrom, GrafanaTo, []byte("[alerting\nenabled=true\n")},
	} {
		if _, err := PrepareEffectiveConfig(tc.project, tc.raw, tc.from, tc.to, true, true); err == nil {
			t.Fatalf("accepted %#v", tc)
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func assertCanonicalFact(t *testing.T, raw []byte, id string, want *bool) {
	t.Helper()
	var doc struct {
		Proposed struct {
			Components []struct {
				Facts []struct {
					ID        string `json:"id"`
					State     string `json:"state"`
					BoolValue *bool  `json:"boolValue"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	fact := doc.Proposed.Components[0].Facts[0]
	if fact.ID != id {
		t.Fatalf("fact id %q", fact.ID)
	}
	if want == nil {
		if fact.State != "unsupported" || fact.BoolValue != nil {
			t.Fatalf("unsupported fact=%+v", fact)
		}
		return
	}
	if fact.State != "declared" || fact.BoolValue == nil || *fact.BoolValue != *want {
		t.Fatalf("fact=%+v want=%v", fact, *want)
	}
}

func TestPrepareKibanaStatusPageLatestScope(t *testing.T) {
	for _, tc := range []struct {
		name, raw, from                            string
		complete, resolved, intentDeclared, intent bool
		state                                      string
		bypass, authentication, required           *bool
	}{
		{"blocked-default", "server.host: localhost\n", "9.4.6", true, true, true, true, "PREPARED", boolPointer(false), boolPointer(true), boolPointer(true)},
		{"pass-bypass", "status.statusPageBypassMonitorPrivilege: true\n", "9.4.6", true, true, true, true, "PREPARED", boolPointer(true), boolPointer(true), boolPointer(true)},
		{"intent-false", "status.statusPageBypassMonitorPrivilege: true\n", "9.4.6", true, true, true, false, "PREPARED", boolPointer(true), boolPointer(true), boolPointer(false)},
		{"missing-intent", "status.statusPageBypassMonitorPrivilege: true\n", "9.4.6", true, true, false, false, "UNKNOWN", boolPointer(true), boolPointer(true), nil},
		{"incomplete", "status.statusPageBypassMonitorPrivilege: true\n", "9.4.6", false, true, true, true, "UNKNOWN", nil, nil, boolPointer(true)},
		{"wrong-pair", "status.statusPageBypassMonitorPrivilege: true\n", "9.4.5", true, true, true, true, "UNKNOWN", nil, nil, nil},
		{"nested-ambiguous", "status:\n  statusPageBypassMonitorPrivilege: true\n", "9.4.6", true, true, true, true, "UNKNOWN", nil, nil, boolPointer(true)},
		{"allow-anonymous-outside-predicate", "status.allowAnonymous: true\n", "9.4.6", true, true, true, true, "PREPARED", boolPointer(false), boolPointer(false), boolPointer(true)},
		{"json-ambiguous", `{"status.statusPageBypassMonitorPrivilege":true}`, "9.4.6", true, true, true, true, "UNKNOWN", nil, nil, boolPointer(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKibanaStatusPage([]byte(tc.raw), tc.from, "9.5.3", tc.complete, tc.resolved, tc.intentDeclared, tc.intent)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalFacts(t, prepared.CanonicalInputJSON, map[string]*bool{KibanaStatusBypassFact: tc.bypass, KibanaStatusAuthFact: tc.authentication, KibanaFullStatusIntentFact: tc.required})
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("localhost")) {
				t.Fatal("raw config leaked")
			}
		})
	}
	duplicate, err := PrepareKibanaStatusPage([]byte("status.statusPageBypassMonitorPrivilege: true\nstatus.statusPageBypassMonitorPrivilege: false\n"), "9.4.6", "9.5.3", true, true, true, true)
	if err != nil || duplicate.State != "UNKNOWN" {
		t.Fatalf("duplicate selected setting state=%q err=%v", duplicate.State, err)
	}
	for _, raw := range []string{
		`"status.statusPageBypassMonitorPrivilege": true`,
		`"status.allowAnonymous": false`,
		"status.statusPageBypassMonitorPrivilege: true\n\"status.statusPageBypassMonitorPrivilege\": false\n",
		"defaults: &defaults\n  status.statusPageBypassMonitorPrivilege: true\n<<: *defaults\n",
		"---\nstatus.statusPageBypassMonitorPrivilege: true\n",
		"- status.statusPageBypassMonitorPrivilege: true\n",
		"  status.statusPageBypassMonitorPrivilege: true\n",
		"status.unknown: true\n",
		"not a YAML mapping\n",
	} {
		prepared, err := PrepareKibanaStatusPage([]byte(raw), "9.4.6", "9.5.3", true, true, true, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("unsupported latest YAML %q state=%q err=%v", raw, prepared.State, err)
		}
		assertCanonicalFacts(t, prepared.CanonicalInputJSON, map[string]*bool{KibanaStatusBypassFact: nil, KibanaStatusAuthFact: nil, KibanaFullStatusIntentFact: boolPointer(true)})
	}
}

func assertCanonicalFacts(t *testing.T, raw []byte, want map[string]*bool) {
	t.Helper()
	var doc struct {
		Proposed struct {
			Components []struct {
				Facts []struct {
					ID        string `json:"id"`
					State     string `json:"state"`
					BoolValue *bool  `json:"boolValue"`
				} `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]struct {
		state string
		value *bool
	}{}
	for _, fact := range doc.Proposed.Components[0].Facts {
		got[fact.ID] = struct {
			state string
			value *bool
		}{fact.State, fact.BoolValue}
	}
	for id, value := range want {
		fact, ok := got[id]
		if !ok {
			t.Fatalf("missing fact %s", id)
		}
		if value == nil {
			if fact.state != "unsupported" || fact.value != nil {
				t.Fatalf("unsupported fact %s=%+v", id, fact)
			}
		} else if fact.state != "declared" || fact.value == nil || *fact.value != *value {
			t.Fatalf("fact %s=%+v", id, fact)
		}
	}
}
