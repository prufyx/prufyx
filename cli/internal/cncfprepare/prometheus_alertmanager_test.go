// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreparePrometheusAlertmanagerConfigSelections(t *testing.T) {
	tests := []struct {
		name, raw, want string
		wantReason      Reason
	}{
		{"v1 blocked fact", "api_version: v1\nscheme: http\nstatic_configs:\n  - targets: [private.example:9093]\n", prometheusAlertmanagerAPIV1, ReasonPrometheusAlertmanagerAPIV1Present},
		{"quoted v2", "api_version: \"v2\"\nscheme: https\n", prometheusAlertmanagerAPIV2, ReasonPrometheusAlertmanagerAPIV2Present},
		{"omitted source default", "scheme: http\nstatic_configs:\n  - targets: [private.example:9093]\n", prometheusAlertmanagerDefaultV2, ReasonPrometheusAlertmanagerAPIDefaultV2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PreparePrometheusAlertmanagerConfig([]byte(test.raw), PrometheusFrom, PrometheusTo, true, true)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != test.wantReason {
				t.Fatalf("prepared=%#v err=%v", prepared, err)
			}
			value, state := prometheusAlertmanagerCanonicalFact(t, prepared.CanonicalInputJSON)
			if value != test.want || state != "declared" {
				t.Fatalf("fact=(%q,%q)", value, state)
			}
			output := string(prepared.CanonicalInputJSON)
			if strings.Contains(output, "private.example") || strings.Contains(output, "9093") || strings.Contains(output, "https") || output == test.raw {
				t.Fatal("private Alertmanager input escaped into canonical facts")
			}
		})
	}
}

func TestPreparePrometheusAlertmanagerConfigRequiresDeclarations(t *testing.T) {
	for _, declarations := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		prepared, err := PreparePrometheusAlertmanagerConfig([]byte("api_version: v1\nscheme: http\n"), PrometheusFrom, PrometheusTo, declarations[0], declarations[1])
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonPrometheusAlertmanagerUnsupported {
			t.Fatalf("declarations=%v prepared=%#v err=%v", declarations, prepared, err)
		}
		if _, state := prometheusAlertmanagerCanonicalFact(t, prepared.CanonicalInputJSON); state != "unsupported" {
			t.Fatalf("state=%q", state)
		}
	}
}

func TestPreparePrometheusAlertmanagerConfigDoesNotDeriveDefaultsOutsideReviewedPair(t *testing.T) {
	prepared, err := PreparePrometheusAlertmanagerConfig([]byte("scheme: http\n"), "3.1.0", "3.2.0", true, true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonPrometheusAlertmanagerUnsupported {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
	value, state := prometheusAlertmanagerCanonicalFact(t, prepared.CanonicalInputJSON)
	if value != "" || state != "unsupported" {
		t.Fatalf("unreviewed pair fact=(%q,%q)", value, state)
	}
	for _, omission := range prepared.Omissions {
		if omission == "OMITTED_API_VERSION_USES_EXACT_TARGET_SOURCE_DERIVED_V2_DEFAULT" {
			t.Fatalf("unreviewed pair claimed source-derived default: %#v", prepared.Omissions)
		}
	}
}

func TestPreparePrometheusAlertmanagerConfigUnknownBoundaries(t *testing.T) {
	tests := []string{
		"{}\n",
		"unrelated: value\n",
		"api_version: v3\nscheme: http\n",
		"api_version: true\nscheme: http\n",
		"api_version: null\nscheme: http\n",
		"api_version: [v2]\nscheme: http\n",
		"api_version: 'v2 '\nscheme: http\n",
		"API_VERSION: v2\nscheme: http\n",
		"api_version.child: v2\nscheme: http\n",
		"'api_version ': v1\nscheme: http\n",
		"nested:\n  'api_version ': v1\nscheme: http\n",
		"wrapper:\n  api_version: v1\nscheme: http\n",
		"alerting:\n  alertmanagers:\n    - api_version: v1\n",
		"global: {}\n",
		"scheme: http\nscheme: https\n",
		"defaults: &defaults\n  api_version: v2\n<<: *defaults\n",
		"api_version: !private v2\nscheme: http\n",
		"api_version: v2\n---\nscheme: http\n",
		"- api_version: v2\n",
		"scheme: ${PRIVATE_SCHEME}\n",
		"scheme: '{{ private_scheme }}'\n",
	}
	for _, raw := range tests {
		prepared, err := PreparePrometheusAlertmanagerConfig([]byte(raw), PrometheusFrom, PrometheusTo, true, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonPrometheusAlertmanagerUnsupported {
			t.Fatalf("raw=%q prepared=%#v err=%v", raw, prepared, err)
		}
		if _, state := prometheusAlertmanagerCanonicalFact(t, prepared.CanonicalInputJSON); state != "unsupported" {
			t.Fatalf("raw=%q state=%q", raw, state)
		}
	}
}

func TestPreparePrometheusAlertmanagerConfigRejectsInvalidEnvelope(t *testing.T) {
	for _, test := range []struct {
		name     string
		raw      []byte
		from, to string
	}{
		{"invalid utf8", []byte{'a', 'p', 'i', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n', ':', ' ', 0xff}, PrometheusFrom, PrometheusTo},
		{"same version", []byte("api_version: v2\n"), PrometheusFrom, PrometheusFrom},
		{"invalid version", []byte("api_version: v2\n"), "private version", PrometheusTo},
	} {
		if _, err := PreparePrometheusAlertmanagerConfig(test.raw, test.from, test.to, true, true); err == nil {
			t.Fatalf("%s accepted", test.name)
		}
	}
}

func TestPreparePrometheusAlertmanagerLatestTargetPairsAreFinite(t *testing.T) {
	for _, from := range []string{"3.9.1", "3.10.0", "3.11.3", "3.12.0", "3.13.3"} {
		prepared, err := PreparePrometheusAlertmanagerConfig([]byte("api_version: v1\nscheme: http\n"), from, PrometheusLatestTo, true, true)
		if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonPrometheusAlertmanagerAPIV1Present {
			t.Fatalf("from=%s prepared=%#v err=%v", from, prepared, err)
		}
	}
	prepared, err := PreparePrometheusAlertmanagerConfig([]byte("api_version: v1\nscheme: http\n"), "3.8.0", PrometheusLatestTo, true, true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonPrometheusAlertmanagerUnsupported {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
}

func prometheusAlertmanagerCanonicalFact(t *testing.T, raw []byte) (string, string) {
	t.Helper()
	var document struct {
		Proposed struct {
			Components []struct {
				Facts []struct{ ID, State, EnumValue string } `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, component := range document.Proposed.Components {
		for _, fact := range component.Facts {
			if fact.ID == PrometheusAlertmanagerAPIVersionFact {
				return fact.EnumValue, fact.State
			}
		}
	}
	t.Fatalf("missing %s", PrometheusAlertmanagerAPIVersionFact)
	return "", ""
}
