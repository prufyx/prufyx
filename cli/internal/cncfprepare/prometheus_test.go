// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreparePrometheusScrapeConfigSelectedRename(t *testing.T) {
	for _, test := range []struct {
		name, raw, wantKey string
		wantReason         Reason
	}{
		{"old true", "job_name: private-job\nscrape_classic_histograms: true\nstatic_configs:\n  - targets: [private.example:9090]\n", prometheusOldKey, ReasonPrometheusOldKeyPresent},
		{"old false still removed", "job_name: 'private-job'\nscrape_classic_histograms: false\n", prometheusOldKey, ReasonPrometheusOldKeyPresent},
		{"new true", "job_name: \"private-job\"\nalways_scrape_classic_histograms: true\n", prometheusNewKey, ReasonPrometheusNewKeyPresent},
		{"new false", "job_name: private-job\nalways_scrape_classic_histograms: false # explicit target key\n", prometheusNewKey, ReasonPrometheusNewKeyPresent},
		{"flow mapping", "{job_name: private-job, always_scrape_classic_histograms: true}\n", prometheusNewKey, ReasonPrometheusNewKeyPresent},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PreparePrometheusScrapeConfig([]byte(test.raw), "private-job", PrometheusFrom, PrometheusTo, true, true)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != test.wantReason {
				t.Fatalf("prepared=%#v err=%v", prepared, err)
			}
			if got, state := prometheusCanonicalFact(t, prepared.CanonicalInputJSON); got != test.wantKey || state != "declared" {
				t.Fatalf("fact=(%q,%q)", got, state)
			}
			if string(prepared.CanonicalInputJSON) == test.raw || containsAny(string(prepared.CanonicalInputJSON), "private-job", "private.example") {
				t.Fatal("private selected input escaped into canonical facts")
			}
		})
	}
}

func TestPreparePrometheusScrapeConfigUnknownBoundaries(t *testing.T) {
	tests := []string{
		"job_name: private-job\n",
		"job_name: private-job\nscrape_classic_histograms: true\nalways_scrape_classic_histograms: false\n",
		"job_name: other\nalways_scrape_classic_histograms: true\n",
		"job_name: private-job\nalways_scrape_classic_histograms: 'true'\n",
		"job_name: private-job\nalways_scrape_classic_histograms: true#suffix\n",
		"job_name: private-job\nAlways_Scrape_Classic_Histograms: true\n",
		"job_name: private-job\n\"\\x73crape_classic_histograms\": true\nalways_scrape_classic_histograms: true\n",
		"job_name: private-job\n'always_scrape_classic_histograms': true\nalways_scrape_classic_histograms: true\n",
		"job_name: private-job\nalways_scrape_classic_histograms.child: true\n",
		"wrapper:\n  always_scrape_classic_histograms: true\njob_name: private-job\n",
		"wrapper:\n  - always_scrape_classic_histograms: true\njob_name: private-job\n",
		"job_name: private-job\njob_name: second\nalways_scrape_classic_histograms: true\n",
		"job_name: private-job\nunrelated: one\nunrelated: two\nalways_scrape_classic_histograms: true\n",
		"defaults: &defaults\n  always_scrape_classic_histograms: true\njob_name: private-job\n<<: *defaults\n",
		"job_name: private-job\n---\nalways_scrape_classic_histograms: true\n",
		"- job_name: private-job\n  always_scrape_classic_histograms: true\n",
		"%YAML 1.2\njob_name: private-job\nalways_scrape_classic_histograms: true\n",
	}
	for _, raw := range tests {
		prepared, err := PreparePrometheusScrapeConfig([]byte(raw), "private-job", PrometheusFrom, PrometheusTo, true, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonPrometheusScrapeConfigUnsupported {
			t.Fatalf("raw=%q prepared=%#v err=%v", raw, prepared, err)
		}
		if _, state := prometheusCanonicalFact(t, prepared.CanonicalInputJSON); state != "unsupported" {
			t.Fatalf("state=%q", state)
		}
	}
	for _, declarations := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		prepared, err := PreparePrometheusScrapeConfig([]byte("job_name: private-job\nalways_scrape_classic_histograms: true\n"), "private-job", PrometheusFrom, PrometheusTo, declarations[0], declarations[1])
		if err != nil || prepared.State != StateUnknown {
			t.Fatalf("declarations=%v prepared=%#v err=%v", declarations, prepared, err)
		}
	}
}

func TestPreparePrometheusScrapeConfigRejectsInvalidEnvelope(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
		job  string
	}{
		{"invalid utf8", []byte{'j', 'o', 'b', '_', 'n', 'a', 'm', 'e', ':', ' ', 0xff}, "private-job"},
		{"dynamic job selector", []byte("job_name: private-job\nalways_scrape_classic_histograms: true\n"), "$JOB"},
	} {
		if _, err := PreparePrometheusScrapeConfig(test.raw, test.job, PrometheusFrom, PrometheusTo, true, true); err == nil {
			t.Fatalf("%s accepted", test.name)
		}
	}
}

func TestPreparePrometheusLatestTargetPairsAreFinite(t *testing.T) {
	for _, from := range []string{"3.9.1", "3.10.0", "3.11.3", "3.12.0", "3.13.3"} {
		prepared, err := PreparePrometheusScrapeConfig([]byte("job_name: private-job\nscrape_classic_histograms: true\n"), "private-job", from, PrometheusLatestTo, true, true)
		if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonPrometheusOldKeyPresent {
			t.Fatalf("from=%s prepared=%#v err=%v", from, prepared, err)
		}
	}
	for _, pair := range [][2]string{{"3.8.0", PrometheusLatestTo}, {"3.13.3", "3.14.1"}} {
		prepared, err := PreparePrometheusScrapeConfig([]byte("job_name: private-job\nscrape_classic_histograms: true\n"), "private-job", pair[0], pair[1], true, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonPrometheusScrapeConfigUnsupported {
			t.Fatalf("pair=%v prepared=%#v err=%v", pair, prepared, err)
		}
	}
}

func prometheusCanonicalFact(t *testing.T, raw []byte) (string, string) {
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
			if fact.ID == PrometheusScrapeKeyFact {
				return fact.EnumValue, fact.State
			}
		}
	}
	t.Fatalf("missing %s", PrometheusScrapeKeyFact)
	return "", ""
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
