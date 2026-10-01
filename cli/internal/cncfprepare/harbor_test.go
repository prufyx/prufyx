// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

func harborArguments(declared bool, argv ...string) []byte {
	return []byte(`{"apiVersion":"` + HarborAPI + `","kind":"` + HarborKind + `","effectiveArgvDeclared":` + map[bool]string{true: "true", false: "false"}[declared] + `,"argv":[` + quoteStrings(argv) + `]}`)
}

func TestPrepareHarborChartMuseumFact(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want State
		flag *bool
	}{
		{name: "removed option", argv: []string{"--with-notary", "--with-chartmuseum"}, want: StatePrepared, flag: boolPtr(true)},
		{name: "complete absence", argv: []string{"--with-notary", "--with-trivy"}, want: StatePrepared, flag: boolPtr(false)},
		{name: "empty complete vector", want: StatePrepared, flag: boolPtr(false)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareHarbor(harborArguments(true, tc.argv...), HarborFrom, HarborTo)
			if err != nil || prepared.State != tc.want {
				t.Fatalf("prepared=%#v err=%v", prepared, err)
			}
			fact := preparedFacts(t, prepared)[HarborFact]
			if fact["state"] != "declared" || fact["boolValue"] != *tc.flag {
				t.Fatalf("fact=%v", fact)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "with-") {
				t.Fatalf("raw argv escaped minimized input: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func boolPtr(value bool) *bool { return &value }

func TestPrepareHarborUnknownBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"missing declaration", []string{"--with-chartmuseum"}},
		{"help", []string{"--help"}},
		{"help after option", []string{"--with-trivy", "--help"}},
		{"inline value", []string{"--with-chartmuseum=true"}},
		{"unknown option", []string{"--with-unknown"}},
		{"duplicate", []string{"--with-trivy", "--with-trivy"}},
		{"wrapper", []string{"sh", "-c", "--with-chartmuseum"}},
		{"response file", []string{"@private.args"}},
		{"shell expansion", []string{"--with-trivy", "$VALUE"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declared := tc.name != "missing declaration"
			prepared, err := PrepareHarbor(harborArguments(declared, tc.argv...), HarborFrom, HarborTo)
			if err != nil || prepared.State != StateUnknown {
				t.Fatalf("prepared=%#v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`) {
				t.Fatalf("unsupported argv declared a bool: %s", prepared.CanonicalInputJSON)
			}
		})
	}
	for _, raw := range []string{
		`{"apiVersion":"` + HarborAPI + `","kind":"` + HarborKind + `","effectiveArgvDeclared":true,"argv":[1]}`,
		`{"apiVersion":"` + HarborAPI + `","kind":"` + HarborKind + `","effectiveArgvDeclared":true,"argv":[],"privateCanary":"omit"}`,
		`{"apiVersion":"` + HarborAPI + `","kind":"` + HarborKind + `","effectiveArgvDeclared":true,"argv":[]}{}`,
	} {
		if _, err := PrepareHarbor([]byte(raw), HarborFrom, HarborTo); err == nil {
			t.Fatalf("invalid input accepted: %s", raw)
		}
	}
}

func TestPrepareHarborLatestExactPairs(t *testing.T) {
	for _, from := range []string{"2.10.3", "2.11.2", "2.12.4", "2.13.5", "2.14.4"} {
		for _, tc := range []struct {
			name string
			argv []string
			want bool
		}{
			{"removed option", []string{"--with-chartmuseum"}, true},
			{"complete absence", []string{"--with-trivy"}, false},
		} {
			prepared, err := PrepareHarbor(harborArguments(true, tc.argv...), from, "2.15.2")
			if err != nil || prepared.State != StatePrepared {
				t.Fatalf("from=%s %s prepared=%#v err=%v", from, tc.name, prepared, err)
			}
			fact := preparedFacts(t, prepared)[HarborFact]
			if fact["state"] != "declared" || fact["boolValue"] != tc.want {
				t.Fatalf("from=%s %s fact=%v", from, tc.name, fact)
			}
		}
		unsupported, err := PrepareHarbor(harborArguments(true, "--with-notary"), from, "2.15.2")
		if err != nil || unsupported.State != StateUnknown || unsupported.Reason != ReasonHarborArgvUnsupported {
			t.Fatalf("from=%s target-rejected option=%#v err=%v", from, unsupported, err)
		}
		prepared, err := PrepareHarbor(harborArguments(true, "--with-chartmuseum"), from, "2.15.1")
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonHarborUnsupportedPair {
			t.Fatalf("from=%s wrong target=%#v err=%v", from, prepared, err)
		}
	}
}

func TestPrepareHarborWrongPairStillExtractsNoFact(t *testing.T) {
	prepared, err := PrepareHarbor(harborArguments(true, "--with-chartmuseum"), "2.7.1", HarborTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonHarborUnsupportedPair {
		t.Fatalf("prepared=%#v err=%v", prepared, err)
	}
	if strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`) {
		t.Fatalf("wrong pair declared fact: %s", prepared.CanonicalInputJSON)
	}
}
