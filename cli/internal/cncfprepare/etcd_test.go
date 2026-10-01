// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func etcdArguments(t *testing.T, declared bool, argv ...string) []byte {
	t.Helper()
	return []byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":` + map[bool]string{true: "true", false: "false"}[declared] + `,"argv":[` + quoteStrings(argv) + `]}`)
}

func quoteStrings(values []string) string {
	var b strings.Builder
	for i, value := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		encoded, _ := json.Marshal(value)
		b.Write(encoded)
	}
	return b.String()
}

func TestPrepareEtcdRemovedOptionAtoms(t *testing.T) {
	cases := []string{
		"--enable-v2=false", "--experimental-enable-v2v3=legacy", "--proxy=off",
		"--proxy-failure-wait=0", "--proxy-refresh-interval=1000", "--proxy-dial-timeout=10",
		"--proxy-write-timeout=20", "--proxy-read-timeout=30",
	}
	for _, atom := range cases {
		t.Run(atom, func(t *testing.T) {
			prepared, err := PrepareEtcd(etcdArguments(t, true, "--name=node", atom), EtcdFrom, EtcdTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonEtcdArgvWitness {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			facts := preparedFacts(t, prepared)
			fact := facts[EtcdFact]
			if fact["state"] != "declared" || fact["boolValue"] != true {
				t.Fatalf("fact=%v", fact)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), atom) || strings.Contains(string(prepared.CanonicalInputJSON), "node") {
				t.Fatal("raw argv escaped minimized declaration")
			}
			if report, err := cncfcheck.Check("etcd", prepared.CanonicalInputJSON, mustTime("2026-09-10T00:00:00Z")); err != nil || report.Check.Claims[0].Status != "BLOCKED" {
				t.Fatalf("check report=%+v err=%v", report, err)
			}
		})
	}
}

func TestPrepareEtcdUnknownBoundariesNeverDeclareFalse(t *testing.T) {
	cases := []struct {
		name string
		argv []string
	}{
		{"missing authority", []string{"--enable-v2=true"}},
		{"empty vector", nil},
		{"target free known atom", []string{"--name=node"}},
		{"unknown separated preceding flag", []string{"--initial-cluster", "--enable-v2=true"}},
		{"unknown equals flag", []string{"--not-registered=x", "--enable-v2=true"}},
		{"separated target", []string{"--enable-v2", "false"}},
		{"sentinel", []string{"--", "--enable-v2=true"}},
		{"positional", []string{"etcd", "--enable-v2=true"}},
		{"single dash", []string{"-enable-v2=true"}},
		{"config file", []string{"--config-file=/private/config", "--enable-v2=true"}},
		{"substitution", []string{"--enable-v2=$VALUE"}},
		{"duplicate", []string{"--enable-v2=true", "--enable-v2=false"}},
		{"bad bool", []string{"--enable-v2=1"}},
		{"bad enum", []string{"--proxy=maybe"}},
		{"bad uint", []string{"--proxy-read-timeout=-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			declared := tc.name != "missing authority"
			prepared, err := PrepareEtcd(etcdArguments(t, declared, tc.argv...), EtcdFrom, EtcdTo)
			if err != nil || prepared.State != StateUnknown || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`) {
				t.Fatalf("prepared=%+v err=%v input=%s", prepared, err, prepared.CanonicalInputJSON)
			}
		})
	}

	raw := []byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","argv":["--enable-v2=true"]}`)
	prepared, err := PrepareEtcd(raw, EtcdFrom, EtcdTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonEtcdAuthorityMissing {
		t.Fatalf("missing declaration prepared=%+v err=%v", prepared, err)
	}
}

func TestPrepareEtcdExactPairAndInputSchema(t *testing.T) {
	prepared, err := PrepareEtcd(etcdArguments(t, true, "--enable-v2=true"), "3.5.16", EtcdTo)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonEtcdUnsupportedPair {
		t.Fatalf("unsupported pair prepared=%+v err=%v", prepared, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":true,"argv":[1]}`),
		[]byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":true,"argv":[],"extra":true}`),
		[]byte(`{"apiVersion":"` + EtcdAPI + `","kind":"` + EtcdKind + `","effectiveArgvDeclared":true,"argv":[]}{}`),
	} {
		if _, err := PrepareEtcd(raw, EtcdFrom, EtcdTo); err == nil {
			t.Fatalf("invalid input accepted: %s", raw)
		}
	}
}

func mustTime(value string) (result time.Time) {
	result, _ = time.Parse(time.RFC3339, value)
	return
}

func TestPrepareEtcdLatestExperimentalFlagPair(t *testing.T) {
	for _, tc := range []struct {
		name  string
		argv  []string
		state State
		value any
	}{
		{"removed flag", []string{"--name=node", "--experimental-memory-mlock=true"}, StatePrepared, true},
		{"documented replacement", []string{"--name=node", "--feature-gates=CompactHashCheck=true"}, StatePrepared, false},
		{"unsupported inferred replacement", []string{"--name=node", "--compact-hash-check-enabled=true"}, StateUnknown, nil},
		{"target only flag", []string{"--name=node", "--snapshot-count=10000"}, StatePrepared, false},
		{"old only flag", []string{"--name=node", "--experimental-enable-lease-checkpoint=true"}, StatePrepared, true},
		{"unknown experimental", []string{"--name=node", "--experimental-future=x"}, StateUnknown, nil},
		{"old allowlist is insufficient", []string{"--name=node", "--experimental-enable-v2v3=write-only"}, StateUnknown, nil},
		{"unknown target flag", []string{"--name=node", "--target-future=x"}, StateUnknown, nil},
		{"config file", []string{"--config-file=private"}, StateUnknown, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareEtcd(etcdArguments(t, true, tc.argv...), "3.6.14", EtcdLatestTo)
			if err != nil || prepared.State != tc.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			fact := preparedFacts(t, prepared)[EtcdLatestFact]
			if tc.value == nil {
				if _, ok := fact["boolValue"]; ok {
					t.Fatalf("unexpected fact=%v", fact)
				}
				return
			}
			if fact["state"] != "declared" || fact["boolValue"] != tc.value {
				t.Fatalf("fact=%v", fact)
			}
		})
	}
}

func TestPrepareEtcdLatestAllExactOriginsAndHopPrecedence(t *testing.T) {
	for _, from := range []string{"3.6.14", "3.5.33", "3.4.45", "3.3.27", "3.2.32"} {
		t.Run(from+"/removed", func(t *testing.T) {
			prepared, err := PrepareEtcd(etcdArguments(t, true, "--name=node", "--experimental-compact-hash-check-enabled=true"), from, EtcdLatestTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonEtcdExperimentalWitness {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			report, err := cncfcheck.Check("etcd", prepared.CanonicalInputJSON, mustTime("2026-09-12T07:38:00Z"))
			if err != nil || len(report.Check.Claims) == 0 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			for _, claim := range report.Check.Claims {
				if claim.Status != "BLOCKED" {
					t.Fatalf("claim=%+v", claim)
				}
			}
		})
		t.Run(from+"/replacement", func(t *testing.T) {
			prepared, err := PrepareEtcd(etcdArguments(t, true, "--name=node", "--feature-gates=CompactHashCheck=true"), from, EtcdLatestTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonEtcdExperimentalAbsent {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			report, err := cncfcheck.Check("etcd", prepared.CanonicalInputJSON, mustTime("2026-09-12T07:38:00Z"))
			if err != nil || len(report.Check.Claims) == 0 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			if from == "3.6.14" {
				if len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "PASS" {
					t.Fatalf("adjacent replacement report=%+v", report)
				}
				return
			}
			blocked, passed := 0, 0
			for _, claim := range report.Check.Claims {
				switch claim.Status {
				case "BLOCKED":
					blocked++
				case "PASS":
					passed++
				}
			}
			if blocked != 1 || passed != 1 {
				t.Fatalf("skipped replacement must remain hop-blocked: %+v", report)
			}
		})
	}
}

func TestPrepareEtcdLatestMissingAmbiguousAndWrongPairsRemainUnknown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		declared bool
		argv     []string
		from     string
		to       string
		reason   Reason
	}{
		{"missing declaration", false, []string{"--experimental-memory-mlock=true"}, "3.6.14", EtcdLatestTo, ReasonEtcdAuthorityMissing},
		{"ambiguous separated value", true, []string{"--feature-gates", "CompactHashCheck=true"}, "3.6.14", EtcdLatestTo, ReasonEtcdArgvUnsupported},
		{"unsupported inferred replacement", true, []string{"--compact-hash-check-enabled=true"}, "3.6.14", EtcdLatestTo, ReasonEtcdArgvUnsupported},
		{"duplicate", true, []string{"--name=node", "--name=other"}, "3.6.14", EtcdLatestTo, ReasonEtcdArgvUnsupported},
		{"wrong origin", true, []string{"--feature-gates=CompactHashCheck=true"}, "3.6.13", EtcdLatestTo, ReasonEtcdUnsupportedPair},
		{"wrong target", true, []string{"--feature-gates=CompactHashCheck=true"}, "3.6.14", "3.7.0", ReasonEtcdUnsupportedPair},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareEtcd(etcdArguments(t, tc.declared, tc.argv...), tc.from, tc.to)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != tc.reason || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue"`) {
				t.Fatalf("prepared=%+v err=%v input=%s", prepared, err, prepared.CanonicalInputJSON)
			}
		})
	}
}
