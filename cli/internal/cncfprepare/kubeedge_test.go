// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

func kubeEdgeArgv(t *testing.T, tokens ...string) []byte {
	t.Helper()
	raw, err := json.Marshal(tokens)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func kubeEdgeTrue() *bool  { value := true; return &value }
func kubeEdgeFalse() *bool { value := false; return &value }

func TestPrepareKubeEdgeInitArgvSelectorForms(t *testing.T) {
	for _, test := range []struct {
		name      string
		tokens    []string
		state     State
		reason    Reason
		selector  string
		factState string
	}{
		{
			name:      "separated legacy profile version selector is a witness",
			tokens:    []string{"keadm", "init", "--advertise-address=127.0.0.1", "--profile", "version=v1.19.0"},
			state:     StatePrepared,
			reason:    ReasonKubeEdgeLegacyProfileVersion,
			selector:  KubeEdgeSelectorLegacyProfile,
			factState: "declared",
		},
		{
			name:      "attached legacy profile version selector is a witness",
			tokens:    []string{"/usr/local/bin/keadm", "init", "--profile=version=v1.19.0"},
			state:     StatePrepared,
			reason:    ReasonKubeEdgeLegacyProfileVersion,
			selector:  KubeEdgeSelectorLegacyProfile,
			factState: "declared",
		},
		{
			name:      "target version flag alone with absent profile resolves",
			tokens:    []string{"keadm", "init", "--kubeedge-version=v1.19.0", "--kube-config=/local/path"},
			state:     StatePrepared,
			reason:    ReasonKubeEdgeVersionFlagOnly,
			selector:  KubeEdgeSelectorVersionFlag,
			factState: "declared",
		},
		{
			name:      "separated target version flag alone resolves",
			tokens:    []string{"keadm", "init", "--kubeedge-version", "v1.19.0"},
			state:     StatePrepared,
			reason:    ReasonKubeEdgeVersionFlagOnly,
			selector:  KubeEdgeSelectorVersionFlag,
			factState: "declared",
		},
		{
			name:      "both selectors conflict",
			tokens:    []string{"keadm", "init", "--profile", "version=v1.19.0", "--kubeedge-version=v1.19.0"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeSelectorConflict,
			factState: "conflict",
		},
		{
			name:      "neither selector is missing",
			tokens:    []string{"keadm", "init", "--advertise-address=127.0.0.1"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeSelectorMissing,
			factState: "missing",
		},
		{
			// The pinned v1.18 --profile help documents "/path/version.yaml" as the
			// other accepted spelling, and the reviewed fact description states that
			// a version-like filename does not prove legacy intent.
			name:      "version-like external values filename is never a legacy witness",
			tokens:    []string{"keadm", "init", "--profile", "/local/version.yaml"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeSelectorUnsupported,
			factState: "unsupported",
		},
		{
			name:      "non-target version flag value is unsupported",
			tokens:    []string{"keadm", "init", "--kubeedge-version=v1.20.0"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeSelectorUnsupported,
			factState: "unsupported",
		},
		{
			name:      "repeated profile options with different meanings are unsupported",
			tokens:    []string{"keadm", "init", "--profile", "version=v1.19.0", "--profile", "/local/values.yaml"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeSelectorUnsupported,
			factState: "unsupported",
		},
		{
			name:      "shorthand spelling is unresolved",
			tokens:    []string{"keadm", "init", "-p", "version=v1.19.0"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeArgvUnresolved,
			factState: "unsupported",
		},
		{
			name:      "option delimiter is unresolved",
			tokens:    []string{"keadm", "init", "--", "--profile", "version=v1.19.0"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeArgvUnresolved,
			factState: "unsupported",
		},
		{
			name:      "missing profile value token is unresolved",
			tokens:    []string{"keadm", "init", "--profile"},
			state:     StateUnknown,
			reason:    ReasonKubeEdgeArgvUnresolved,
			factState: "unsupported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeEdgeInitArgv(kubeEdgeArgv(t, test.tokens...), KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue())
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.State != test.state || prepared.Reason != test.reason {
				t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
			}
			canonical := string(prepared.CanonicalInputJSON)
			if !strings.Contains(canonical, `"id":"`+KubeEdgeSelectorFact+`","state":"`+test.factState+`"`) {
				t.Fatalf("selector fact state %q missing: %s", test.factState, canonical)
			}
			if test.selector != "" && !strings.Contains(canonical, `"enumValue":"`+test.selector+`"`) {
				t.Fatalf("selector %q missing: %s", test.selector, canonical)
			}
			if !strings.Contains(canonical, `"id":"`+KubeEdgeSurfaceFact+`","state":"declared","enumValue":"`+KubeEdgeSurfaceInit+`"`) {
				t.Fatalf("surface not bound to keadm init: %s", canonical)
			}
			// No private argv token, path, or address may survive preparation.
			for _, secret := range []string{"127.0.0.1", "/local/path", "/local/version.yaml", "/local/values.yaml", "/usr/local/bin/keadm"} {
				if strings.Contains(canonical, secret) {
					t.Fatalf("private argv fragment %q retained: %s", secret, canonical)
				}
			}
		})
	}
}

func TestPrepareKubeEdgeInitArgvGuardsAndSurface(t *testing.T) {
	legacy := kubeEdgeArgv(t, "keadm", "init", "--profile", "version=v1.19.0")
	for _, test := range []struct {
		name         string
		raw          []byte
		from, to     string
		distribution string
		argvComplete *bool
		state        State
		reason       Reason
	}{
		{"missing distribution stays unknown", legacy, KubeEdgeFrom, KubeEdgeTo, "", kubeEdgeTrue(), StateUnknown, ReasonKubeEdgeGuardMissing},
		{"missing argv completeness stays unknown", legacy, KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, nil, StateUnknown, ReasonKubeEdgeGuardMissing},
		{"unreviewed pair stays unknown", legacy, "1.18.1", KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue(), StateUnknown, ReasonKubeEdgePairUnsupported},
		{"other keadm subcommand is another surface", kubeEdgeArgv(t, "keadm", "join", "--profile", "version=v1.19.0"), KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue(), StateUnknown, ReasonKubeEdgeSurfaceOther},
		{"wrapper is another surface", kubeEdgeArgv(t, "sh", "-c", "keadm init --profile version=v1.19.0"), KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue(), StateUnknown, ReasonKubeEdgeSurfaceOther},
		{"templated argv is unresolved", kubeEdgeArgv(t, "keadm", "init", "--kubeedge-version={{ .Values.version }}"), KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue(), StateUnknown, ReasonKubeEdgeTemplated},
		{"non-argv shape is unresolved", []byte(`{"argv":["keadm","init"]}`), KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue(), StateUnknown, ReasonKubeEdgeInputUnsupported},
		{"declared incomplete argv still records the caller declaration", legacy, KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeFalse(), StatePrepared, ReasonKubeEdgeLegacyProfileVersion},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKubeEdgeInitArgv(test.raw, test.from, test.to, test.distribution, test.argvComplete)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.State != test.state || prepared.Reason != test.reason {
				t.Fatalf("state=%s reason=%s", prepared.State, prepared.Reason)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "keadm init --profile") {
				t.Fatalf("wrapper string retained: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareKubeEdgeInitArgvRejectsMalformedEnvelope(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		[]byte(``),
		[]byte(`[]`),
		[]byte(`["keadm","init",""]`),
		[]byte(`["keadm","init",1]`),
	} {
		prepared, err := PrepareKubeEdgeInitArgv(raw, KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue())
		if err == nil && prepared.State != StateUnknown {
			t.Fatalf("accepted malformed argv %s", raw)
		}
	}
	if _, err := PrepareKubeEdgeInitArgv(kubeEdgeArgv(t, "keadm", "init"), KubeEdgeFrom, KubeEdgeTo, "unreviewed_distribution", kubeEdgeTrue()); err == nil {
		t.Fatal("accepted an unregistered distribution token")
	}
	if _, err := PrepareKubeEdgeInitArgv(kubeEdgeArgv(t, "keadm", "init"), "1.18", KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue()); err == nil {
		t.Fatal("accepted a non-canonical version")
	}
}

func TestPrepareKubeEdgeInitArgvOmissionsStayExplicit(t *testing.T) {
	prepared, err := PrepareKubeEdgeInitArgv(kubeEdgeArgv(t, "keadm", "init", "--kubeedge-version=v1.19.0"), KubeEdgeFrom, KubeEdgeTo, KubeEdgeDistributionOfficial, kubeEdgeTrue())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"DECLARED_ARGV_IS_CALLER_SUPPLIED_NOT_EXECUTED",
		"EXTERNAL_PROFILE_VALUES_FILES_NOT_OPENED_OR_INTERPRETED",
		OmissionNoLiveObservation,
		OmissionNoWholeUpgrade,
	} {
		found := false
		for _, omission := range prepared.Omissions {
			if omission == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing omission %q in %v", want, prepared.Omissions)
		}
	}
}
