// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "testing"

func openFGAComplete(value bool) *bool { return &value }

func TestPrepareOpenFGAOIDC(t *testing.T) {
	tests := []struct {
		name, raw, from, to string
		complete            *bool
		state               State
		reason              Reason
		wantMissing         bool
	}{
		{"missing issuer", `{"authn":{"method":"oidc","oidc":{"audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StatePrepared, ReasonOpenFGAMissing, true},
		{"missing audience", `{"authn":{"method":"oidc","oidc":{"issuer":"https://issuer.example.invalid"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StatePrepared, ReasonOpenFGAMissing, true},
		{"empty strings stay missing", `{"authn":{"method":"oidc","oidc":{"issuer":"","audience":""}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StatePrepared, ReasonOpenFGAMissing, true},
		{"whitespace is nonempty", `{"authn":{"method":"oidc","oidc":{"issuer":" ","audience":"\t"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StatePrepared, ReasonOpenFAPresent, false},
		{"both configured", `{"authn":{"method":"oidc","oidc":{"issuer":"https://issuer.example.invalid","audience":"aud"}},"unrelated":{"canary":"omit-me"}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StatePrepared, ReasonOpenFAPresent, false},
		{"no completeness flag", `{"authn":{"method":"oidc","oidc":{"issuer":"issuer","audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, nil, StateUnknown, ReasonOpenFGAIncomplete, true},
		{"false completeness flag", `{"authn":{"method":"oidc","oidc":{"issuer":"issuer","audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(false), StateUnknown, ReasonOpenFGAIncomplete, true},
		{"non oidc remains unknown", `{"authn":{"method":"none"}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"unknown method remains unknown", `{"authn":{"method":"future"}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"wrong selected type", `{"authn":{"method":"oidc","oidc":{"issuer":null,"audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"case ambiguous selected key", `{"authn":{"method":"oidc","oidc":{"issuer":"issuer","Issuer":"other","audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"single noncanonical authn key", `{"Authn":{"method":"oidc","oidc":{"issuer":"issuer","audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"single noncanonical oidc key", `{"authn":{"method":"oidc","OIDC":{"issuer":"issuer","audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"single noncanonical issuer key", `{"authn":{"method":"oidc","oidc":{"Issuer":"issuer","audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"dotted selected key", `{"authn.oidc.issuer":"issuer","authn":{"method":"oidc","oidc":{"audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"dotted selected keys under authn", `{"authn":{"method":"oidc","oidc.issuer":"issuer","oidc.audience":"aud"}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"mixed nested and dotted selected keys", `{"authn":{"method":"oidc","oidc.issuer":"issuer","oidc":{"audience":"aud"}}}`, OpenFGAFrom, OpenFGATo, openFGAComplete(true), StateUnknown, ReasonOpenFGAUnsupported, true},
		{"unsupported pair still extracts fact", `{"authn":{"method":"oidc","oidc":{"issuer":"issuer","audience":"aud"}}}`, "1.17.0", OpenFGATo, openFGAComplete(true), StatePrepared, ReasonOpenFGAPair, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareOpenFGAOIDC([]byte(test.raw), test.from, test.to, test.complete)
			if err != nil || prepared.State != test.state || prepared.Reason != test.reason {
				t.Fatalf("PrepareOpenFGAOIDC() = %#v, %v", prepared, err)
			}
			if len(prepared.CanonicalInputJSON) == 0 || prepared.InputDigest == prepared.SourceDigest {
				t.Fatalf("prepared declaration lacks independent canonical digest: %#v", prepared)
			}
			if test.wantMissing && string(prepared.CanonicalInputJSON) == "" {
				t.Fatal("missing declaration was empty")
			}
		})
	}
}

func TestPrepareOpenFGARejectsMalformedJSON(t *testing.T) {
	if _, err := PrepareOpenFGAOIDC([]byte(`{"authn":{"method":"oidc"}`), OpenFGAFrom, OpenFGATo, openFGAComplete(true)); err == nil {
		t.Fatal("expected malformed JSON rejection")
	}
	if _, err := PrepareOpenFGAOIDC([]byte(`{"authn":{"method":"oidc","method":"none"}}`), OpenFGAFrom, OpenFGATo, openFGAComplete(true)); err == nil {
		t.Fatal("expected exact duplicate JSON rejection")
	}
}
