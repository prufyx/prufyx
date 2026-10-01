// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const kedaExternalNoCertFile = `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"scaleTargetRef":{"name":"private-workload"},"triggers":[{"type":"external","metadata":{"scalerAddress":"private-scaler.svc:9090"}}]}}`
const kedaExternalWithCertFile = `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"scaleTargetRef":{"name":"private-workload"},"triggers":[{"type":"external","metadata":{"scalerAddress":"private-scaler.svc:9090","tlsCertFile":"/etc/private-certs/tls.crt"}}]}}`
const kedaCPUOnly = `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"scaleTargetRef":{"name":"private-workload"},"triggers":[{"type":"cpu","metadata":{"value":"60"}}]}}`

// The reviewed condition fact says in its own description that a raw
// tlsCertFile metadata field is not sufficient to establish reliance on the
// removed direct transport. Presence therefore never becomes a true fact on
// its own; it requires the operator's explicit declaration.
func TestPrepareKEDAScaledObject_PresenceNeverDerivesTheConditionFact(t *testing.T) {
	prepared, err := PrepareKEDAScaledObject([]byte(kedaExternalWithCertFile), KEDAFrom, KEDATo, "", true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKEDATransportUndeclared {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	canonical := string(prepared.CanonicalInputJSON)
	if strings.Contains(canonical, `"`+KEDALegacyTLSTransportFact+`","state":"declared"`) {
		t.Fatalf("presence alone declared the condition fact: %s", canonical)
	}
	if !strings.Contains(canonical, `"`+KEDAExternalScalerFact+`","state":"declared","boolValue":true`) {
		t.Fatalf("applicability guard not derived: %s", canonical)
	}
}

func TestPrepareKEDAScaledObject_ResolvedConditionOutcomes(t *testing.T) {
	trueValue, falseValue := true, false
	tests := []struct {
		name, raw, declaration string
		state                  State
		reason                 Reason
		want                   *bool
	}{
		{"cert file absent derives false", kedaExternalNoCertFile, "", StatePrepared, ReasonKEDALegacyCertFileAbsent, &falseValue},
		{"cert file absent with explicit false", kedaExternalNoCertFile, KEDADeclarationNotRequired, StatePrepared, ReasonKEDALegacyCertFileAbsent, &falseValue},
		{"cert file present with declared reliance", kedaExternalWithCertFile, KEDADeclarationRequired, StatePrepared, ReasonKEDATransportRequired, &trueValue},
		{"cert file present declared forwarded only", kedaExternalWithCertFile, KEDADeclarationNotRequired, StatePrepared, ReasonKEDATransportNotRequired, &falseValue},
		{"external-push trigger is in scope", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"triggers":[{"type":"external-push","metadata":{"scalerAddress":"private-scaler.svc:9090","tlsCertFile":"/etc/private-certs/tls.crt"}}]}}`, KEDADeclarationRequired, StatePrepared, ReasonKEDATransportRequired, &trueValue},
		{"non-external trigger alongside external", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"triggers":[{"type":"cpu","metadata":{"value":"60"}},{"type":"external","metadata":{"scalerAddress":"private-scaler.svc:9090"}}]}}`, "", StatePrepared, ReasonKEDALegacyCertFileAbsent, &falseValue},
		{"flat v1 list of scaled objects", `{"apiVersion":"v1","kind":"List","items":[` + kedaExternalNoCertFile + `,` + kedaExternalWithCertFile + `]}`, KEDADeclarationRequired, StatePrepared, ReasonKEDATransportRequired, &trueValue},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKEDAScaledObject([]byte(test.raw), KEDAFrom, KEDATo, test.declaration, true)
			if err != nil || prepared.State != test.state || prepared.Reason != test.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			canonical := string(prepared.CanonicalInputJSON)
			want := `"boolValue":false`
			if *test.want {
				want = `"boolValue":true`
			}
			if !strings.Contains(canonical, `"`+KEDALegacyTLSTransportFact+`","state":"declared",`+want) {
				t.Fatalf("condition fact = %s, want %s", canonical, want)
			}
			if strings.Contains(canonical, "private-") {
				t.Fatalf("canonical input retained private names: %s", canonical)
			}
		})
	}
}

// A ScaledObject with no External Scaler trigger declares the rule's guard
// false and stops. The condition fact must never be declared from it.
func TestPrepareKEDAScaledObject_NoExternalScalerDeclaresGuardFalseOnly(t *testing.T) {
	for _, declaration := range []string{"", KEDADeclarationNotRequired, KEDADeclarationRequired} {
		prepared, err := PrepareKEDAScaledObject([]byte(kedaCPUOnly), KEDAFrom, KEDATo, declaration, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKEDAExternalScalerAbsent {
			t.Fatalf("declaration=%q prepared=%+v err=%v", declaration, prepared, err)
		}
		canonical := string(prepared.CanonicalInputJSON)
		if !strings.Contains(canonical, `"`+KEDAExternalScalerFact+`","state":"declared","boolValue":false`) {
			t.Fatalf("guard not declared false: %s", canonical)
		}
		if strings.Contains(canonical, `"`+KEDALegacyTLSTransportFact+`","state":"declared"`) {
			t.Fatalf("declaration=%q declared a condition fact without an external scaler: %s", declaration, canonical)
		}
	}
}

// A TriggerAuthentication reference can supply the effective metadata this
// route never reads, so the absence of tlsCertFile in the document is not the
// absence of the effective value.
func TestPrepareKEDAScaledObject_AuthenticationRefBlocksDerivedAbsence(t *testing.T) {
	const raw = `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"private-scaler"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"private-scaler.svc:9090"},"authenticationRef":{"name":"private-auth"}}]}}`
	prepared, err := PrepareKEDAScaledObject([]byte(raw), KEDAFrom, KEDATo, "", true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKEDATransportUndeclared {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if strings.Contains(string(prepared.CanonicalInputJSON), `"`+KEDALegacyTLSTransportFact+`","state":"declared"`) {
		t.Fatalf("derived a condition fact behind a TriggerAuthentication reference: %s", prepared.CanonicalInputJSON)
	}
	// With the operator's own declaration the fact is resolvable again.
	prepared, err = PrepareKEDAScaledObject([]byte(raw), KEDAFrom, KEDATo, KEDADeclarationRequired, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonKEDATransportRequired {
		t.Fatalf("declared prepared=%+v err=%v", prepared, err)
	}
}

// Declaring reliance on a removed behavior that reads a field the complete
// selection does not carry and cannot obtain out of band is a contradiction,
// and resolves to nothing rather than to either predicate value.
func TestPrepareKEDAScaledObject_ConflictingDeclarationStaysUnknown(t *testing.T) {
	prepared, err := PrepareKEDAScaledObject([]byte(kedaExternalNoCertFile), KEDAFrom, KEDATo, KEDADeclarationRequired, true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKEDATransportConflict {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if strings.Contains(string(prepared.CanonicalInputJSON), `"`+KEDALegacyTLSTransportFact+`","state":"declared"`) {
		t.Fatalf("conflict declared a condition fact: %s", prepared.CanonicalInputJSON)
	}
}

func TestPrepareKEDAScaledObject_GuardsPrecedeDocumentClassification(t *testing.T) {
	tests := []struct {
		name, from, to string
		complete       bool
		reason         Reason
	}{
		{"unreviewed origin", "2.15.1", KEDATo, true, ReasonKEDAPairUnsupported},
		{"unreviewed target", KEDAFrom, "2.18.0", true, ReasonKEDAPairUnsupported},
		{"patch origin is not the reviewed pair", "2.16.1", KEDATo, true, ReasonKEDAPairUnsupported},
		{"selection scope undeclared", KEDAFrom, KEDATo, false, ReasonKEDASelectionIncomplete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKEDAScaledObject([]byte(kedaExternalNoCertFile), test.from, test.to, "", test.complete)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != test.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), `"state":"declared"`) {
				t.Fatalf("guard failure declared a fact: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareKEDAScaledObject_UnresolvedShapesStayUnknown(t *testing.T) {
	tests := []struct {
		name, raw string
		reason    Reason
	}{
		{"template marker", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"{{ .Values.addr }}"}}]}}`, ReasonKEDATemplated},
		{"shell substitution", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"${ADDR}"}}]}}`, ReasonKEDATemplated},
		{"unreviewed served version", `{"apiVersion":"keda.sh/v1beta1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"a"}}]}}`, ReasonKEDAUnreviewedAPI},
		{"scaled job is another surface", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledJob","metadata":{"name":"s"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"a"}}]}}`, ReasonKEDASurfaceOther},
		{"trigger authentication is another surface", `{"apiVersion":"keda.sh/v1alpha1","kind":"TriggerAuthentication","metadata":{"name":"s"},"spec":{}}`, ReasonKEDASurfaceOther},
		{"unrelated object", `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"s"},"spec":{}}`, ReasonKEDASurfaceOther},
		{"paginated list", `{"apiVersion":"v1","kind":"List","metadata":{"continue":"token"},"items":[` + kedaExternalNoCertFile + `]}`, ReasonKEDAPagination},
		{"typed list", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObjectList","items":[]}`, ReasonKEDAInputUnsupported},
		{"empty list", `{"apiVersion":"v1","kind":"List","items":[]}`, ReasonKEDAInputUnsupported},
		{"missing name", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"a"}}]}}`, ReasonKEDAInputUnsupported},
		{"missing triggers", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{}}`, ReasonKEDAInputUnsupported},
		{"empty triggers", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{"triggers":[]}}`, ReasonKEDAInputUnsupported},
		{"trigger without type", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{"triggers":[{"metadata":{}}]}}`, ReasonKEDAInputUnsupported},
		{"external trigger without metadata", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{"triggers":[{"type":"external"}]}}`, ReasonKEDAInputUnsupported},
		{"non-string metadata value", `{"apiVersion":"keda.sh/v1alpha1","kind":"ScaledObject","metadata":{"name":"s"},"spec":{"triggers":[{"type":"external","metadata":{"scalerAddress":"a","tlsCertFile":7}}]}}`, ReasonKEDAInputUnsupported},
		{"array root", `[` + kedaExternalNoCertFile + `]`, ReasonKEDAInputUnsupported},
		{"scalar root", `"scaledobject"`, ReasonKEDAInputUnsupported},
		{"truncated json", `{"apiVersion":"keda.sh/v1alpha1",`, ReasonKEDAInputUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareKEDAScaledObject([]byte(test.raw), KEDAFrom, KEDATo, KEDADeclarationNotRequired, true)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != test.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), `"state":"declared"`) {
				t.Fatalf("unresolved input declared a fact: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

// One unresolvable document in a selection keeps the whole selection UNKNOWN
// rather than being silently skipped.
func TestPrepareKEDAScaledObject_OneUnresolvableItemStopsTheSelection(t *testing.T) {
	raw := `{"apiVersion":"v1","kind":"List","items":[` + kedaExternalNoCertFile + `,{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"other"},"spec":{}}]}`
	prepared, err := PrepareKEDAScaledObject([]byte(raw), KEDAFrom, KEDATo, "", true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonKEDASurfaceOther {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if strings.Contains(string(prepared.CanonicalInputJSON), `"state":"declared"`) {
		t.Fatalf("mixed selection declared a fact: %s", prepared.CanonicalInputJSON)
	}
}

func TestPrepareKEDAScaledObject_RejectsRawBoundsVersionSyntaxAndDeclarationToken(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0xff},
		make([]byte, maxInputBytes+1),
	} {
		if _, err := PrepareKEDAScaledObject(raw, KEDAFrom, KEDATo, "", true); err == nil {
			t.Fatalf("accepted raw input of %d bytes", len(raw))
		}
	}
	for _, from := range []string{"", "2.16", "v2.16.0", KEDATo} {
		if _, err := PrepareKEDAScaledObject([]byte(kedaExternalNoCertFile), from, KEDATo, "", true); err == nil {
			t.Fatalf("accepted from version %q", from)
		}
	}
	for _, declaration := range []string{"TRUE", "yes", "1", "required"} {
		if _, err := PrepareKEDAScaledObject([]byte(kedaExternalNoCertFile), KEDAFrom, KEDATo, declaration, true); err == nil {
			t.Fatalf("accepted declaration token %q", declaration)
		}
	}
}

func TestPrepareKEDAScaledObject_DigestsAndOmissionsAreStable(t *testing.T) {
	first, err := PrepareKEDAScaledObject([]byte(kedaExternalWithCertFile), KEDAFrom, KEDATo, KEDADeclarationRequired, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareKEDAScaledObject([]byte(kedaExternalWithCertFile), KEDAFrom, KEDATo, KEDADeclarationRequired, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceDigest != second.SourceDigest || first.InputDigest != second.InputDigest {
		t.Fatalf("unstable digests %+v %+v", first, second)
	}
	if first.SourceDigest != digestBytes([]byte(kedaExternalWithCertFile)) || first.InputDigest != digestBytes(first.CanonicalInputJSON) {
		t.Fatalf("digest bindings %+v", first)
	}
	if len(first.Omissions) != 4 || first.Omissions[3] != OmissionNoWholeUpgrade || first.Omissions[2] != OmissionNoLiveObservation {
		t.Fatalf("omissions = %v", first.Omissions)
	}
}
