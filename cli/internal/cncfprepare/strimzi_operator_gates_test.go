// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const strimziCanary = "canary-private-value"

func strimziOperatorDeployment(containers ...string) string {
	return `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"private-operator","namespace":"private-ns"},"spec":{"template":{"spec":{"containers":[` + strings.Join(containers, ",") + `]}}}}`
}

func strimziOperatorContainerWith(extra string) string {
	return `{"name":"strimzi-cluster-operator","image":"registry.invalid/private/operator:0.44.0"` + extra + `}`
}

func strimziGatesEnv(value string) string {
	encoded, _ := json.Marshal(value)
	return `,"env":[{"name":"STRIMZI_NAMESPACE","value":"` + strimziCanary + `"},{"name":"STRIMZI_FEATURE_GATES","value":` + string(encoded) + `}]`
}

// gatesFact decodes the canonical input and returns the proposed-side gates
// fact (state, members, complete).
func gatesFact(t *testing.T, prepared Prepared) (string, []string, bool) {
	t.Helper()
	var envelope inputEnvelope
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Current.Components[0].Facts) != 0 {
		t.Fatalf("current side must stay empty: %+v", envelope.Current)
	}
	for _, fact := range envelope.Proposed.Components[0].Facts {
		if fact.ID != StrimziOperatorGatesFact {
			continue
		}
		if fact.SetValue == nil {
			return fact.State, nil, false
		}
		return fact.State, fact.SetValue.Members, fact.SetValue.Complete
	}
	t.Fatal("no gates fact")
	return "", nil, false
}

func prepareOperator(t *testing.T, raw string, complete bool) Prepared {
	t.Helper()
	prepared, err := PrepareStrimziOperatorDeployment([]byte(raw), StrimziOperatorGatesFrom, StrimziOperatorGatesTo, StrimziDistributionOfficial, complete)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return prepared
}

// noLeak fails when any retained or reported text holds the canary, a private
// name, or the raw env value.
func noLeak(t *testing.T, prepared Prepared, forbidden ...string) {
	t.Helper()
	all := string(prepared.CanonicalInputJSON) + prepared.Reason + prepared.State + prepared.SourceDigest + strings.Join(prepared.Omissions, "|")
	for _, text := range append([]string{strimziCanary, "private-", "registry.invalid"}, forbidden...) {
		if text == "" {
			continue
		}
		if strings.Contains(all, text) {
			t.Fatalf("output retained %q: %s", text, all)
		}
	}
}

func TestPrepareStrimziOperatorDeployment_GateSyntaxIsTheOperatorsOwn(t *testing.T) {
	const known = "ContinueReconciliationOnManualRollingUpdateFailure"
	tests := []struct {
		name, value string
		members     []string
		complete    bool
	}{
		{"plus UseKRaft", "+UseKRaft", []string{"UseKRaft"}, true},
		{"minus UseKRaft", "-UseKRaft", []string{"UseKRaft"}, true},
		{"whitespace around a token is valid", " +UseKRaft ", []string{"UseKRaft"}, true},
		{"tab and newline around tokens are valid", "\t+UseKRaft\n,\n-" + known + "\r", []string{known, "UseKRaft"}, true},
		{"vertical tab and form feed are Java whitespace", "\x0b+UseKRaft\x0c", []string{"UseKRaft"}, true},
		{"known 0.44 gate only", "+" + known, []string{known}, true},
		{"duplicate names collapse", "+UseKRaft,-UseKRaft", []string{"UseKRaft"}, true},
		{"empty value is the empty complete set", "", []string{}, true},
		{"whitespace-only value is the empty complete set", " \t\n", []string{}, true},
		{"bare name has no prefix and is no member", "UseKRaft", []string{}, false},
		{"bare name in a list", "+" + known + ",UseKRaft", []string{}, false},
		{"double plus", "++UseKRaft", []string{}, false},
		{"plus minus", "+-UseKRaft", []string{}, false},
		{"only commas", ",,", []string{}, false},
		{"trailing comma", "+UseKRaft,", []string{}, false},
		{"leading comma", ",+UseKRaft", []string{}, false},
		{"empty token between", "+UseKRaft,,-" + known, []string{}, false},
		{"space inside a name", "+Use KRaft", []string{}, false},
		{"tab inside a name", "+Use\tKRaft", []string{}, false},
		{"newline inside a name", "+Use\nKRaft", []string{}, false},
		{"underscore", "+Use_KRaft", []string{}, false},
		{"dot", "+Use.KRaft", []string{}, false},
		{"no comma between prefixed tokens", "+UseKRaft+" + known, []string{}, false},
		{"non-breaking space", "+UseKRaft ", []string{}, false},
		{"control character only", "\x01", []string{}, false},
		{"prefix alone", "+", []string{}, false},
		{"lower-case spelling is another name", "+usekraft", []string{"usekraft"}, false},
		{"unknown gate", "+SomeOtherGate", []string{"SomeOtherGate"}, false},
		{"known beside unknown", "+" + known + ",-SomeOtherGate", []string{known, "SomeOtherGate"}, false},
		{"UseKRaft beside unknown still names UseKRaft", "+UseKRaft,+SomeOtherGate", []string{"SomeOtherGate", "UseKRaft"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared := prepareOperator(t, strimziOperatorDeployment(strimziOperatorContainerWith(strimziGatesEnv(test.value))), false)
			state, members, complete := gatesFact(t, prepared)
			if state != "declared" || prepared.State != StatePrepared || prepared.Reason != ReasonStrimziOperatorGatesDeclared {
				t.Fatalf("state=%s prepared=%s reason=%s", state, prepared.State, prepared.Reason)
			}
			if !reflect.DeepEqual(members, test.members) || complete != test.complete {
				t.Fatalf("members=%v complete=%v, want %v %v", members, complete, test.members, test.complete)
			}
			noLeak(t, prepared, test.value)
		})
	}
}

func TestPrepareStrimziOperatorDeployment_OversizeValuesAreUnsupported(t *testing.T) {
	var many []string
	for i := 0; i < 300; i++ {
		many = append(many, fmt.Sprintf("+g%03d", i))
	}
	for name, value := range map[string]string{
		"more members than a set holds": strings.Join(many, ","),
		"value above the byte cap":      "+" + strings.Repeat("a", strimziGatesMaxValue),
		"member above the set bound":    "+" + strings.Repeat("a", 129),
	} {
		t.Run(name, func(t *testing.T) {
			prepared := prepareOperator(t, strimziOperatorDeployment(strimziOperatorContainerWith(strimziGatesEnv(value))), true)
			state, members, _ := gatesFact(t, prepared)
			if state != "missing" || members != nil || prepared.State != StateUnknown || prepared.Reason != ReasonStrimziOperatorUnresolved {
				t.Fatalf("state=%s members=%v prepared=%s reason=%s", state, members, prepared.State, prepared.Reason)
			}
			noLeak(t, prepared, value)
		})
	}
}

func TestPrepareStrimziOperatorDeployment_AbsentVariable(t *testing.T) {
	for _, test := range []struct {
		name, container string
		complete        bool
		state           string
		complete2       bool
		reason          Reason
	}{
		{"no env, no declaration", strimziOperatorContainerWith(""), false, "missing", false, ReasonStrimziOperatorGatesAbsent},
		{"no env, declared complete", strimziOperatorContainerWith(""), true, "declared", true, ReasonStrimziOperatorGatesDeclared},
		{"empty env, declared complete", strimziOperatorContainerWith(`,"env":[]`), true, "declared", true, ReasonStrimziOperatorGatesDeclared},
		{"empty envFrom, declared complete", strimziOperatorContainerWith(`,"envFrom":[]`), true, "declared", true, ReasonStrimziOperatorGatesDeclared},
		{"other env only, no declaration", strimziOperatorContainerWith(`,"env":[{"name":"STRIMZI_NAMESPACE","value":"` + strimziCanary + `"}]`), false, "missing", false, ReasonStrimziOperatorGatesAbsent},
		{"other env only, declared complete", strimziOperatorContainerWith(`,"env":[{"name":"STRIMZI_NAMESPACE","value":"` + strimziCanary + `"}]`), true, "declared", true, ReasonStrimziOperatorGatesDeclared},
		{"envFrom secret, declared complete", strimziOperatorContainerWith(`,"envFrom":[{"secretRef":{"name":"` + strimziCanary + `"}}]`), true, "missing", false, ReasonStrimziOperatorEnvFrom},
		{"envFrom configMap, no declaration", strimziOperatorContainerWith(`,"envFrom":[{"configMapRef":{"name":"` + strimziCanary + `"}}]`), false, "missing", false, ReasonStrimziOperatorEnvFrom},
		{"envFrom with other env, declared complete", strimziOperatorContainerWith(`,"env":[{"name":"X","value":"1"}],"envFrom":[{"secretRef":{"name":"s"}}]`), true, "missing", false, ReasonStrimziOperatorEnvFrom},
		{"variable name in another case is another variable", strimziOperatorContainerWith(`,"env":[{"name":"strimzi_feature_gates","value":"+UseKRaft"}]`), false, "missing", false, ReasonStrimziOperatorGatesAbsent},
		{"gates only in a sidecar are not read", strimziOperatorContainerWith("") + `,{"name":"sidecar","env":[{"name":"STRIMZI_FEATURE_GATES","value":"+UseKRaft"}]}`, false, "missing", false, ReasonStrimziOperatorGatesAbsent},
		{"envFrom of the wrong type", strimziOperatorContainerWith(`,"envFrom":"x"`), true, "missing", false, ReasonStrimziOperatorUnresolved},
		{"env of the wrong type", strimziOperatorContainerWith(`,"env":{}`), true, "missing", false, ReasonStrimziOperatorUnresolved},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared := prepareOperator(t, strimziOperatorDeployment(test.container), test.complete)
			state, members, complete := gatesFact(t, prepared)
			if state != test.state || complete != test.complete2 || prepared.Reason != test.reason {
				t.Fatalf("state=%s members=%v complete=%v reason=%s", state, members, complete, prepared.Reason)
			}
			if state == "declared" && (len(members) != 0 || prepared.State != StatePrepared) {
				t.Fatalf("absent variable must be the empty set: %v %s", members, prepared.State)
			}
			if state == "missing" && prepared.State != StateUnknown {
				t.Fatalf("state=%s", prepared.State)
			}
			noLeak(t, prepared)
		})
	}
}

// A literal value wins over envFrom, as in Kubernetes.
func TestPrepareStrimziOperatorDeployment_LiteralBeatsEnvFrom(t *testing.T) {
	prepared := prepareOperator(t, strimziOperatorDeployment(strimziOperatorContainerWith(strimziGatesEnv("+UseKRaft")[:len(strimziGatesEnv("+UseKRaft"))-1]+`],"envFrom":[{"secretRef":{"name":"s"}}]`)), false)
	if _, members, _ := gatesFact(t, prepared); !reflect.DeepEqual(members, []string{"UseKRaft"}) {
		t.Fatalf("members=%v", members)
	}
	noLeak(t, prepared)
}

func TestPrepareStrimziOperatorDeployment_UnresolvedShapesStayUnknown(t *testing.T) {
	gates := `{"name":"STRIMZI_FEATURE_GATES","value":"+UseKRaft"}`
	good := strimziOperatorContainerWith(`,"env":[` + gates + `]`)
	for _, test := range []struct {
		name, raw string
		reason    Reason
	}{
		{"valueFrom", strimziOperatorDeployment(strimziOperatorContainerWith(`,"env":[{"name":"STRIMZI_FEATURE_GATES","valueFrom":{"secretKeyRef":{"name":"` + strimziCanary + `","key":"k"}}}]`)), ReasonStrimziOperatorUnresolved},
		{"value and valueFrom", strimziOperatorDeployment(strimziOperatorContainerWith(`,"env":[{"name":"STRIMZI_FEATURE_GATES","value":"+UseKRaft","valueFrom":{"configMapKeyRef":{"name":"c","key":"k"}}}]`)), ReasonStrimziOperatorUnresolved},
		{"no value at all", strimziOperatorDeployment(strimziOperatorContainerWith(`,"env":[{"name":"STRIMZI_FEATURE_GATES"}]`)), ReasonStrimziOperatorUnresolved},
		{"non-string value", strimziOperatorDeployment(strimziOperatorContainerWith(`,"env":[{"name":"STRIMZI_FEATURE_GATES","value":true}]`)), ReasonStrimziOperatorUnresolved},
		{"duplicate variable", strimziOperatorDeployment(strimziOperatorContainerWith(`,"env":[` + gates + `,{"name":"STRIMZI_FEATURE_GATES","value":"-UseKRaft"}]`)), ReasonStrimziOperatorUnresolved},
		{"env entry without a name", strimziOperatorDeployment(strimziOperatorContainerWith(`,"env":[{"value":"x"},` + gates + `]`)), ReasonStrimziOperatorUnresolved},
		{"env entry that is not an object", strimziOperatorDeployment(strimziOperatorContainerWith(`,"env":["x",` + gates + `]`)), ReasonStrimziOperatorUnresolved},
		{"two operator containers", strimziOperatorDeployment(good, good), ReasonStrimziOperatorUnresolved},
		{"operator container absent", strimziOperatorDeployment(`{"name":"sidecar","env":[` + gates + `]}`), ReasonStrimziOperatorUnresolved},
		{"container without a name", strimziOperatorDeployment(`{"env":[`+gates+`]}`, good), ReasonStrimziOperatorUnresolved},
		{"container that is not an object", strimziOperatorDeployment(`"x"`, good), ReasonStrimziOperatorUnresolved},
		{"no containers array", `{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{}}}}`, ReasonStrimziOperatorUnresolved},
		{"not a Deployment", strings.Replace(strimziOperatorDeployment(good), `"Deployment"`, `"StatefulSet"`, 1), ReasonStrimziOperatorUnresolved},
		{"other apiVersion", strings.Replace(strimziOperatorDeployment(good), `apps/v1`, `apps/v1beta2`, 1), ReasonStrimziOperatorUnresolved},
		{"a List of Deployments", `{"apiVersion":"v1","kind":"List","items":[` + strimziOperatorDeployment(good) + `]}`, ReasonStrimziOperatorUnresolved},
		{"templated", strings.Replace(strimziOperatorDeployment(good), `+UseKRaft`, `{{ .Values.gates }}`, 1), ReasonStrimziOperatorTemplated},
		{"shell substitution", strings.Replace(strimziOperatorDeployment(good), `+UseKRaft`, `${GATES}`, 1), ReasonStrimziOperatorTemplated},
		{"duplicate JSON key", strings.Replace(strimziOperatorDeployment(good), `"kind":"Deployment"`, `"kind":"Deployment","kind":"Deployment"`, 1), ReasonStrimziOperatorUnresolved},
		{"duplicate key differing in case", strings.Replace(strimziOperatorDeployment(good), `"kind":"Deployment"`, `"kind":"Deployment","Kind":"Deployment"`, 1), ReasonStrimziOperatorUnresolved},
		{"trailing data", strimziOperatorDeployment(good) + ` {}`, ReasonStrimziOperatorUnresolved},
		{"scalar root", `"x"`, ReasonStrimziOperatorUnresolved},
		{"truncated", strimziOperatorDeployment(good)[:40], ReasonStrimziOperatorUnresolved},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared := prepareOperator(t, test.raw, true)
			state, members, _ := gatesFact(t, prepared)
			if state != "missing" || members != nil || prepared.State != StateUnknown || prepared.Reason != test.reason {
				t.Fatalf("state=%s members=%v prepared=%s reason=%s", state, members, prepared.State, prepared.Reason)
			}
			noLeak(t, prepared)
		})
	}
}

func TestPrepareStrimziOperatorDeployment_GuardsPrecedeTheDeployment(t *testing.T) {
	raw := []byte(strimziOperatorDeployment(strimziOperatorContainerWith(strimziGatesEnv("+UseKRaft"))))
	for _, test := range []struct {
		name, from, to, distribution string
		reason                       Reason
		distributionDeclared         bool
	}{
		{"later target", StrimziOperatorGatesFrom, "0.45.0", StrimziDistributionOfficial, ReasonStrimziPairUnsupported, true},
		{"other source patch", "0.41.1", StrimziOperatorGatesTo, StrimziDistributionOfficial, ReasonStrimziPairUnsupported, true},
		{"other target patch", StrimziOperatorGatesFrom, "0.44.1", StrimziDistributionOfficial, ReasonStrimziPairUnsupported, true},
		{"same version", StrimziOperatorGatesTo, StrimziOperatorGatesTo, StrimziDistributionOfficial, ReasonStrimziPairUnsupported, true},
		{"the other reviewed pair", StrimziFrom, StrimziTo, StrimziDistributionOfficial, ReasonStrimziPairUnsupported, true},
		{"distribution undeclared", StrimziOperatorGatesFrom, StrimziOperatorGatesTo, "", ReasonStrimziGuardUnresolved, false},
		{"distribution unknown token", StrimziOperatorGatesFrom, StrimziOperatorGatesTo, "vendor_build", ReasonStrimziGuardUnresolved, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareStrimziOperatorDeployment(raw, test.from, test.to, test.distribution, true)
			if err != nil {
				t.Fatal(err)
			}
			state, members, _ := gatesFact(t, prepared)
			if state != "missing" || members != nil || prepared.State != StateUnknown || prepared.Reason != test.reason {
				t.Fatalf("state=%s members=%v prepared=%s reason=%s", state, members, prepared.State, prepared.Reason)
			}
			noLeak(t, prepared)
		})
	}
	custom, err := PrepareStrimziOperatorDeployment(raw, StrimziOperatorGatesFrom, StrimziOperatorGatesTo, StrimziDistributionCustom, false)
	if err != nil || !strings.Contains(string(custom.CanonicalInputJSON), `"enumValue":"custom_build"`) {
		t.Fatalf("custom build must be declared, so the rule does not apply: %v %s", err, custom.CanonicalInputJSON)
	}
}

func TestPrepareStrimziOperatorDeployment_InvalidRequestsFailWithoutEchoing(t *testing.T) {
	good := []byte(strimziOperatorDeployment(strimziOperatorContainerWith(strimziGatesEnv("+UseKRaft"))))
	for name, call := range map[string]func() (Prepared, error){
		"empty": func() (Prepared, error) {
			return PrepareStrimziOperatorDeployment(nil, "0.41.0", "0.44.0", "official_upstream", false)
		},
		"oversize": func() (Prepared, error) {
			return PrepareStrimziOperatorDeployment(make([]byte, maxInputBytes+1), "0.41.0", "0.44.0", "official_upstream", false)
		},
		"invalid utf8": func() (Prepared, error) {
			return PrepareStrimziOperatorDeployment([]byte("\xff"+string(good)), "0.41.0", "0.44.0", "official_upstream", false)
		},
		"bad version": func() (Prepared, error) {
			return PrepareStrimziOperatorDeployment(good, "0.41", "0.44.0", "official_upstream", false)
		},
	} {
		t.Run(name, func(t *testing.T) {
			prepared, err := call()
			if err != ErrInvalid || prepared.CanonicalInputJSON != nil {
				t.Fatalf("err=%v prepared=%+v", err, prepared)
			}
			if strings.Contains(err.Error(), strimziCanary) || strings.Contains(err.Error(), "UseKRaft") {
				t.Fatalf("error echoes input: %v", err)
			}
		})
	}
}

// Only the one reviewed variable is read: whatever else the Deployment holds
// never reaches the canonical input, whatever the outcome.
func TestPrepareStrimziOperatorDeployment_NothingElseIsCollected(t *testing.T) {
	container := `{"name":"strimzi-cluster-operator","image":"registry.invalid/private/operator:0.44.0","args":["--token=` + strimziCanary + `"],"command":["` + strimziCanary + `"],` +
		`"env":[{"name":"A","value":"` + strimziCanary + `"},{"name":"B","valueFrom":{"secretKeyRef":{"name":"` + strimziCanary + `","key":"k"}}},{"name":"STRIMZI_FEATURE_GATES","value":"+UseKRaft,-` + strimziCanary + `"}],` +
		`"envFrom":[{"secretRef":{"name":"` + strimziCanary + `"}}]}`
	raw := strimziOperatorDeployment(container)
	prepared := prepareOperator(t, raw, true)
	noLeak(t, prepared)
	var envelope inputEnvelope
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Proposed.Components) != 1 || len(envelope.Proposed.Components[0].Facts) != 2 {
		t.Fatalf("unexpected facts: %s", prepared.CanonicalInputJSON)
	}
	// A hyphen is not part of a name, so this value is malformed and no member
	// is emitted, not even the valid-looking one.
	if state, members, complete := gatesFact(t, prepared); state != "declared" || len(members) != 0 || complete {
		t.Fatalf("state=%s members=%v complete=%v", state, members, complete)
	}
}

func TestPrepareStrimziOperatorDeployment_ReplayBytesAreStable(t *testing.T) {
	raw := strimziOperatorDeployment(strimziOperatorContainerWith(strimziGatesEnv("-UseKRaft, +ContinueReconciliationOnManualRollingUpdateFailure")))
	first, second := prepareOperator(t, raw, false), prepareOperator(t, raw, false)
	if string(first.CanonicalInputJSON) != string(second.CanonicalInputJSON) || first.InputDigest != second.InputDigest || first.SourceDigest != second.SourceDigest {
		t.Fatal("preparation is not deterministic")
	}
	if !strings.HasSuffix(string(first.CanonicalInputJSON), "}\n") || strings.Count(string(first.CanonicalInputJSON), "\n") != 1 {
		t.Fatalf("canonical input must be compact with one trailing newline: %q", first.CanonicalInputJSON)
	}
	if first.InputDigest != digestBytes(first.CanonicalInputJSON) || first.SourceDigest != digestBytes([]byte(raw)) {
		t.Fatal("digests do not bind the bytes")
	}
}

func TestStrimziKnownGatesAreSourcePinned(t *testing.T) {
	if !reflect.DeepEqual(StrimziKnownGates044, []string{"ContinueReconciliationOnManualRollingUpdateFailure"}) {
		t.Fatalf("0.44.0 gates: %v", StrimziKnownGates044)
	}
	if !reflect.DeepEqual(StrimziKnownGates041, []string{"ContinueReconciliationOnManualRollingUpdateFailure", "UseKRaft"}) {
		t.Fatalf("0.41.0 gates: %v", StrimziKnownGates041)
	}
	var removed []string
	for _, name := range StrimziKnownGates041 {
		known := false
		for _, other := range StrimziKnownGates044 {
			known = known || name == other
		}
		if !known {
			removed = append(removed, name)
		}
	}
	if !reflect.DeepEqual(removed, []string{"UseKRaft"}) {
		t.Fatalf("gates removed by 0.44.0: %v", removed)
	}
}
