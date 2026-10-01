// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"unicode/utf8"
)

const (
	KnativeComponent         = "pkg:github/knative/serving"
	KnativeStartupPortFact   = "component.knative.serving_startup_http_named_port_mismatch"
	KnativeFrom              = "1.22.0"
	KnativeTo                = "1.23.0"
	knativeServiceAPIVersion = "serving.knative.dev/v1"
	knativeServiceKind       = "Service"
)

var ErrInvalidKnative = ErrInvalid

const (
	ReasonKnativeStartupPortWitness  Reason = "KNATIVE_SERVING_STARTUP_HTTP_NAMED_PORT_WITNESS"
	ReasonKnativeResourceUnsupported Reason = "KNATIVE_SERVING_RESOURCE_SHAPE_UNSUPPORTED"
)

// PrepareKnativeServing derives one stable observation from one private
// proposed Knative Service. A selected rule supplies version applicability. It
// supports only a single user container with one
// explicitly named http1/h2c port and one HTTP startup probe using a named
// http1/h2c port. Every absent or ambiguous shape stays UNKNOWN.
func PrepareKnativeServing(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) ||
		!validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalidKnative
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalidKnative
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Prepared{}, ErrInvalidKnative
	}

	factState := "unsupported"
	var mismatch *bool
	state := StateUnknown
	reason := ReasonKnativeResourceUnsupported
	if observed, supported := inspectKnativeServingStartupPort(root); supported {
		mismatch = &observed
		factState = "declared"
		state = StatePrepared
		reason = ReasonKnativeStartupPortWitness
	}
	canonical, err := marshalComponentInput(KnativeComponent, from, to, []inputFact{{
		ID: KnativeStartupPortFact, State: factState, BoolValue: mismatch,
	}})
	if err != nil {
		return Prepared{}, ErrInvalidKnative
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"OTHER_KNATIVE_SERVICE_ADMISSION_CONSTRAINTS_NOT_EVALUATED",
			"MULTI_CONTAINER_AND_MULTI_PORT_SERVICES_NOT_EVALUATED",
			"NUMERIC_AND_NON_HTTP_STARTUP_PROBES_NOT_EVALUATED",
			OmissionNoLiveObservation,
			OmissionNoWholeUpgrade,
		},
	}, nil
}

func inspectKnativeServingStartupPort(root map[string]any) (bool, bool) {
	if stringField(root, "apiVersion") != knativeServiceAPIVersion || stringField(root, "kind") != knativeServiceKind {
		return false, false
	}
	spec := objectField(root, "spec")
	template := objectField(spec, "template")
	templateSpec := objectField(template, "spec")
	containers := arrayField(templateSpec, "containers")
	if len(containers) != 1 {
		return false, false
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		return false, false
	}
	ports := arrayField(container, "ports")
	if len(ports) != 1 {
		return false, false
	}
	port, ok := ports[0].(map[string]any)
	if !ok {
		return false, false
	}
	declaredName := stringField(port, "name")
	if !knativePortName(declaredName) || !validPortNumber(port["containerPort"]) {
		return false, false
	}
	if protocol, exists := port["protocol"]; exists && protocol != "TCP" {
		return false, false
	}
	probe := objectField(container, "startupProbe")
	if probe == nil || competingProbeHandler(probe) {
		return false, false
	}
	httpGet := objectField(probe, "httpGet")
	if httpGet == nil {
		return false, false
	}
	probeName := stringField(httpGet, "port")
	if !knativePortName(probeName) {
		return false, false
	}
	return probeName != declaredName, true
}

func objectField(object map[string]any, key string) map[string]any {
	if object == nil {
		return nil
	}
	value, _ := object[key].(map[string]any)
	return value
}

func arrayField(object map[string]any, key string) []any {
	if object == nil {
		return nil
	}
	value, _ := object[key].([]any)
	return value
}

func stringField(object map[string]any, key string) string {
	if object == nil {
		return ""
	}
	value, _ := object[key].(string)
	return value
}

func knativePortName(value string) bool {
	return value == "http1" || value == "h2c"
}

func validPortNumber(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Int64()
	return err == nil && parsed >= 1 && parsed <= 65535
}

func competingProbeHandler(probe map[string]any) bool {
	for _, key := range []string{"exec", "tcpSocket", "grpc"} {
		if _, exists := probe[key]; exists {
			return true
		}
	}
	return false
}
