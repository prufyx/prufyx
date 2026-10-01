// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"io"
)

const (
	MariaDBOperatorProject              = "mariadb-operator"
	MariaDBOperatorComponent            = "pkg:github/mariadb-operator/mariadb-operator"
	MariaDBOperatorFrom                 = "26.3.0"
	MariaDBOperatorTo                   = "26.6.0"
	MariaDBOperatorGaleraFact           = "component.mariadb_operator.galera_enabled"
	MariaDBOperatorReplicationFact      = "component.mariadb_operator.replication_enabled"
	MariaDBOperatorAutoUpdateFact       = "component.mariadb_operator.auto_update_data_plane"
	MariaDBOperatorResourceCompleteFact = "component.mariadb_operator.resource_complete"
	MariaDBOperatorPreUpdateFact        = "component.mariadb_operator.pre_operator_update"
)

// PrepareMariaDBOperatorResource reduces one caller-selected MariaDB custom
// resource to the five facts used by the embedded operator rule. It
// never infers a live object, admission result, update outcome, or cluster
// topology. complete and preOperatorUpdate are declarations supplied by the
// caller and are deliberately required by the CLI route.
func PrepareMariaDBOperatorResource(raw []byte, from, to string, complete, preOperatorUpdate bool) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !json.Valid(raw) {
		return Prepared{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	if token, extra := decoder.Token(); extra != io.EOF || token != nil {
		return Prepared{}, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Prepared{}, ErrInvalid
	}

	galera, replication, autoUpdate, supported := mariaDBOperatorFacts(root)
	pairSupported := from == MariaDBOperatorFrom && to == MariaDBOperatorTo
	facts := []inputFact{
		{ID: MariaDBOperatorAutoUpdateFact, State: "unsupported"},
		{ID: MariaDBOperatorGaleraFact, State: "unsupported"},
		{ID: MariaDBOperatorPreUpdateFact, State: "unsupported"},
		{ID: MariaDBOperatorReplicationFact, State: "unsupported"},
		{ID: MariaDBOperatorResourceCompleteFact, State: "unsupported"},
	}
	state, reason := "UNKNOWN", "MARIADB_OPERATOR_RESOURCE_SCOPE_OR_DECLARATION_UNRESOLVED"
	if !pairSupported {
		reason = "UNSUPPORTED_VERSION_PAIR"
	} else if !supported {
		reason = "MARIADB_OPERATOR_RESOURCE_SHAPE_UNSUPPORTED"
	} else {
		facts[0].State, facts[0].BoolValue = "declared", operatorBoolPointer(autoUpdate)
		facts[1].State, facts[1].BoolValue = "declared", operatorBoolPointer(galera)
		facts[2].State, facts[2].BoolValue = "declared", operatorBoolPointer(preOperatorUpdate)
		facts[3].State, facts[3].BoolValue = "declared", operatorBoolPointer(replication)
		facts[4].State, facts[4].BoolValue = "declared", operatorBoolPointer(complete)
		if !complete || !preOperatorUpdate {
			reason = "MARIADB_OPERATOR_RESOURCE_COMPLETENESS_OR_PHASE_UNDECLARED"
		} else if galera && !replication {
			state, reason = "PREPARED", "MARIADB_OPERATOR_GALERA_RESOURCE_PREREQUISITE_DECLARED"
		} else {
			reason = "MARIADB_OPERATOR_GALERA_SCOPE_OR_DECLARATION_UNRESOLVED"
		}
	}
	canonical, err := marshalInput(MariaDBOperatorComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digest(raw),
		InputDigest:        digest(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CALLER_SUPPLIED_MARIADB_RESOURCE_NOT_LIVE_OBSERVATION",
			"API_KIND_GALERA_REPLICATION_AND_UPDATE_STRATEGY_ARE_CALLER_DECLARATIONS",
			"PRE_OPERATOR_UPDATE_DECLARATION_IS_NOT_OBSERVED_PHASE",
			"OPERATOR_ADMISSION_CONTROLLER_RUNTIME_AND_DATA_PLANE_COMPLETION_NOT_EVALUATED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func mariaDBOperatorFacts(root map[string]any) (galera, replication, autoUpdate, supported bool) {
	apiVersion, ok := exactString(root, "apiVersion")
	if !ok || apiVersion != "k8s.mariadb.com/v1alpha1" {
		return false, false, false, false
	}
	kind, ok := exactString(root, "kind")
	if !ok || kind != "MariaDB" {
		return false, false, false, false
	}
	spec, ok := exactObject(root, "spec")
	if !ok {
		return false, false, false, false
	}
	galeraObject, ok := exactObject(spec, "galera")
	if !ok {
		return false, false, false, false
	}
	galeraValue, ok := exactBool(galeraObject, "enabled")
	if !ok {
		return false, false, false, false
	}
	if value, exists := spec["replication"]; exists {
		replicationObject, ok := value.(map[string]any)
		if !ok || hasCaseVariant(spec, "replication") {
			return false, false, false, false
		}
		replicationValue, ok := exactBool(replicationObject, "enabled")
		if !ok {
			return false, false, false, false
		}
		replication = replicationValue
	} else if hasCaseVariant(spec, "replication") {
		return false, false, false, false
	}
	updateStrategy, ok := exactObject(spec, "updateStrategy")
	if !ok {
		return false, false, false, false
	}
	autoUpdate, ok = exactBool(updateStrategy, "autoUpdateDataPlane")
	if !ok {
		return false, false, false, false
	}
	return galeraValue, replication, autoUpdate, true
}

func exactBool(object map[string]any, key string) (bool, bool) {
	if hasCaseVariant(object, key) {
		return false, false
	}
	value, ok := object[key]
	boolean, isBool := value.(bool)
	return boolean, ok && isBool
}

func operatorBoolPointer(value bool) *bool { return &value }
