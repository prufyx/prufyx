// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The CRD-family pairs of the MariaDB Operator calendar-version releases. Each
// pair names two consecutive public releases (the last patch of each release
// line) whose published MariaDB CRD schemas differ in a field a caller's
// MariaDB resource can still carry: a field the target schema no longer
// defines, or one it retypes. The preparer reduces one caller-selected MariaDB
// resource to one fact per such field and never reads a value except to tell a
// JSON boolean from any other type for the one retyped field. Everything else
// in the upgrade (Helm values, flags, data-plane and replication migration
// steps, admission, runtime behavior) is outside these pairs.
const (
	MariaDBOperatorSyncBinlogBooleanFact    = "component.mariadb_operator.replication_sync_binlog_boolean"
	MariaDBOperatorGaleraAutoFailoverFact   = "component.mariadb_operator.galera_primary_automatic_failover_present"
	MariaDBOperatorReplAutoFailoverFact     = "component.mariadb_operator.replication_primary_automatic_failover_present"
	MariaDBOperatorReplAutoFailoverDelayFct = "component.mariadb_operator.replication_primary_automatic_failover_delay_present"
	MariaDBOperatorReplProbesEnabledFact    = "component.mariadb_operator.replication_probes_enabled_present"
	MariaDBOperatorReplConnRetriesFact      = "component.mariadb_operator.replication_replica_connection_retries_present"
	MariaDBOperatorReplConnTimeoutFact      = "component.mariadb_operator.replication_replica_connection_timeout_present"
	MariaDBOperatorReplWaitPointFact        = "component.mariadb_operator.replication_replica_wait_point_present"
	MariaDBOperatorEmbeddedMaxScaleFact     = "component.mariadb_operator.embedded_max_scale_present"
)

type mariaDBOperatorField struct {
	Fact string
	// Path is the key path under spec.
	Path []string
	// BooleanType makes the fact true only when the value is a JSON boolean
	// (a retyped field); otherwise the fact is the presence of the key.
	BooleanType bool
}

type mariaDBOperatorCRDPair struct {
	From, To string
	Fields   []mariaDBOperatorField
}

var mariaDBOperatorCRDPairs = []mariaDBOperatorCRDPair{
	{From: "0.38.1", To: "25.0.0", Fields: []mariaDBOperatorField{
		{Fact: MariaDBOperatorSyncBinlogBooleanFact, Path: []string{"replication", "syncBinlog"}, BooleanType: true},
	}},
	{From: "25.8.4", To: "25.10.4", Fields: []mariaDBOperatorField{
		{Fact: MariaDBOperatorEmbeddedMaxScaleFact, Path: []string{"maxScale"}},
		{Fact: MariaDBOperatorGaleraAutoFailoverFact, Path: []string{"galera", "primary", "automaticFailover"}},
		{Fact: MariaDBOperatorReplAutoFailoverFact, Path: []string{"replication", "primary", "automaticFailover"}},
		{Fact: MariaDBOperatorReplAutoFailoverDelayFct, Path: []string{"replication", "primary", "automaticFailoverDelay"}},
		{Fact: MariaDBOperatorReplProbesEnabledFact, Path: []string{"replication", "probesEnabled"}},
		{Fact: MariaDBOperatorReplConnRetriesFact, Path: []string{"replication", "replica", "connectionRetries"}},
		{Fact: MariaDBOperatorReplConnTimeoutFact, Path: []string{"replication", "replica", "connectionTimeout"}},
		{Fact: MariaDBOperatorReplWaitPointFact, Path: []string{"replication", "replica", "waitPoint"}},
	}},
}

func mariaDBOperatorCRDPairFor(from, to string) (mariaDBOperatorCRDPair, bool) {
	for _, pair := range mariaDBOperatorCRDPairs {
		if (constraintengine.RuleTransition{Component: MariaDBOperatorComponent, From: pair.From, To: pair.To}).IsAnchor(from, to) {
			return pair, true
		}
	}
	return mariaDBOperatorCRDPair{}, false
}

// IsMariaDBOperatorCRDPair reports whether from and to are exactly one of the
// CRD-family pairs. No other pair, and no pair that merely spans one of them,
// is accepted.
func IsMariaDBOperatorCRDPair(from, to string) bool {
	_, ok := mariaDBOperatorCRDPairFor(from, to)
	return ok
}

// MariaDBOperatorCRDFacts lists the field fact ids a CRD-family pair declares
// (the resource-complete guard fact is common to every route and not listed).
func MariaDBOperatorCRDFacts(from, to string) []string {
	pair, ok := mariaDBOperatorCRDPairFor(from, to)
	if !ok {
		return nil
	}
	ids := make([]string, 0, len(pair.Fields))
	for _, field := range pair.Fields {
		ids = append(ids, field.Fact)
	}
	return ids
}

// PrepareMariaDBOperatorCRDPairResource reduces one caller-selected MariaDB
// resource to the field facts of one CRD-family pair. complete is the caller's
// declaration that the resource is the whole selected resource; without it, or
// when any key on a checked path could be read in more than one way (a case
// variant of a key, a non-object where an object must be), every fact is
// unsupported and the state is UNKNOWN.
func PrepareMariaDBOperatorCRDPairResource(raw []byte, from, to string, complete bool) (Prepared, error) {
	pair, ok := mariaDBOperatorCRDPairFor(from, to)
	if !ok || len(raw) == 0 || len(raw) > maxInputBytes || !json.Valid(raw) {
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
	found, supported := mariaDBOperatorCRDFacts(root, pair)

	facts := make([]inputFact, 0, len(pair.Fields)+1)
	for _, field := range pair.Fields {
		facts = append(facts, inputFact{ID: field.Fact, State: "unsupported"})
	}
	facts = append(facts, inputFact{ID: MariaDBOperatorResourceCompleteFact, State: "declared", BoolValue: operatorBoolPointer(complete)})
	state, reason := "UNKNOWN", "MARIADB_OPERATOR_RESOURCE_COMPLETENESS_UNDECLARED"
	switch {
	case !supported:
		reason = "MARIADB_OPERATOR_RESOURCE_SHAPE_UNSUPPORTED"
	case complete:
		for i, field := range pair.Fields {
			facts[i] = inputFact{ID: field.Fact, State: "declared", BoolValue: operatorBoolPointer(found[field.Fact])}
		}
		state, reason = "PREPARED", "MARIADB_OPERATOR_CRD_FIELDS_INSPECTED"
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
			"RESOURCE_COMPLETENESS_IS_A_CALLER_DECLARATION",
			"ONLY_THE_LISTED_CRD_FIELDS_OF_THE_MARIADB_KIND_INSPECTED_NOT_THEIR_VALUES_OR_ANY_OTHER_FIELD_OR_KIND",
			"HELM_VALUES_FLAGS_DATA_PLANE_AND_REPLICATION_MIGRATION_STEPS_NOT_EVALUATED",
			"ADMISSION_CONTROLLER_RUNTIME_AND_DATA_PLANE_COMPLETION_NOT_EVALUATED",
			"WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

// mariaDBOperatorCRDFacts walks each field's path under spec. A key is found
// only by its exact spelling; a case variant of any key on the path, or a
// present non-object on the way, makes the whole shape unsupported. An absent
// parent means the field is absent. The apiVersion and kind must be exactly
// k8s.mariadb.com/v1alpha1 and MariaDB.
func mariaDBOperatorCRDFacts(root map[string]any, pair mariaDBOperatorCRDPair) (map[string]bool, bool) {
	apiVersion, ok := exactString(root, "apiVersion")
	if !ok || apiVersion != "k8s.mariadb.com/v1alpha1" {
		return nil, false
	}
	kind, ok := exactString(root, "kind")
	if !ok || kind != "MariaDB" {
		return nil, false
	}
	spec, ok := exactObject(root, "spec")
	if !ok {
		return nil, false
	}
	found := map[string]bool{}
	for _, field := range pair.Fields {
		value, exists, shapeOK := lookupCRDPath(spec, field.Path)
		if !shapeOK {
			return nil, false
		}
		if !field.BooleanType {
			found[field.Fact] = exists
			continue
		}
		switch value.(type) {
		case nil:
			if exists {
				return nil, false
			}
			found[field.Fact] = false
		case bool:
			found[field.Fact] = true
		case json.Number:
			found[field.Fact] = false
		default:
			return nil, false
		}
	}
	return found, true
}

// lookupCRDPath follows path from node by exact key spelling. exists is false
// when a key on the path is absent; ok is false when a key on the path has a
// case variant or an intermediate value is present and is not an object.
func lookupCRDPath(node map[string]any, path []string) (value any, exists, ok bool) {
	for depth, key := range path {
		if hasCaseVariant(node, key) {
			return nil, false, false
		}
		child, present := node[key]
		if !present {
			return nil, false, true
		}
		if depth == len(path)-1 {
			return child, true, true
		}
		next, isObject := child.(map[string]any)
		if !isObject {
			return nil, false, false
		}
		node = next
	}
	return nil, false, false
}
