// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

// CloudNativePG's 1.30 CEL validation makes the cluster reference immutable
// for these namespaced resources. The adapter compares two caller-supplied
// objects with the same Kubernetes identity; it does not inspect a cluster or
// infer the update intent from one object.
const (
	CloudNativePGComponent = "pkg:github/cloudnative-pg/cloudnative-pg"
	CloudNativePGFact      = "component.cloudnativepg.cluster_reference_changed"
	CloudNativePGFrom      = "1.29.0"
	CloudNativePGTo        = "1.30.0"
)

const ReasonCloudNativePGUnsupported Reason = "CNPG_CLUSTER_REFERENCE_INPUT_UNSUPPORTED"
const ReasonCloudNativePGChanged Reason = "CNPG_CLUSTER_REFERENCE_CHANGED"
const ReasonCloudNativePGStable Reason = "CNPG_CLUSTER_REFERENCE_UNCHANGED"

func PrepareCloudNativePG(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	envelope, ok := value.(map[string]any)
	if !ok || !allowedObjectKeys(envelope, "current", "proposed") {
		return Prepared{}, ErrInvalid
	}
	current, okCurrent := cnpgObject(envelope["current"])
	proposed, okProposed := cnpgObject(envelope["proposed"])
	fact := inputFact{ID: CloudNativePGFact, State: "unsupported"}
	state, reason := StateUnknown, ReasonCloudNativePGUnsupported
	if okCurrent && okProposed && sameCNPGIdentity(current, proposed) {
		changed := current.cluster != proposed.cluster
		fact.State = "declared"
		fact.BoolValue = &changed
		state = StatePrepared
		if changed {
			reason = ReasonCloudNativePGChanged
		} else {
			reason = ReasonCloudNativePGStable
		}
	}
	canonical, err := marshalComponentInput(CloudNativePGComponent, from, to, []inputFact{fact})
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"CURRENT_AND_PROPOSED_OBJECTS_ARE_CALLER_SUPPLIED",
			"NO_LIVE_CLUSTER_OR_API_SERVER_OBSERVATION",
			"NO_SCHEMA_CONVERSION_OR_RUNTIME_COMPATIBILITY_EVALUATED",
		},
	}, nil
}

type cnpgObjectValue struct {
	apiVersion string
	kind       string
	namespace  string
	name       string
	cluster    string
}

func cnpgObject(value any) (cnpgObjectValue, bool) {
	object, ok := value.(map[string]any)
	// Kubernetes API objects commonly carry server-managed metadata and status.
	// The scoped predicate observes only the identity and spec.cluster.name;
	// unrelated fields are deliberately ignored and are never canonicalized.
	if !ok {
		return cnpgObjectValue{}, false
	}
	apiVersion, okAPI := object["apiVersion"].(string)
	kind, okKind := object["kind"].(string)
	if !okAPI || apiVersion != "postgresql.cnpg.io/v1" || !okKind || !oneOf(kind, "Database", "Pooler", "Publication", "Subscription", "ScheduledBackup") {
		return cnpgObjectValue{}, false
	}
	metadata, okMetadata := object["metadata"].(map[string]any)
	name, okName := metadata["name"].(string)
	namespace, okNamespace := metadata["namespace"].(string)
	spec, okSpec := object["spec"].(map[string]any)
	clusterRef, okClusterRef := spec["cluster"].(map[string]any)
	cluster, okCluster := clusterRef["name"].(string)
	if !okMetadata || !okName || name == "" || !okNamespace || namespace == "" || !okSpec || !okClusterRef || !okCluster || cluster == "" {
		return cnpgObjectValue{}, false
	}
	return cnpgObjectValue{apiVersion: apiVersion, kind: kind, namespace: namespace, name: name, cluster: cluster}, true
}

func sameCNPGIdentity(a, b cnpgObjectValue) bool {
	return a.apiVersion == b.apiVersion && a.kind == b.kind && a.namespace == b.namespace && a.name == b.name
}

func allowedObjectKeys(object map[string]any, allowed ...string) bool {
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key := range object {
		if !set[key] {
			return false
		}
	}
	return true
}
