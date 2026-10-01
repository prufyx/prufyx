// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

// These canonical JSON values define what persisted *Digest fields bind.
// They identify behavioral contracts, not source-file or executable bytes.
// Source review binds the Go implementation and binary separately.
var strictJSONContract = []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"strict-json","version":"v2","rules":["utf8-json","duplicate-members-rejected-recursively","nonstandard-numbers-rejected","trailing-values-rejected","max-depth-64","max-nodes-250000"]}`)
var boundedRunnerContract = []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"bounded-kubectl-runner","version":"v2","rules":["stdin-closed","stdout-16777216","stderr-65536","deadline-30s","process-group-term-kill","environment-allowlist","stderr-not-emitted"]}`)
var stderrClassifierContract = []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"kubectl-stderr-classifier","version":"v1","authority":"heuristic-local-diagnostic-not-proof","output":"closed-enum-only"}`)
var certManagerProjectorContract = []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"cert-manager-derived-projector","version":"v2","input":"minimized-native-go-surfaces","raw-identities-retained":false}`)

func componentFilterContract(profile string) []byte {
	if profile == "v3" {
		return []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"component-projector","version":"v3-go","profile":"v3","raw-images-retained":false,"command-args-retained":false}`)
	}
	return []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"component-projector","version":"v2-go","profile":"v2","raw-images-retained":false,"command-args-retained":false}`)
}

func componentAggregateContract(profile string) []byte {
	if profile == "v3" {
		return []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"component-aggregate","version":"v3-go","profile":"v3","conflicts-fail-closed":true}`)
	}
	return []byte(`{"kind":"prufyx.io/collector-behavior-contract","name":"component-aggregate","version":"v2-go","profile":"v2","conflicts-fail-closed":true}`)
}
