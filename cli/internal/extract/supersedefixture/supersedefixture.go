// SPDX-License-Identifier: AGPL-3.0-only

// Package supersedefixture rebuilds, for tests only, the rule pack as it was
// before the served-API supersede: the 25 reviewed Kubernetes API-removal
// rules in place of the mechanical ones. Tests of the supersede machinery
// need reviewed rules to replace; the shipped pack no longer holds any. No
// production code imports this package.
package supersedefixture

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

//go:embed reviewed-kubernetes-entries.json
var reviewedEntries []byte

// mechanicalPrefix is the id prefix of the mechanical Kubernetes rules.
const mechanicalPrefix = "kubernetes.served-api-removal."

// Reviewed returns pack with its mechanical served-API rules removed and the
// 25 reviewed Kubernetes rules added back, rendered like the shipped pack.
func Reviewed(pack []byte) ([]byte, error) {
	p, err := extractpack.ParsePack(pack)
	if err != nil {
		return nil, err
	}
	var old []json.RawMessage
	if err := json.Unmarshal(reviewedEntries, &old); err != nil {
		return nil, err
	}
	var kept []json.RawMessage
	for _, raw := range p.Entries {
		var e struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(e.Rule.ID, mechanicalPrefix) {
			kept = append(kept, raw)
		}
	}
	p.Entries = append(kept, old...)
	return p.Render()
}
