// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
)

// ParseKubeVersion classifies a Chart.yaml kubeVersion constraint with the
// same strict rules the extractor uses: only a single lower bound is a
// minimum; every other shape is "other" and yields no minimum.
func ParseKubeVersion(constraint string) KubeMinimum { return parseKubeVersion(constraint) }

// ChartKubeVersion reads only the kubeVersion of a Chart.yaml (strict YAML
// subset; a templated or non-X.Y.Z chart version does not matter here) and
// returns the constraint as written and its 1-based line, "" and 0 when the
// chart declares none.
func ChartKubeVersion(data []byte) (constraint string, line int, err error) {
	root, v, err := helmvaluespath.DecodeYAML(data)
	if err != nil {
		return "", 0, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "", 0, fmt.Errorf("Chart.yaml is not a mapping")
	}
	kv, present := m["kubeVersion"]
	if !present || kv == nil {
		return "", 0, nil
	}
	s, ok := kv.(string)
	if !ok {
		return "", 0, fmt.Errorf("Chart.yaml kubeVersion is not a string")
	}
	return s, helmvaluespath.MappingLine(root, "kubeVersion"), nil
}
