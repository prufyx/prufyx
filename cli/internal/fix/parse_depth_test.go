// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"strings"
	"testing"
)

// fix must accept every manifest scan accepts: a published CRD schema 38
// levels deep is deeper than intake.MaxDepth but within MaxManifestDepth.
func TestParseFileAcceptsDeepCRDSchema(t *testing.T) {
	var b strings.Builder
	b.WriteString("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.test\nspec:\n  versions:\n  - name: v1\n    schema:\n      openAPIV3Schema:\n")
	indent := 8
	for i := 0; i < 17; i++ {
		b.WriteString(strings.Repeat(" ", indent) + "properties:\n")
		b.WriteString(strings.Repeat(" ", indent+2) + "x:\n")
		indent += 4
	}
	b.WriteString(strings.Repeat(" ", indent) + "type: string\n")
	if _, r := parseFile([]byte(b.String())); r != nil {
		t.Fatalf("a CRD schema 38 levels deep was refused: %v", r)
	}
}
