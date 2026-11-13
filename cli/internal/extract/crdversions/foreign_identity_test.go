// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"
)

const foreignIdentityFixture = `apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  name: widgets.foreign.example.io
spec:
  group: foreign.example.io
  versions: [{name: v1}]
  versions: [{name: v1beta1}]
`

func TestPinnedForeignIdentityRejectsAmbiguousOwnDefinitions(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		wantOK     bool
	}{
		{"pinned duplicate nonidentity versions", foreignIdentityFixture, true},
		{"duplicate own group", foreignIdentityFixture + "  group: kubevirt.io\n", false},
		{"duplicate escaped own group", foreignIdentityFixture + "  group: \"kub\\u0065virt.io\"\n", false},
		{"escaped own group in schema", foreignIdentityFixture + "  description: \"kub\\u0065virt.io\"\n", false},
		{"own group in duplicate branch", foreignIdentityFixture + "  schema: {description: kubevirt.io}\n  schema: {}\n", false},
		{"duplicate metadata", strings.Replace(foreignIdentityFixture, "spec:\n", "metadata: {name: hidden.kubevirt.io}\nspec:\n", 1), false},
		{"alias", foreignIdentityFixture + "  schema: &own {description: harmless}\n  x: *own\n", false},
		{"embedded own definition", foreignIdentityFixture + "  data: |\n    kind: CustomResourceDefinition\n    spec: {group: kubevirt.io}\n", false},
		{"nested definition", foreignIdentityFixture + "  hidden: {kind: CustomResourceDefinition, spec: {group: other.example.io}}\n", false},
		{"nested JSON escapes", foreignIdentityFixture + "  hidden: '{\"ki\\u006ed\":\"CustomResourceDef\\u0069nition\",\"spec\":{\"group\":\"kub\\u0065virt.io\"}}'\n", false},
		{"custom tag", foreignIdentityFixture + "  schema: !unknown value\n", false},
		{"duplicate identity only", strings.Replace(foreignIdentityFixture, "  group: foreign.example.io", "  group: foreign.example.io\n  group: other.example.io", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &ForeignBundle{IdentityOnly: true, Groups: []string{"foreign.example.io"}, SHA256: []string{pbDigest(tc.data)}}
			why := foreignBundleProblem(b, []byte(tc.data), []string{"kubevirt.io"})
			if (why == "") != tc.wantOK {
				t.Fatalf("accepted=%v want=%v: %s", why == "", tc.wantOK, why)
			}
		})
	}
}

func TestForeignIdentityDoesNotLoosenOrdinaryDecoder(t *testing.T) {
	b := &ForeignBundle{Groups: []string{"foreign.example.io"}, SHA256: []string{pbDigest(foreignIdentityFixture)}}
	if foreignBundleProblem(b, []byte(foreignIdentityFixture), []string{"kubevirt.io"}) == "" {
		t.Fatal("ordinary foreign decoder admitted duplicate versions")
	}
	b.IdentityOnly = true
	b.SHA256 = []string{pbDigest("different")}
	if foreignBundleProblem(b, []byte(foreignIdentityFixture), []string{"kubevirt.io"}) == "" {
		t.Fatal("identity reader accepted an unpinned file")
	}
}
