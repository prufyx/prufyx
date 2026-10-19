// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"reflect"
	"testing"
)

// The located preparation returns the very prepared input of the plain one,
// whatever the label of the file, and names the objects behind each fact.
func TestPrepareKubernetesRemovedAPIsLocatedKeepsThePreparedInput(t *testing.T) {
	t.Parallel()
	complete := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\napiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: b\n  namespace: ns\n"
	partial := complete + "---\napiVersion: v1\nkind: Thing\nmetadata:\n  name: c\nitems: []\n"
	for name, raw := range map[string]string{"complete": complete, "partial readable set": partial} {
		for _, file := range []string{"applyset.yaml", "Chart.yaml", "kustomization.yaml"} {
			want, err := PrepareKubernetesRemovedAPIs([]byte(raw), "1.24.0", "1.25.0", "official_upstream", true, true)
			if err != nil {
				t.Fatal(err)
			}
			got, refs, err := PrepareKubernetesRemovedAPIsLocated([]byte(raw), file, "1.24.0", "1.25.0", "official_upstream", true, true)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %s: %v\n got %+v\nwant %+v", name, file, err, got, want)
			}
			found := false
			for _, list := range refs {
				for _, ref := range list {
					found = true
					if ref.File != file || ref.Kind != "CronJob" || ref.Namespace != "ns" || ref.Name != "b" || ref.Document != 1 || ref.Line != 6 {
						t.Fatalf("%s %s: ref %+v", name, file, ref)
					}
				}
			}
			if !found {
				t.Fatalf("%s %s: no object located", name, file)
			}
		}
	}
}
