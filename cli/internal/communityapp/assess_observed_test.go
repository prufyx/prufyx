// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/onecommand"
)

func TestAssessHumanPrintsObservedBeforeSummary(t *testing.T) {
	report := onecommand.Report{Contexts: []onecommand.ContextAssessment{{
		ContextHash: "ctx", CollectionStatus: "partial_for_declared_surface",
		Observed: onecommand.Observed{
			KubernetesVersion: "v1.31.0",
			Kubelets: onecommand.ObservedKubelets{NodeCount: 3, Min: "v1.30.2", Max: "v1.31.0",
				Versions: []onecommand.KubeletVersionCt{{Version: "v1.30.2", Nodes: 2}, {Version: "v1.31.0", Nodes: 1}}},
			Components: []onecommand.ObservedComp{{ComponentID: "pkg:oci/prometheus/prometheus", Version: "2.55.1", State: "observed"}},
			Omissions:  []onecommand.ObservedOmitted{{Resource: "storageclasses", Code: "projection_filter_rejected", Hint: "report it"}},
		},
	}}}
	var out bytes.Buffer
	writeAssessHuman(&out, report)
	text := out.String()
	for _, want := range []string{"kubernetes server: v1.31.0", "3 nodes (min v1.30.2, max v1.31.0)", "v1.30.2 x2", "pkg:oci/prometheus/prometheus 2.55.1 (observed)", "storageclasses: projection_filter_rejected -- report it"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Index(text, "observed:") > strings.Index(text, "fully satisfiable") {
		t.Fatal("observed section must precede the summary")
	}
}
