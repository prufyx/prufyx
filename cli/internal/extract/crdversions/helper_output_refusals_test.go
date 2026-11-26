// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Helper sources that can emit definitions must remain blockers even if a
// future reader accepts helpers that only produce bounded metadata. Dynamic
// cases seed the kind in a fail diagnostic; sources without that seed are
// outside the current scanner boundary.
func TestHelperOutputRefusals(t *testing.T) {
	const helper = "charts/x/templates/_helpers.tpl"
	const caller = "charts/x/templates/crds.yaml"
	alpha := crd("Alpha", "v1beta1", "v1")
	later := crd("Alpha", "v1beta1:off", "v1")
	cases := map[string]map[string]string{
		"direct template output": {
			helper: "{{- define \"x.crd\" }}\n" + alpha + "{{- end }}\n",
			caller: "{{ template \"x.crd\" . }}\n",
		},
		"named helper invoked by template": {
			helper: "{{- define \"x.crd\" }}\n" + alpha + "{{- end }}\n{{- define \"x.outer\" }}{{ include \"x.crd\" . }}{{- end }}\n",
			caller: "{{ include \"x.outer\" . }}\n",
		},
		"definition behind control branch": {
			helper: "{{- define \"x.crd\" }}\n{{- if .Values.installCRDs }}\n" + alpha + "{{- end }}\n{{- end }}\n",
			caller: "{{ include \"x.crd\" . }}\n",
		},
		"dynamic include output": {
			helper: "{{- define \"x.crd\" }}\n{{- if .Values.reject }}{{ fail \"CustomResourceDefinition\" }}{{- end }}\n{{ include .Values.helper . }}\n{{- end }}\n",
			caller: "{{ include \"x.crd\" . }}\n",
		},
		"dynamic tpl output": {
			helper: "{{- define \"x.crd\" }}\n{{- if .Values.reject }}{{ fail \"CustomResourceDefinition\" }}{{- end }}\n{{ tpl .Values.extra . }}\n{{- end }}\n",
			caller: "{{ include \"x.crd\" . }}\n",
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			// The caller alone must not be the reason the pair is withheld.
			from := map[string]string{"deploy/crds/a.yaml": alpha}
			to := map[string]string{"deploy/crds/a.yaml": later, caller: files[caller]}
			control := runSynth(t, attestingTarget(), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to}))
			cp, _ := pairOf(t, control, "1.0.0", "1.1.0")
			if cp.Status != extract.PairDerived || len(cp.Rules) != 1 {
				t.Fatalf("caller alone: %s %q rules %v", cp.Status, cp.Reason, cp.Rules)
			}
			to[helper] = files[helper]
			out := runSynth(t, attestingTarget(), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to}))
			p, proof := pairOf(t, out, "1.0.0", "1.1.0")
			if proof.To == nil || proof.To.Scan == nil {
				t.Fatalf("missing scan: %+v", p)
			}
			f := findingOf(proof.To.Scan, helper)
			if f == nil || f.Class != ClassUnsupported || f.Reason != ReasonSourceTemplate {
				t.Fatalf("helper finding: %+v", f)
			}
			// Withholding an unread later source happens before completeness is built.
			if proof.Completeness != nil || p.Status != extract.PairWithheld || p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 || len(p.Rules) != 0 || !strings.Contains(p.Reason, helper+" is "+ClassUnsupported) {
				t.Fatalf("pair %s %q; completeness %+v", p.Status, p.Reason, proof.Completeness)
			}
		})
	}
}
