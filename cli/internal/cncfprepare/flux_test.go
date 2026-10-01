// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

func TestPrepareFlux_SelectedResourceSet(t *testing.T) {
	cases := []struct {
		name, raw string
		complete  bool
		state     State
		reason    Reason
		fact      string
	}{
		{"removed witness blocks without completeness", `{"apiVersion":"source.toolkit.fluxcd.io/v1beta1","kind":"GitRepository","metadata":{"name":"app"}}`, false, StatePrepared, ReasonFluxRemovedAPIWitness, `"boolValue":true`},
		{"clear object needs completeness", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}`, true, StatePrepared, ReasonFluxSelectedSetClear, `"boolValue":false`},
		{"clear object incomplete unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}`, false, StateUnknown, ReasonFluxScopeIncomplete, `"state":"unsupported"`},
		{"list witness blocks", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app"}},{"apiVersion":"helm.toolkit.fluxcd.io/v2beta1","kind":"HelmRelease","metadata":{"name":"chart"}}]}`, false, StatePrepared, ReasonFluxRemovedAPIWitness, `"boolValue":true`},
		{"paginated list unknown", `{"apiVersion":"v1","kind":"List","metadata":{"continue":"next"},"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app"}}]}`, true, StateUnknown, ReasonFluxPagination, `"state":"unsupported"`},
		{"wrong shaped list metadata unknown", `{"apiVersion":"v1","kind":"List","metadata":[],"items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app"}}]}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"nested list unknown", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"v1","kind":"List","metadata":{"name":"nested"},"items":[]}]}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"typed list wrapper unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepositoryList","metadata":{"name":"wrapped"},"items":[{"apiVersion":"source.toolkit.fluxcd.io/v1beta1","kind":"GitRepository","metadata":{"name":"removed"}}]}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"leaf items wrapper unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"wrapped"},"items":[{"apiVersion":"source.toolkit.fluxcd.io/v1beta1","kind":"GitRepository","metadata":{"name":"removed"}}]}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"whitespace identity unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1 ","kind":"GitRepository","metadata":{"name":"app"}}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"internal API whitespace unknown", `{"apiVersion":"source.toolkit.fluxcd.io/ v1","kind":"GitRepository","metadata":{"name":"app"}}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"internal kind whitespace unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"Git Repository","metadata":{"name":"app"}}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"control identity unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository\u0001","metadata":{"name":"app"}}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"whitespace name unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":" app"}}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"internal name whitespace unknown", `{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"private app"}}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
		{"api only unknown", `{"apiVersion":"apps/v1","metadata":{"name":"app"}}`, true, StateUnknown, ReasonFluxResourceUnsupported, `"state":"unsupported"`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareFlux([]byte(test.raw), FluxFrom, FluxTo, test.complete)
			if err != nil || prepared.State != test.state || prepared.Reason != test.reason || !strings.Contains(string(prepared.CanonicalInputJSON), test.fact) {
				t.Fatalf("PrepareFlux() = %#v, %v", prepared, err)
			}
		})
	}
}

func TestPrepareFlux_RejectsMalformedOrDuplicateInput(t *testing.T) {
	for _, raw := range []string{
		`{"apiVersion":"v1","apiVersion":"v1","kind":"List","items":[]}`,
		`{"apiVersion":"v1","kind":"List","items":"not-array"}`,
		`not json`,
	} {
		prepared, err := PrepareFlux([]byte(raw), FluxFrom, FluxTo, true)
		if err != nil {
			continue
		}
		if prepared.State != StateUnknown {
			t.Fatalf("malformed/unsupported %q prepared %q", raw, prepared.State)
		}
	}
	prepared, err := PrepareFlux([]byte(`{"apiVersion":"v1","kind":"List","items":[]}`), FluxFrom, FluxTo, true)
	if err != nil || prepared.State != StateUnknown {
		t.Fatalf("empty List = %#v, %v", prepared, err)
	}
	if _, err := PrepareFlux([]byte{'{', 0xff, '}'}, FluxFrom, FluxTo, true); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestPrepareFluxLatest_RemovesUnionFromV28AndV29(t *testing.T) {
	for index, api := range fluxLatestRemovedAPIs {
		kinds := []string{"GitRepository", "Kustomization", "HelmRelease", "ImagePolicy", "Alert"}
		raw := `{"apiVersion":"` + api + `","kind":"` + kinds[index] + `","metadata":{"name":"app"}}`
		prepared, err := PrepareFlux([]byte(raw), "2.4.0", FluxLatestTo, false)
		if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonFluxRemovedAPIWitness || !strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":true`) {
			t.Fatalf("api=%s prepared=%#v err=%v", api, prepared, err)
		}
	}
}

func TestPrepareFluxLatestRetainsV27RemovedAPIsAsSeparateFact(t *testing.T) {
	raw := []byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1beta1","kind":"GitRepository","metadata":{"name":"app"}}`)
	prepared, err := PrepareFlux(raw, "2.6.4", FluxLatestTo, false)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonFluxRemovedAPIWitness || !strings.Contains(string(prepared.CanonicalInputJSON), FluxLatestFact) || !strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":true`) {
		t.Fatalf("legacy latest witness=%#v err=%v", prepared, err)
	}
}

func TestPrepareFluxLatestDoesNotInferGroupRemovalForUnknownKind(t *testing.T) {
	raw := []byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1beta2","kind":"Unlisted","metadata":{"name":"app"}}`)
	prepared, err := PrepareFlux(raw, "2.8.8", FluxLatestTo, true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonFluxResourceUnsupported || !strings.Contains(string(prepared.CanonicalInputJSON), `"component.flux.latest_removed_beta_api_present","state":"unsupported"`) {
		t.Fatalf("unknown kind=%#v err=%v", prepared, err)
	}
}

func TestPrepareFluxLatestDoesNotInferClearForUnknownAPIVersion(t *testing.T) {
	for _, test := range []struct {
		api, kind string
	}{
		{"source.toolkit.fluxcd.io/v99", "GitRepository"},
		{"kustomize.toolkit.fluxcd.io/v99", "Kustomization"},
		{"helm.toolkit.fluxcd.io/v99", "HelmRelease"},
		{"image.toolkit.fluxcd.io/v99", "ImagePolicy"},
		{"notification.toolkit.fluxcd.io/v99", "Alert"},
	} {
		raw := []byte(`{"apiVersion":"` + test.api + `","kind":"` + test.kind + `","metadata":{"name":"app"}}`)
		prepared, err := PrepareFlux(raw, "2.8.8", FluxLatestTo, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonFluxResourceUnsupported || !strings.Contains(string(prepared.CanonicalInputJSON), `"state":"unsupported"`) {
			t.Fatalf("api=%s kind=%s prepared=%#v err=%v", test.api, test.kind, prepared, err)
		}
	}
}

func TestPrepareFluxLatestTargetServedVersionsAreScopedClear(t *testing.T) {
	for _, test := range []struct {
		api, kind string
	}{
		{"source.toolkit.fluxcd.io/v1", "GitRepository"},
		{"kustomize.toolkit.fluxcd.io/v1", "Kustomization"},
		{"helm.toolkit.fluxcd.io/v2", "HelmRelease"},
		{"image.toolkit.fluxcd.io/v1", "ImageRepository"},
		{"notification.toolkit.fluxcd.io/v1beta3", "Alert"},
		{"notification.toolkit.fluxcd.io/v1beta3", "Provider"},
		{"notification.toolkit.fluxcd.io/v1", "Receiver"},
	} {
		raw := []byte(`{"apiVersion":"` + test.api + `","kind":"` + test.kind + `","metadata":{"name":"app"}}`)
		prepared, err := PrepareFlux(raw, "2.8.8", FluxLatestTo, true)
		if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonFluxSelectedSetClear || !strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":false`) {
			t.Fatalf("api=%s kind=%s prepared=%#v err=%v", test.api, test.kind, prepared, err)
		}
	}
}

func TestPrepareFluxLatestAllowsOrdinaryNonFluxResources(t *testing.T) {
	raw := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"app"}}`)
	prepared, err := PrepareFlux(raw, "2.8.8", FluxLatestTo, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonFluxSelectedSetClear || !strings.Contains(string(prepared.CanonicalInputJSON), `"component.flux.latest_removed_beta_api_present","state":"declared","boolValue":false`) {
		t.Fatalf("ordinary resource=%#v err=%v", prepared, err)
	}
}

func TestPrepareFluxLatestRejectsUnlistedOrigin(t *testing.T) {
	raw := []byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1beta2","kind":"GitRepository","metadata":{"name":"app"}}`)
	prepared, err := PrepareFlux(raw, "2.3.0", FluxLatestTo, false)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonFluxLatestTransition || !strings.Contains(string(prepared.CanonicalInputJSON), FluxLatestFact) || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":true`) {
		t.Fatalf("unlisted origin=%#v err=%v", prepared, err)
	}
}

func TestPrepareFluxLatestClearRequiresCompleteSelectedSet(t *testing.T) {
	raw := []byte(`{"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"app"}}`)
	prepared, err := PrepareFlux(raw, "2.8.8", FluxLatestTo, false)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonFluxScopeIncomplete {
		t.Fatalf("incomplete=%#v err=%v", prepared, err)
	}
	prepared, err = PrepareFlux(raw, "2.8.8", FluxLatestTo, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonFluxSelectedSetClear || !strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":false`) {
		t.Fatalf("complete=%#v err=%v", prepared, err)
	}
}
