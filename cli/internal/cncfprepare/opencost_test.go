// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

func TestPrepareOpenCostCloudSourceOutcomes(t *testing.T) {
	tests := []struct {
		name, current, proposed, wantFact string
		wantState                         State
	}{
		{
			name:      "provider reliance without migrated source is blocked fact",
			current:   `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:  `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived","cloudIntegrationConfigSource":"absent"}`,
			wantFact:  `"id":"component.opencost.target_cloud_integration_source_selected_and_declared_present","state":"declared","boolValue":false`,
			wantState: StatePrepared,
		},
		{
			name:      "explicit target integration declaration is fixed fact",
			current:   `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:  `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}`,
			wantFact:  `"id":"component.opencost.target_cloud_integration_source_selected_and_declared_present","state":"declared","boolValue":true`,
			wantState: StatePrepared,
		},
		{
			name:      "incomplete selection remains unknown",
			current:   `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:  `{"cloudCostEnabled":true,"sourceSelectionComplete":false}`,
			wantFact:  `"id":"component.opencost.target_cloud_integration_source_selected_and_declared_present","state":"unsupported"`,
			wantState: StateUnknown,
		},
		{
			name:      "API managed source remains unknown",
			current:   `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:  `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"api_managed","cloudIntegrationConfigSource":"unknown"}`,
			wantFact:  `"id":"component.opencost.target_cloud_integration_source_selected_and_declared_present","state":"unsupported"`,
			wantState: StateUnknown,
		},
		{
			name:      "contradictory provider and integration declaration remains unknown",
			current:   `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"}`,
			proposed:  `{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived","cloudIntegrationConfigSource":"present"}`,
			wantFact:  `"id":"component.opencost.target_cloud_integration_source_selected_and_declared_present","state":"unsupported"`,
			wantState: StateUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte(`{"schema":"` + OpenCostDeclarationSchema + `","current":` + test.current + `,"proposed":` + test.proposed + `,"privateCanary":"must-not-be-accepted"}`)
			if _, err := PrepareOpenCostCloudSource(raw, OpenCostFrom, OpenCostTo); err == nil {
				t.Fatal("accepted undeclared private field")
			}
			raw = []byte(`{"schema":"` + OpenCostDeclarationSchema + `","current":` + test.current + `,"proposed":` + test.proposed + `}`)
			prepared, err := PrepareOpenCostCloudSource(raw, OpenCostFrom, OpenCostTo)
			if err != nil || prepared.State != test.wantState || !strings.Contains(string(prepared.CanonicalInputJSON), test.wantFact) {
				t.Fatalf("PrepareOpenCostCloudSource() = %#v, %v\n%s", prepared, err, prepared.CanonicalInputJSON)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "selectedSource") || strings.Contains(string(prepared.CanonicalInputJSON), "cloudIntegrationConfigSource") {
				t.Fatalf("raw declaration retained: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareOpenCostCloudSourceMalformedAndUnsupported(t *testing.T) {
	malformed := []string{
		`{"schema":"` + OpenCostDeclarationSchema + `","current":{"cloudCostEnabled":"true"},"proposed":{}}`,
		`{"schema":"` + OpenCostDeclarationSchema + `","current":{},"proposed":{"sourceSelectionComplete":true,"sourceSelectionComplete":false}}`,
		`{"schema":"wrong","current":{},"proposed":{}}`,
	}
	for _, raw := range malformed {
		if _, err := PrepareOpenCostCloudSource([]byte(raw), OpenCostFrom, OpenCostTo); err == nil {
			t.Fatalf("accepted malformed declaration: %s", raw)
		}
	}
	unknown := `{"schema":"` + OpenCostDeclarationSchema + `","current":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"ambiguous"},"proposed":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}}`
	prepared, err := PrepareOpenCostCloudSource([]byte(unknown), OpenCostFrom, OpenCostTo)
	if err != nil || prepared.State != StateUnknown || !strings.Contains(string(prepared.CanonicalInputJSON), `"id":"component.opencost.current_provider_derived_source_selected","state":"unsupported"`) {
		t.Fatalf("ambiguous source = %#v, %v", prepared, err)
	}
}

func TestPrepareOpenCostCloudSourceExtractsFactsOutsideReviewedPair(t *testing.T) {
	raw := []byte(`{"schema":"` + OpenCostDeclarationSchema + `","current":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"},"proposed":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}}`)
	prepared, err := PrepareOpenCostCloudSource(raw, "1.120.0", "1.121.0")
	if err != nil || prepared.State != StatePrepared || !strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":true`) {
		t.Fatalf("future pair = %#v, %v", prepared, err)
	}
}

func TestPrepareOpenCostLatestRoutes(t *testing.T) {
	raw := []byte(`{"schema":"` + OpenCostDeclarationSchema + `","current":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"provider_derived"},"proposed":{"cloudCostEnabled":true,"sourceSelectionComplete":true,"selectedSource":"cloud_integration","cloudIntegrationConfigSource":"present"}}`)
	for _, from := range openCostLatestOrigins {
		prepared, err := PrepareOpenCostCloudSource(raw, from, OpenCostLatestTo)
		if err != nil || prepared.State != StatePrepared || !strings.Contains(string(prepared.CanonicalInputJSON), `"version":"`+from+`"`) || !strings.Contains(string(prepared.CanonicalInputJSON), `"version":"1.121.2"`) {
			t.Fatalf("%s latest route = %+v, %v", from, prepared, err)
		}
	}
}
