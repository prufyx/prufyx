// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/communityapp/

const (
	gwComponent = "pkg:github/kubernetes-sigs/gateway-api"
	gwFact      = "component.gateway_api.custom_resource_versions_set"
	gwRuleID    = "gateway-api.crd-version-removal.gateways-gateway-networking-k8s-io.1-1-0-to-1-2-0"
	gwRevision  = "4836c7dd74ce973f06d97936916ed7f20c1a2ff0"
)

func useGatewayAPIKnowledge(t *testing.T) {
	t.Helper()
	rule := `{"id":"` + gwRuleID + `","operator":"forbid_set_member","subject":{"component":"` + gwComponent + `","from":"1.1.0","to":"1.2.0"},` +
		`"setCondition":{"side":"proposed","component":"` + gwComponent + `","factId":"` + gwFact + `","members":["gateway.networking.k8s.io/v1beta1/Gateway"]},` +
		`"evidence":{"state":"active","reviewedAt":"2026-10-01T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"crd-1-2-0","url":"https://github.com/kubernetes-sigs/gateway-api/blob/` + gwRevision + `/config/crd/standard/gateway.networking.k8s.io_gateways.yaml","revision":"` + gwRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Gateway to gateway.networking.k8s.io/v1 before upgrading to 1.2.0"}`
	entry := cncfcheck.Entry{Project: "gateway-api", Description: "Gateway API 1.2.0 no longer serves version v1beta1 of Gateway. Test only.",
		RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: gwFact, Component: gwComponent, Type: "set", Description: "Custom-resource versions of the Gateway API custom resources."}},
		Rule:          json.RawMessage(rule)}
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, []cncfcheck.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
}

const gatewayRemoved = "apiVersion: gateway.networking.k8s.io/v1beta1\nkind: Gateway\nmetadata:\n  name: private-name\n  namespace: private-ns\n"

func gatewayArgs(path string, extra ...string) []string {
	return append([]string{"check", "cncf", "--project", "gateway-api", "--custom-resources", path, "--from", "1.1.0", "--to", "1.2.0", "--now", "2026-10-05T00:00:00Z"}, extra...)
}

// A community project with data is checked through the custom-resource mode,
// labelled in the JSON and the human output, and never exits 0.
func TestSyntheticCommunityCustomResourceCheck(t *testing.T) {
	useGatewayAPIKnowledge(t)
	path := writeCNCFFile(t, "manifests.yaml", []byte(gatewayRemoved), 0o600)
	code, stdout, stderr := runCNCFCLI(t, gatewayArgs(path, "--custom-resources-complete", "--format", "json")...)
	if code != ExitBlocked || stderr != "" || strings.Contains(stdout, "private-") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var report cncfcheck.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Project != "gateway-api" || report.Catalog != cncfcheck.CatalogCommunity || len(report.Check.Claims) != 1 || report.Check.Claims[0].Status != "BLOCKED" || report.Check.Claims[0].RuleID != gwRuleID {
		t.Fatalf("report %+v", report)
	}
	code, stdout, stderr = runCNCFCLI(t, gatewayArgs(path, "--custom-resources-complete")...)
	if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, "catalog: "+customresources.CommunityLabel+"\n") || !strings.Contains(stdout, gwRuleID) || strings.Contains(stdout, "private-") {
		t.Fatalf("human: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	// A served version is never a pass.
	served := writeCNCFFile(t, "served.yaml", []byte(strings.Replace(gatewayRemoved, "v1beta1", "v1", 1)), 0o600)
	code, stdout, _ = runCNCFCLI(t, gatewayArgs(served, "--custom-resources-complete", "--format", "json")...)
	if code != ExitUnknown {
		t.Fatalf("served version: code=%d %s", code, stdout)
	}
	// The generic canonical-input route still does not know the project, and
	// a CNCF project's report carries no catalog member.
	code, _, stderr = runCNCFCLI(t, "check", "cncf", "--project", "gateway-api", "--input", path, "--now", "2026-10-05T00:00:00Z")
	if code == ExitOK || !strings.Contains(stderr, `unknown project "gateway-api"`) {
		t.Fatalf("generic route: code=%d %q", code, stderr)
	}
	strimzi := writeCNCFFile(t, "strimzi.yaml", []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"), 0o600)
	_, stdout, _ = runCNCFCLI(t, customResourceArgs(strimzi, "--format", "json")...)
	if strings.Contains(stdout, `"catalog"`) {
		t.Fatalf("a CNCF project's report carries a catalog member: %s", stdout)
	}
}

// The rule listing names the community catalog on the rule, in both
// formats, and keeps the CNCF families as they were.
func TestSyntheticCommunityCatalogChecks(t *testing.T) {
	useGatewayAPIKnowledge(t)
	code, stdout, stderr := runCNCFCLI(t, "catalog", "checks", "--project", "gateway-api")
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "gateway-api "+gwRuleID+" 1.1.0 -> 1.2.0\n  catalog: "+customresources.CommunityLabel+"\n") || !strings.Contains(stdout, "check cncf --project gateway-api --custom-resources") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, _ = runCNCFCLI(t, "catalog", "checks", "--project", "gateway-api", "--format", "json")
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	var result checkroutemetadata.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Checks) != 1 || result.Checks[0].Family != checkroutemetadata.FamilyCommunityCatalog || result.Checks[0].Catalog != cncfcheck.CatalogCommunity || result.Checks[0].GenericDeclarationRoute.State != checkroutemetadata.RouteNotExposed {
		t.Fatalf("checks %+v", result.Checks)
	}
	found := false
	for _, family := range result.Scope.IncludedFamilies {
		found = found || family == checkroutemetadata.FamilyCommunityCatalog
	}
	if !found {
		t.Fatalf("families %v", result.Scope.IncludedFamilies)
	}
	// The catalogue of CNCF projects does not list it.
	code, stdout, _ = runCNCFCLI(t, "catalog", "cncf", "--format", "json")
	if code != ExitOK || strings.Contains(stdout, `"slug":"gateway-api"`) {
		t.Fatalf("code=%d catalogue lists the community project", code)
	}
}
