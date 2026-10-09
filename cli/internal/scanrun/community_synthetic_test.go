// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// A synthetic rule of a community project (never published): Gateway API
// 1.2.0 no longer serves version v1beta1 of Gateway. The knowledge gains it
// through the real loader, the real pack schema level and, for a database,
// the real per-project targets and import.

const (
	gwSlug      = "gateway-api"
	gwComponent = "pkg:github/kubernetes-sigs/gateway-api"
	gwFact      = "component.gateway_api.custom_resource_versions_set"
	gwRuleID    = "gateway-api.crd-version-removal.gateways-gateway-networking-k8s-io.1-1-0-to-1-2-0"
	gwRevision  = "4836c7dd74ce973f06d97936916ed7f20c1a2ff0"
)

func gwEntry() cncfcheck.Entry {
	rule := `{"id":"` + gwRuleID + `","operator":"forbid_set_member","subject":{"component":"` + gwComponent + `","from":"1.1.0","to":"1.2.0"},` +
		`"setCondition":{"side":"proposed","component":"` + gwComponent + `","factId":"` + gwFact + `","members":["gateway.networking.k8s.io/v1beta1/Gateway"]},` +
		`"evidence":{"state":"active","reviewedAt":"` + currentReviewed + `","validUntil":"` + currentUntil + `","sources":[{"id":"crd-1-2-0","url":"https://github.com/kubernetes-sigs/gateway-api/blob/` + gwRevision + `/config/crd/standard/gateway.networking.k8s.io_gateways.yaml","revision":"` + gwRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"CRD_VERSION_NOT_SERVED","nextAction":"change apiVersion of Gateway to gateway.networking.k8s.io/v1 before upgrading to 1.2.0"}`
	return cncfcheck.Entry{
		Project: gwSlug, Description: "Gateway API 1.2.0 no longer serves version v1beta1 of Gateway. Test only.",
		RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: gwFact, Component: gwComponent, Type: "set", Description: "Custom-resource versions of the Gateway API custom resources."}},
		Rule:          json.RawMessage(rule),
	}
}

func installCommunity(t *testing.T) Knowledge {
	t.Helper()
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, []cncfcheck.Entry{gwEntry()})
	if err != nil {
		t.Fatalf("community knowledge refused: %v", err)
	}
	t.Cleanup(restore)
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded
}

const (
	gwRemoved = "apiVersion: gateway.networking.k8s.io/v1beta1\nkind: Gateway\nmetadata:\n  name: edge\n  namespace: infra\n"
	gwServed  = "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nmetadata:\n  name: edge\n  namespace: infra\n"
)

func gwScan(t *testing.T, knowledge Knowledge, docs []string, extra ...string) Result {
	t.Helper()
	_, paths := files(t, map[string]string{"gw.yaml": strings.Join(docs, "---\n")})
	return mustScan(t, knowledge, append(append([]string{}, paths...), append([]string{"--now", testNow, "--from", "gateway-api=1.1.0", "--to", "gateway-api=1.2.0"}, extra...)...)...)
}

// The community project is scanned like a CNCF one with a custom-resource
// version set (blocked on a removed version, never covered, never a pass of
// the component) and is labelled as the community catalog in every output.
func TestScanCommunityProjectWithData(t *testing.T) {
	k := installCommunity(t)
	result := gwScan(t, k, []string{gwRemoved, settingsDoc}, "--resource-scope-complete")
	if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != gwRuleID || result.Report.Findings[0].Component != gwSlug {
		t.Fatalf("exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
	}
	var gw scanreport.Component
	for _, c := range result.Report.Inventory {
		if c.Name == gwSlug {
			gw = c
		}
	}
	if gw.Catalog != cncfcheck.CatalogCommunity || gw.Component != gwComponent || gw.Covered {
		t.Fatalf("inventory %+v", gw)
	}
	if !hasComponentGap(result.Report, gwSlug, scanreport.ReasonComponentNotCovered, "only for custom-resource versions") {
		t.Fatalf("gaps %v", gapReasons(result.Report))
	}
	label := scanreport.Text(scanreport.NoteCommunityCatalog, gwSlug)
	if !strings.Contains(label, customresources.CommunityLabel) {
		t.Fatalf("note %q does not carry the table's label %q", label, customresources.CommunityLabel)
	}
	found := 0
	for _, note := range result.Report.Notes {
		if note == label {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("notes %v", result.Report.Notes)
	}
	human := string(scanreport.Human(result.Report, scanreport.HumanOptions{}))
	md := string(scanreport.Markdown(result.Report, scanreport.MarkdownOptions{}))
	sarif, err := scanreport.SARIF(result.Report)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result.Report)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"human": human, "markdown": md} {
		if !strings.Contains(out, "gateway-api is in the community catalog (not in the embedded CNCF landscape catalog; no CNCF status asserted)") {
			t.Fatalf("%s output lacks the catalog label:\n%s", name, out)
		}
	}
	if !strings.Contains(string(sarif), `"communityCatalog": [`) || !strings.Contains(string(sarif), `"gateway-api"`) {
		t.Fatalf("sarif lacks the community catalog:\n%s", sarif)
	}
	if !strings.Contains(string(raw), `"catalog":"community"`) {
		t.Fatalf("json lacks the catalog member: %s", raw)
	}
	for _, out := range []string{human, md, string(sarif), string(raw)} {
		for _, banned := range []string{"CNCF project gateway-api", "CNCF catalog project"} {
			if strings.Contains(out, banned) {
				t.Fatalf("output says %q", banned)
			}
		}
	}
	conformReport(t, "community project", result.Report)

	// A served version never passes the component: the hop is partial, the
	// answer UNKNOWN.
	served := gwScan(t, k, []string{gwServed}, "--resource-scope-complete")
	if served.Exit != scanreport.ExitUnknown || served.Report.Verdict == scanreport.VerdictPass || len(served.Report.Findings) != 0 {
		t.Fatalf("served: exit %d verdict %s", served.Exit, served.Report.Verdict)
	}
	for _, c := range served.Report.Inventory {
		if c.Covered {
			t.Fatalf("%s is covered", c.Name)
		}
	}
	// A scan that names a CNCF project and the community project labels
	// only the community one.
	both := gwScan(t, k, []string{gwRemoved}, "--to", "strimzi=1.0.0", "--from", "strimzi=0.51.0", "--resource-scope-complete")
	labelled := 0
	for _, c := range both.Report.Inventory {
		if c.Catalog != "" {
			labelled++
			if c.Name != gwSlug {
				t.Fatalf("%s is labelled", c.Name)
			}
		}
	}
	if labelled != 1 || len(both.Report.Notes) != 1 {
		t.Fatalf("labelled %d, notes %v", labelled, both.Report.Notes)
	}
}

// A CNCF-only scan against knowledge that also holds community data carries
// no community label anywhere.
func TestScanCNCFProjectIsNeverLabelledCommunity(t *testing.T) {
	k := installCommunity(t)
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
	inDir(t, dir, func() {
		result := mustScan(t, k, args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
		raw, err := json.Marshal(result.Report)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "community") {
			t.Fatalf("a CNCF scan mentions the community catalog: %s", raw)
		}
		for _, c := range result.Report.Inventory {
			if c.Catalog != "" {
				t.Fatalf("%s labelled %q", c.Name, c.Catalog)
			}
		}
	})
}

// A knowledge database carries the community project's target (under its
// own path and the v3 index); the scan reads it from the database only.
func TestScanCommunityProjectFromADatabase(t *testing.T) {
	for _, layout := range storeLayouts {
		t.Run(layout, func(t *testing.T) {
			installCommunity(t)
			fixture := newStoreFixture(t, layout)
			fixture.importPack(nil, "5")
			opened, err := OpenStore(fixture.store, []string{gwSlug})
			if err != nil {
				t.Fatal(err)
			}
			moved := *opened
			instant, _ := time.Parse(time.RFC3339, testNow)
			moved.info.EvaluatedAt = instant
			_, paths := files(t, map[string]string{"gw.yaml": gwRemoved})
			result := mustScan(t, &moved, append(append([]string{}, paths...), "--from", "gateway-api=1.1.0", "--to", "gateway-api=1.2.0", "--resource-scope-complete")...)
			if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != gwRuleID {
				t.Fatalf("exit %d findings %+v gaps %v", result.Exit, result.Report.Findings, gapReasons(result.Report))
			}
			if result.Report.Provenance.KnowledgeOrigin != "external_signed_local" {
				t.Fatalf("provenance %+v", result.Report.Provenance)
			}
			var gw scanreport.Component
			for _, c := range result.Report.Inventory {
				if c.Name == gwSlug {
					gw = c
				}
			}
			if gw.Catalog != cncfcheck.CatalogCommunity {
				t.Fatalf("inventory %+v", gw)
			}
			if layout == cncfknowledge.LayoutPerProject {
				ks := result.Report.Provenance.KnowledgeStore
				if ks == nil || len(ks.Projects) != 1 || ks.Projects[0].Project != gwSlug || ks.Projects[0].TargetPath != "knowledge/community/projects/gateway-api.v1.json" || ks.Projects[0].Status != "present" {
					t.Fatalf("knowledge store %+v", ks)
				}
				if !strings.Contains(string(scanreport.Human(result.Report, scanreport.HumanOptions{})), "knowledge/community/projects/gateway-api.v1.json") {
					t.Fatal("human provenance does not name the community target")
				}
			}

			// The same database, opened by the real route with
			// --knowledge-db, answers the same.
			request, err := ParseArgs(append(append([]string{}, paths...), "--from", "gateway-api=1.1.0", "--to", "gateway-api=1.2.0", "--resource-scope-complete", "--knowledge-db", fixture.store))
			if err != nil {
				t.Fatal(err)
			}
			viaRoute, err := Run(request, Options{Build: &testBuild})
			if err != nil {
				// The rule's window may not contain the verifier's clock;
				// then the route must say so rather than refuse the project.
				var usage *UsageError
				if errors.As(err, &usage) {
					t.Fatalf("the database route refused the community project: %v", err)
				}
				t.Fatal(err)
			}
			if viaRoute.Report.Provenance.KnowledgeOrigin != "external_signed_local" {
				t.Fatalf("route provenance %+v", viaRoute.Report.Provenance)
			}
		})
	}
}
