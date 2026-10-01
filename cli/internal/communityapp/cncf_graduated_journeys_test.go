// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type graduatedJourney struct {
	name       string
	project    string
	fixture    string
	setup      func(map[string]any)
	pass       func(map[string]any)
	missing    func(map[string]any)
	wrongPair  func(map[string]any)
	passCode   int
	passStatus string
	multiRule  bool
}

func TestSyntheticGraduatedCNCFJourneys(t *testing.T) {
	journeys := []graduatedJourney{
		{
			name:      "Dragonfly manager debug retention",
			project:   "dragonfly",
			fixture:   "dragonfly-input.json",
			multiRule: true,
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.dragonfly.debug_logging_enabled", true)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.dragonfly.debug_logging_enabled")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/dragonflyoss/dragonfly", "2.2.5")
			},
		},
		{
			name:      "Dragonfly scheduler debug retention",
			project:   "dragonfly",
			fixture:   "dragonfly-input.json",
			multiRule: true,
			setup: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.dragonfly.execution_surface", "scheduler_config")
			},
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.dragonfly.debug_logging_enabled", true)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.dragonfly.debug_logging_enabled")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/dragonflyoss/dragonfly", "2.2.5")
			},
		},
		{
			name:    "Falco 0.41 removed flags",
			project: "falco",
			fixture: "falco-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.falco.removed_040_cli_flags_present", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.falco.removed_040_cli_flags_present")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/falcosecurity/falco", "0.41.1")
			},
		},
		{
			name:    "Falco 0.42 removed flags",
			project: "falco",
			fixture: "falco-042-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.falco.removed_040_cli_flags_present", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.falco.removed_040_cli_flags_present")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/falcosecurity/falco", "0.42.1")
			},
		},
		{
			name:    "Fluentd Ruby minimum",
			project: "fluentd",
			fixture: "fluentd-input.json",
			pass: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:generic/ruby", "2.7.0")
			},
			missing: func(document map[string]any) {
				removeProposedComponent(t, document, "pkg:generic/ruby")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/fluent/fluentd", "1.17.1")
			},
		},
		{
			name:    "Flux beta API removal",
			project: "flux",
			fixture: "flux-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.flux.removed_beta_api_present", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.flux.removed_beta_api_present")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/fluxcd/flux2", "2.7.1")
			},
		},
		{
			name:    "Harbor installer format",
			project: "harbor",
			fixture: "harbor-input.json",
			pass: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.harbor.installer_config_format", "yml")
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.harbor.installer_config_format")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/goharbor/harbor", "1.8.1")
			},
		},
		{
			name:    "KEDA external scaler TLS",
			project: "keda",
			fixture: "keda-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.keda.legacy_tls_cert_file_required_for_transport", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.keda.legacy_tls_cert_file_required_for_transport")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/kedacore/keda", "2.17.1")
			},
		},
		{
			name:       "Rook Helm intermediate",
			project:    "rook",
			fixture:    "rook-input.json",
			passStatus: "UNKNOWN",
			passCode:   ExitUnknown,
			pass: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.rook.deployment_mode", "custom")
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.rook.deployment_mode")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/rook/rook", "1.20.1")
			},
		},
		{
			name:    "Rook Kubernetes minimum",
			project: "rook",
			fixture: "rook-input.json",
			setup: func(document map[string]any) {
				setCurrentVersionForComponent(t, document, "pkg:github/rook/rook", "1.19.5")
				addProposedComponent(document, "pkg:github/kubernetes/kubernetes", "1.30.9")
			},
			pass: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/kubernetes/kubernetes", "1.31.0")
			},
			missing: func(document map[string]any) {
				removeProposedComponent(t, document, "pkg:github/kubernetes/kubernetes")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/rook/rook", "1.19.5")
			},
		},
		{
			name:    "SPIRE entry TTL",
			project: "spire",
			fixture: "spire-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.spire.removed_entry_ttl_flag_present", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.spire.removed_entry_ttl_flag_present")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/spiffe/spire", "1.11.1")
			},
		},
		{
			name:    "Vitess multi-statement DBA RPC",
			project: "vitess",
			fixture: "vitess-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.vitess.multi_statement_execute_fetch_as_dba", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.vitess.multi_statement_execute_fetch_as_dba")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersionForComponent(t, document, "pkg:github/vitessio/vitess", "23.0.1")
			},
		},
		{
			name:    "Kubernetes dockershim",
			project: "kubernetes",
			fixture: "kubernetes-dockershim-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.kubernetes.in_tree_dockershim_required", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.kubernetes.in_tree_dockershim_required")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "1.24.1")
			},
		},
		{
			name:    "Crossplane Composition",
			project: "crossplane",
			fixture: "crossplane-composition-input.json",
			pass: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.crossplane.composition_mode", "pipeline")
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.crossplane.schema_validation_required")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "2.0.1")
			},
		},
		{
			name:    "OPA producer",
			project: "opa",
			fixture: "opa-producer-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.opa.producer_v0_compatible", true)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.opa.producer_v0_compatible")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "1.0.1")
			},
		},
		{
			name:      "containerd CRI",
			project:   "containerd",
			fixture:   "containerd-input.json",
			multiRule: true,
			pass: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.containerd.cri_api", "v1")
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.containerd.cri_api")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "2.0.1")
			},
		},
		{
			name:    "CoreDNS federation",
			project: "coredns",
			fixture: "coredns-input.json",
			pass: func(document map[string]any) {
				setProposedBoolFact(t, document, "component.coredns.federation_directive_present", false)
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.coredns.federation_directive_present")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "1.7.1")
			},
		},
		{
			name:    "Envoy xDS",
			project: "envoy",
			fixture: "envoy-input.json",
			pass: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.envoy.xds_api_major", "v3")
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.envoy.xds_api_major")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "1.18.1")
			},
		},
		{
			name:    "Helm post-renderer",
			project: "helm",
			fixture: "helm-post-renderer-input.json",
			pass: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.helm.post_renderer_mode", "plugin_name")
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.helm.post_renderer_mode")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "4.0.1")
			},
		},
		{
			name:    "Istio compatibility profile",
			project: "istio",
			fixture: "istio-compatibility-profile-input.json",
			pass: func(document map[string]any) {
				setProposedEnumFact(t, document, "component.istio.compatibility_profile", "other")
			},
			missing: func(document map[string]any) {
				removeProposedFact(t, document, "component.istio.compatibility_profile")
			},
			wrongPair: func(document map[string]any) {
				setProposedVersion(t, document, "1.24.1")
			},
		},
	}

	for _, journey := range journeys {
		journey := journey
		t.Run(journey.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../../examples/cncf", journey.fixture))
			if err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				name       string
				mutate     func(map[string]any)
				wantCode   int
				wantStatus string
				wantClaim  bool
				wantReason string
			}{
				{name: "declared trigger", wantCode: ExitBlocked, wantStatus: "BLOCKED", wantClaim: true},
				{name: "declared non-trigger", mutate: journey.pass, wantCode: journey.passCode, wantStatus: journey.passStatus, wantClaim: true},
				{name: "missing applicability fact", mutate: journey.missing, wantCode: ExitUnknown, wantStatus: "UNKNOWN", wantClaim: true},
				{name: "wrong transition", mutate: journey.wrongPair, wantCode: ExitUnknown, wantStatus: "UNKNOWN", wantClaim: true, wantReason: "RULE_TRANSITION_NOT_REVIEWED"},
			}
			if journey.project == "coredns" {
				cases = append(cases,
					struct {
						name       string
						mutate     func(map[string]any)
						wantCode   int
						wantStatus string
						wantClaim  bool
						wantReason string
					}{name: "custom distribution guard", mutate: func(document map[string]any) {
						setProposedEnumFact(t, document, "component.coredns.distribution", "custom")
					}, wantCode: ExitUnknown, wantStatus: "UNKNOWN", wantClaim: true},
					struct {
						name       string
						mutate     func(map[string]any)
						wantCode   int
						wantStatus string
						wantClaim  bool
						wantReason string
					}{name: "missing distribution guard", mutate: func(document map[string]any) {
						removeProposedFact(t, document, "component.coredns.distribution")
					}, wantCode: ExitUnknown, wantStatus: "UNKNOWN", wantClaim: true},
				)
			}
			if journey.passStatus == "" {
				cases[1].wantCode = ExitOK
				cases[1].wantStatus = "PASS"
			}
			for _, tc := range cases {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					input := raw
					if tc.mutate != nil {
						var document map[string]any
						if err := json.Unmarshal(raw, &document); err != nil {
							t.Fatal(err)
						}
						if journey.setup != nil {
							journey.setup(document)
						}
						tc.mutate(document)
						input, err = json.Marshal(document)
						if err != nil {
							t.Fatal(err)
						}
					}
					if tc.mutate == nil && journey.setup != nil {
						var document map[string]any
						if err := json.Unmarshal(raw, &document); err != nil {
							t.Fatal(err)
						}
						journey.setup(document)
						input, err = json.Marshal(document)
						if err != nil {
							t.Fatal(err)
						}
					}
					path := writeCNCFFile(t, "input.json", input, 0o600)
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != 0o600 {
						t.Fatalf("input mode=%o, want 0600", info.Mode().Perm())
					}
					now := "2026-09-10T04:00:00Z"
					if journey.project == "containerd" {
						now = "2026-09-12T12:30:00Z"
					}
					args := []string{"check", "cncf", "--project", journey.project, "--input", path, "--input-digest", cncfDigest(input), "--now", now, "--format", "json"}
					code, stdout, stderr := runCNCFCLI(t, args...)
					wantCode := tc.wantCode
					if journey.multiRule {
						if tc.wantStatus == "BLOCKED" {
							wantCode = ExitBlocked
						} else {
							wantCode = ExitUnknown
						}
					}
					if code != wantCode || stderr != "" {
						t.Fatalf("code=%d want=%d stdout=%q stderr=%q", code, wantCode, stdout, stderr)
					}
					if !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || !strings.Contains(stdout, `"networkUsed":false`) || !strings.Contains(stdout, `"runtimeReproduced":0`) {
						t.Fatalf("report escaped bounded preview: %q", stdout)
					}
					if tc.wantClaim && !strings.Contains(stdout, `"status":"`+tc.wantStatus+`"`) {
						t.Fatalf("missing claim status %s: %q", tc.wantStatus, stdout)
					}
					if tc.wantReason != "" && !strings.Contains(stdout, `"reasonCode":"`+tc.wantReason+`"`) {
						t.Fatalf("missing reason %s: %q", tc.wantReason, stdout)
					}
				})
			}
		})
	}
}

func proposedComponent(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	proposed, ok := document["proposed"].(map[string]any)
	if !ok {
		t.Fatal("missing proposed component set")
	}
	components, ok := proposed["components"].([]any)
	if !ok || len(components) == 0 {
		t.Fatal("expected proposed component")
	}
	component, ok := components[0].(map[string]any)
	if !ok {
		t.Fatal("invalid proposed component")
	}
	return component
}

func proposedFacts(t *testing.T, document map[string]any) []any {
	t.Helper()
	facts, ok := proposedComponent(t, document)["facts"].([]any)
	if !ok {
		t.Fatal("missing proposed facts")
	}
	return facts
}

func componentByID(t *testing.T, document map[string]any, side, componentID string) map[string]any {
	t.Helper()
	section, ok := document[side].(map[string]any)
	if !ok {
		t.Fatalf("missing %s component set", side)
	}
	components, ok := section["components"].([]any)
	if !ok {
		t.Fatalf("missing %s components", side)
	}
	for _, raw := range components {
		component, ok := raw.(map[string]any)
		if ok && component["component"] == componentID {
			return component
		}
	}
	t.Fatalf("component %s not found on %s side", componentID, side)
	return nil
}

func factComponent(t *testing.T, document map[string]any, id string) map[string]any {
	t.Helper()
	section, ok := document["proposed"].(map[string]any)
	if !ok {
		t.Fatal("missing proposed component set")
	}
	components, ok := section["components"].([]any)
	if !ok {
		t.Fatal("missing proposed components")
	}
	for _, raw := range components {
		component, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		facts, _ := component["facts"].([]any)
		for _, rawFact := range facts {
			fact, ok := rawFact.(map[string]any)
			if ok && fact["id"] == id {
				return component
			}
		}
	}
	t.Fatalf("fact %s not found", id)
	return nil
}

func setProposedVersion(t *testing.T, document map[string]any, version string) {
	t.Helper()
	proposedComponent(t, document)["version"] = version
}

func setProposedVersionForComponent(t *testing.T, document map[string]any, componentID, version string) {
	t.Helper()
	componentByID(t, document, "proposed", componentID)["version"] = version
}

func setCurrentVersionForComponent(t *testing.T, document map[string]any, componentID, version string) {
	t.Helper()
	componentByID(t, document, "current", componentID)["version"] = version
}

func addProposedComponent(document map[string]any, componentID, version string) {
	section := document["proposed"].(map[string]any)
	components := section["components"].([]any)
	components = append(components, map[string]any{"component": componentID, "version": version, "facts": []any{}})
	sort.Slice(components, func(i, j int) bool {
		return components[i].(map[string]any)["component"].(string) < components[j].(map[string]any)["component"].(string)
	})
	section["components"] = components
}

func setProposedBoolFact(t *testing.T, document map[string]any, id string, value bool) {
	t.Helper()
	setProposedFactValue(t, document, id, "boolValue", value)
}

func setProposedEnumFact(t *testing.T, document map[string]any, id, value string) {
	t.Helper()
	setProposedFactValue(t, document, id, "enumValue", value)
}

func setProposedFactValue(t *testing.T, document map[string]any, id, key string, value any) {
	t.Helper()
	component := factComponent(t, document, id)
	facts, ok := component["facts"].([]any)
	if !ok {
		t.Fatalf("missing proposed facts for %s", id)
	}
	for _, rawFact := range facts {
		fact, ok := rawFact.(map[string]any)
		if ok && fact["id"] == id {
			fact[key] = value
			return
		}
	}
	t.Fatalf("fact %s not found", id)
}

func removeProposedFact(t *testing.T, document map[string]any, id string) {
	t.Helper()
	component := factComponent(t, document, id)
	facts, ok := component["facts"].([]any)
	if !ok {
		t.Fatalf("missing proposed facts for %s", id)
	}
	filtered := make([]any, 0, len(facts))
	for _, rawFact := range facts {
		fact, ok := rawFact.(map[string]any)
		if !ok || fact["id"] != id {
			filtered = append(filtered, rawFact)
		}
	}
	component["facts"] = filtered
}

func removeProposedComponent(t *testing.T, document map[string]any, componentID string) {
	t.Helper()
	section, ok := document["proposed"].(map[string]any)
	if !ok {
		t.Fatal("missing proposed component set")
	}
	components, ok := section["components"].([]any)
	if !ok {
		t.Fatal("missing proposed components")
	}
	filtered := make([]any, 0, len(components))
	for _, raw := range components {
		component, ok := raw.(map[string]any)
		if !ok || component["component"] != componentID {
			filtered = append(filtered, raw)
		}
	}
	section["components"] = filtered
}
