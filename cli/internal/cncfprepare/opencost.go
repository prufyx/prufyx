// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "unicode/utf8"

// OpenCost cloud-cost source selection is an operator declaration, not a
// native OpenCost configuration document. The adapter retains only the facts
// needed for the reviewed v1.119.0 to v1.120.0 source-selection constraint.
const (
	OpenCostDeclarationSchema = "prufyx.io/opencost-cloud-cost-source-selection/v1alpha1"
	OpenCostComponent         = "pkg:github/opencost/opencost"
	OpenCostFrom              = "1.119.0"
	OpenCostTo                = "1.120.0"
	OpenCostLatestTo          = "1.121.2"

	OpenCostCurrentEnabledFact          = "component.opencost.current_cloud_cost_enabled"
	OpenCostCurrentCompleteFact         = "component.opencost.current_source_selection_complete"
	OpenCostCurrentProviderRelianceFact = "component.opencost.current_provider_derived_source_selected"
	OpenCostProposedEnabledFact         = "component.opencost.proposed_cloud_cost_enabled"
	OpenCostProposedCompleteFact        = "component.opencost.proposed_source_selection_complete"
	OpenCostTargetSourceReadyFact       = "component.opencost.target_cloud_integration_source_selected_and_declared_present"
)

var openCostLatestOrigins = [...]string{"1.120.4", "1.119.2", "1.118.0", "1.117.6", "1.116.0"}

const (
	ReasonOpenCostSelectionDeclared    Reason = "OPENCOST_CLOUD_COST_SOURCE_SELECTION_DECLARED"
	ReasonOpenCostSelectionUnsupported Reason = "OPENCOST_CLOUD_COST_SOURCE_SELECTION_UNRESOLVED"
)

type openCostSelection struct {
	enabled  bool
	complete bool
	source   string
	config   string
}

// PrepareOpenCostCloudSource minimizes one caller-owned declaration of the
// already-resolved cloud-cost source selection. A declared file presence is
// not a filesystem observation and does not validate the file, credentials,
// deployment mounts, provider values, cloud access, startup, or runtime.
func PrepareOpenCostCloudSource(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	if to == OpenCostLatestTo && sourceContractDigest(openCostLatestSourceContract) != OpenCostLatestSourceContractDigest {
		return Prepared{}, ErrInvalid
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"schema": true, "current": true, "proposed": true}) != nil {
		return Prepared{}, ErrInvalid
	}
	schema, ok := root["schema"].(string)
	if !ok || schema != OpenCostDeclarationSchema {
		return Prepared{}, ErrInvalid
	}
	current, currentOK, err := openCostSide(root["current"], false)
	if err != nil {
		return Prepared{}, err
	}
	proposed, proposedOK, err := openCostSide(root["proposed"], true)
	if err != nil {
		return Prepared{}, err
	}

	currentFacts := []inputFact{
		{ID: OpenCostCurrentEnabledFact, State: "unsupported"},
		{ID: OpenCostCurrentProviderRelianceFact, State: "unsupported"},
		{ID: OpenCostCurrentCompleteFact, State: "unsupported"},
	}
	proposedFacts := []inputFact{
		{ID: OpenCostProposedEnabledFact, State: "unsupported"},
		{ID: OpenCostProposedCompleteFact, State: "unsupported"},
		{ID: OpenCostTargetSourceReadyFact, State: "unsupported"},
	}
	state, reason := StateUnknown, ReasonOpenCostSelectionUnsupported
	if currentOK {
		currentFacts[0] = boolFact(OpenCostCurrentEnabledFact, current.enabled)
		currentFacts[2] = boolFact(OpenCostCurrentCompleteFact, current.complete)
		if current.complete {
			currentFacts[1] = boolFact(OpenCostCurrentProviderRelianceFact, current.source == "provider_derived")
		}
	}
	if proposedOK {
		proposedFacts[0] = boolFact(OpenCostProposedEnabledFact, proposed.enabled)
		proposedFacts[1] = boolFact(OpenCostProposedCompleteFact, proposed.complete)
		if proposed.complete {
			ready, resolved := openCostTargetReady(proposed)
			if resolved {
				proposedFacts[2] = boolFact(OpenCostTargetSourceReadyFact, ready)
			}
		}
	}
	if currentOK && proposedOK && current.complete && proposed.complete && currentFacts[1].State == "declared" && proposedFacts[2].State == "declared" {
		state, reason = StatePrepared, ReasonOpenCostSelectionDeclared
	}
	canonical, err := marshalComponentInputBoth(OpenCostComponent, from, to, currentFacts, proposedFacts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{
		CanonicalInputJSON: canonical,
		SourceDigest:       digestBytes(raw),
		InputDigest:        digestBytes(canonical),
		State:              state,
		Reason:             reason,
		Omissions: []string{
			"SOURCE_SELECTION_AND_FILE_PRESENCE_ARE_CALLER_DECLARED_NOT_OBSERVED",
			"CONFIG_CONTENT_CREDENTIALS_MOUNTS_AND_CLOUD_ACCESS_NOT_EVALUATED",
			"STARTUP_RUNTIME_PROVIDER_COVERAGE_AND_WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED",
		},
	}, nil
}

func openCostSide(value any, proposed bool) (openCostSelection, bool, error) {
	object, ok := value.(map[string]any)
	if !ok {
		if value == nil {
			return openCostSelection{}, false, nil
		}
		return openCostSelection{}, false, ErrInvalid
	}
	allowed := map[string]bool{"cloudCostEnabled": true, "sourceSelectionComplete": true, "selectedSource": true}
	if proposed {
		allowed["cloudIntegrationConfigSource"] = true
	}
	if allowFields(object, allowed) != nil {
		return openCostSelection{}, false, ErrInvalid
	}
	enabled, enabledOK := object["cloudCostEnabled"].(bool)
	complete, completeOK := object["sourceSelectionComplete"].(bool)
	if !enabledOK || !completeOK {
		if _, exists := object["cloudCostEnabled"]; exists && !enabledOK {
			return openCostSelection{}, false, ErrInvalid
		}
		if _, exists := object["sourceSelectionComplete"]; exists && !completeOK {
			return openCostSelection{}, false, ErrInvalid
		}
		return openCostSelection{}, false, nil
	}
	selection := openCostSelection{enabled: enabled, complete: complete}
	if source, exists := object["selectedSource"]; exists {
		text, ok := source.(string)
		if !ok {
			return openCostSelection{}, false, ErrInvalid
		}
		selection.source = text
	}
	if proposed {
		if config, exists := object["cloudIntegrationConfigSource"]; exists {
			text, ok := config.(string)
			if !ok {
				return openCostSelection{}, false, ErrInvalid
			}
			selection.config = text
		}
	}
	if !complete {
		return selection, true, nil
	}
	if selection.source != "provider_derived" && selection.source != "cloud_integration" {
		return selection, false, nil
	}
	if proposed && selection.config != "present" && selection.config != "absent" {
		return selection, false, nil
	}
	if proposed && selection.source == "provider_derived" && selection.config == "present" {
		return selection, false, nil
	}
	return selection, true, nil
}

func openCostTargetReady(selection openCostSelection) (bool, bool) {
	if selection.source == "cloud_integration" {
		return selection.config == "present", true
	}
	if selection.source == "provider_derived" && selection.config == "absent" {
		return false, true
	}
	return false, false
}

func boolFact(id string, value bool) inputFact {
	return inputFact{ID: id, State: "declared", BoolValue: &value}
}
