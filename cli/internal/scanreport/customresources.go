// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"strconv"
	"strings"
)

const (
	// crSarifPrefix starts the rule id of every custom resource result.
	crSarifPrefix = "prufyx/custom-resource/"
	// crSarifBlocked is the rule id of a blocked custom resource whose
	// blocking finding has no result at the object's own location.
	crSarifBlocked     = crSarifPrefix + "blocked"
	kindCustomResource = "custom-resource"
)

// crState is the state a custom resource shows in every output: the verdict
// of an evaluated object (BLOCKED or NO_FINDING, never a pass), else its
// status (NOT_EVALUATED). An unknown status is shown as it is, never as an
// evaluated one.
func crState(cr CustomResource) string {
	if cr.Status == CRStatusEvaluated && cr.Verdict != "" {
		return cr.Verdict
	}
	return cr.Status
}

// crObject is "namespace/name" ("(no name)" when unnamed), digests short.
func crObject(cr CustomResource) string {
	name := short(cr.Name)
	if name == "" {
		name = labelNoName
	}
	if cr.Namespace != "" {
		name = short(cr.Namespace) + "/" + name
	}
	return name
}

// writeCustomResourceTable lists the custom resources in a table, capped at
// maxCustomResourceLines like the text output.
func writeCustomResourceTable(line func(string, ...any), list []CustomResource) {
	if len(list) == 0 {
		return
	}
	line("")
	line("## Custom resources (%d)", len(list))
	line("")
	line("| apiVersion | Kind | Object | Status | Reason | %s |", labelMDActionHeader)
	line("| --- | --- | --- | --- | --- | --- |")
	for i, cr := range list {
		if i == maxCustomResourceLines {
			line("")
			line("%s", mdText("and "+strconv.Itoa(len(list)-i)+" more (see --format json)"))
			break
		}
		line("| %s | %s | %s | %s | %s | %s |", mdText(cr.APIVersion), mdText(cr.Kind), mdCode(crObject(cr)), mdText(crState(cr)), mdText(cr.Reason), mdText(cr.Next))
	}
}

// csvCustomResourceRow is one record of type CUSTOM_RESOURCE: the reason in
// rule_id, the state and the object's apiVersion and kind in title, the next
// action in fix.
func csvCustomResourceRow(cr CustomResource) []string {
	row := make([]string, len(csvColumns))
	row[0] = csvCell("CUSTOM_RESOURCE")
	row[1] = csvCell(cr.Reason)
	row[2] = csvCell(cr.Component)
	row[3] = csvCell(cr.File)
	if cr.Line > 0 {
		row[4] = csvCell(strconv.Itoa(cr.Line))
	}
	row[5] = csvCell(cr.Kind)
	row[6] = csvCell(cr.Namespace)
	row[7] = csvCell(cr.Name)
	row[8] = csvCell(strings.TrimSpace(crState(cr) + " " + cr.APIVersion + " " + cr.Kind))
	row[9] = csvCell(cr.Next)
	return row
}

// sarifCustomResourceRules adds one rule per reason of a not evaluated
// custom resource, and the rule of a blocked one without its own result.
func sarifCustomResourceRules(report Report, add func(sarifRule)) {
	for _, cr := range report.CustomResources {
		switch crState(cr) {
		case CRStatusNotEvaluated:
			id := crSarifPrefix + cr.Reason
			add(sarifRule{ID: id, ShortDescription: sarifText{"custom resource not evaluated: " + cr.Reason},
				Help:                 sarifText{"No reviewed check decided this custom resource (" + cr.Reason + "); this is not a pass."},
				DefaultConfiguration: sarifConfig{sarifNote}, Properties: sarifRuleProps{Basis: "none", Kind: kindCustomResource}})
		case CRVerdictBlocked:
			if !crHasFindingResult(report, cr) {
				add(sarifRule{ID: crSarifBlocked, ShortDescription: sarifText{"custom resource blocked"},
					Help:                 sarifText{"A reviewed rule blocks this custom resource."},
					DefaultConfiguration: sarifConfig{sarifError}, Properties: sarifRuleProps{Basis: "none", Kind: kindCustomResource}})
			}
		}
	}
}

// crHasFindingResult reports whether a finding already gives this object a
// result at its own location, so a blocked object is one error, not two.
func crHasFindingResult(report Report, cr CustomResource) bool {
	for _, f := range report.Findings {
		for _, l := range f.Locations {
			if l.File == cr.File && l.Document == cr.Document && l.Item == cr.Item {
				return true
			}
		}
	}
	return false
}

// sarifCustomResourceResults adds a result for every not evaluated custom
// resource (level note) and for every blocked one without a finding result
// (level error). An object with no finding is a result of neither kind: it
// is listed in the run properties, never as a pass.
func sarifCustomResourceResults(report Report, index map[string]int, results []sarifResult, dropped int) ([]sarifResult, int) {
	for _, cr := range report.CustomResources {
		var id, level, text string
		switch crState(cr) {
		case CRStatusNotEvaluated:
			id, level = crSarifPrefix+cr.Reason, sarifNote
			text = "not evaluated (" + cr.Reason + "): " + cr.Next
		case CRVerdictBlocked:
			if crHasFindingResult(report, cr) {
				continue
			}
			id, level = crSarifBlocked, sarifError
			text = "blocked: " + cr.Next
		default:
			continue
		}
		result := sarifResult{
			RuleID: id, RuleIndex: index[id], Level: level,
			Message:    sarifText{cut(cr.APIVersion+" "+cr.Kind+" "+crObject(cr)+" "+text, sarifMessageMax)},
			Properties: sarifResultProps{Component: cr.Component, Basis: "none", Match: kindCustomResource},
		}
		if uri := sarifURI(cr.File); uri != "" {
			physical := sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri, URIBaseID: sarifSrcRoot}}
			if cr.Line >= 1 {
				physical.Region = &sarifRegion{StartLine: cr.Line}
			}
			result.Locations = []sarifLocation{{PhysicalLocation: physical, LogicalLocations: []sarifLogical{logicalOf(Location{Kind: cr.Kind, Namespace: cr.Namespace, Name: cr.Name})}}}
			result.PartialFingerprints = map[string]string{fingerprintKey: fingerprint(id, uri, cr.Document, cr.Item)}
		}
		results = append(results, result)
	}
	return results, dropped
}

type sarifCustomResource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
	File       string `json:"file"`
	Line       int    `json:"line,omitempty"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	Next       string `json:"next"`
}

func sarifCustomResourceList(report Report) []sarifCustomResource {
	var out []sarifCustomResource
	for _, cr := range report.CustomResources {
		out = append(out, sarifCustomResource{APIVersion: cr.APIVersion, Kind: cr.Kind, Namespace: cr.Namespace, Name: cr.Name,
			File: cr.File, Line: cr.Line, State: crState(cr), Reason: cr.Reason, Next: cr.Next})
	}
	return out
}
