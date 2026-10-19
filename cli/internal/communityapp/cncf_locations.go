// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// claimLocations lists, per rule id, the objects that made a BLOCKED claim
// true. Only a BLOCKED claim has any: a claim without a verdict names no
// object, as scan records locations on findings only. Order and duplicates
// follow scan: sorted, each object once. redact replaces file, namespace and
// name by their digests as scan --redact does.
func claimLocations(claims []constraintengine.Claim, facts map[string][]cncfprepare.ObjectRef, redact bool) map[string][]scanreport.Location {
	out := map[string][]scanreport.Location{}
	for _, claim := range claims {
		if claim.Status != "BLOCKED" {
			continue
		}
		seen := map[cncfprepare.ObjectRef]bool{}
		var locations []scanreport.Location
		for _, fact := range claim.RequiredFacts {
			for _, ref := range facts[fact.FactID] {
				if seen[ref] {
					continue
				}
				seen[ref] = true
				location := scanreport.Location{File: ref.File, Document: ref.Document, Item: ref.Item, Line: ref.Line, Kind: ref.Kind, Namespace: ref.Namespace, Name: ref.Name}
				if redact {
					location = scanreport.RedactLocation(location)
				}
				locations = append(locations, location)
			}
		}
		if len(locations) == 0 {
			continue
		}
		scanreport.SortLocations(locations)
		out[claim.RuleID] = locations
	}
	return out
}

// locationLines are the human object lines of each rule.
func locationLines(locations map[string][]scanreport.Location) map[string][]string {
	out := map[string][]string{}
	for ruleID, list := range locations {
		for _, location := range list {
			out[ruleID] = append(out[ruleID], scanreport.LocationText(location))
		}
	}
	return out
}

var errLocationSplice = errors.New("locations could not be added to the report")

// spliceClaimLocations adds `"locations":[...]` as the last member of each
// listed claim of a verified report. It only inserts bytes: every byte of
// raw stays, in order. The result is checked before it is returned: removing
// the inserted members gives raw back and the output is valid JSON.
func spliceClaimLocations(raw []byte, locations map[string][]scanreport.Location) ([]byte, error) {
	if len(locations) == 0 {
		return raw, nil
	}
	var shape struct {
		Check struct {
			Claims []json.RawMessage `json:"claims"`
		} `json:"check"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, errLocationSplice
	}
	var out, inserted bytes.Buffer
	cursor, added := 0, 0
	for _, claim := range shape.Check.Claims {
		var head struct {
			RuleID string `json:"ruleId"`
		}
		if err := json.Unmarshal(claim, &head); err != nil {
			return nil, errLocationSplice
		}
		at := bytes.Index(raw[cursor:], claim)
		if at < 0 || len(claim) < 2 || claim[len(claim)-1] != '}' {
			return nil, errLocationSplice
		}
		end := cursor + at + len(claim) - 1
		list, ok := locations[head.RuleID]
		if !ok {
			continue
		}
		encoded, err := json.Marshal(list)
		if err != nil {
			return nil, errLocationSplice
		}
		member := append([]byte(`,"locations":`), encoded...)
		out.Write(raw[cursor:end])
		out.Write(member)
		inserted.Write(member)
		cursor = end
		added++
	}
	if added != len(locations) {
		return nil, errLocationSplice
	}
	out.Write(raw[cursor:])
	result := out.Bytes()
	if !json.Valid(result) || len(result) != len(raw)+inserted.Len() {
		return nil, errLocationSplice
	}
	// Removing every inserted member must give the verified bytes back.
	check := result
	for _, claim := range shape.Check.Claims {
		var head struct {
			RuleID string `json:"ruleId"`
		}
		_ = json.Unmarshal(claim, &head)
		if list, ok := locations[head.RuleID]; ok {
			encoded, _ := json.Marshal(list)
			check = bytes.Replace(check, append([]byte(`,"locations":`), encoded...), nil, 1)
		}
	}
	if !bytes.Equal(check, raw) {
		return nil, errLocationSplice
	}
	return result, nil
}
