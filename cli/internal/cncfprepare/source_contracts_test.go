// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"reflect"
	"testing"
)

type latestSourceContract struct {
	Schema    string `json:"schema"`
	Component string `json:"component"`
	Target    struct {
		Version    string `json:"version"`
		Tag        string `json:"tag"`
		ReleaseTag string `json:"releaseTag"`
		Commit     string `json:"commit"`
	} `json:"target"`
	Origins []struct {
		Version                 string `json:"version"`
		Tag                     string `json:"tag"`
		ReleaseTag              string `json:"releaseTag"`
		Commit                  string `json:"commit"`
		InitializationSemantics string `json:"initializationSemantics"`
	} `json:"origins"`
	TargetSources []struct {
		ID            string `json:"id"`
		Path          string `json:"path"`
		Commit        string `json:"commit"`
		ContentDigest string `json:"contentDigest"`
		StartLine     int    `json:"startLine"`
		EndLine       int    `json:"endLine"`
	} `json:"targetSources"`
	RuntimeClaims string `json:"runtimeClaims"`
}

func TestLatestSourceContractsBindReviewedRoutes(t *testing.T) {
	tests := []struct {
		name, digest, component, targetVersion, targetTag, targetCommit string
		raw                                                             []byte
		origins                                                         []string
		targetSourceCount                                               int
	}{
		{
			name: "Cloud Custodian", raw: cloudCustodianLatestSourceContract,
			digest: CloudCustodianLatestSourceContractDigest, component: CloudCustodianComponent,
			targetVersion: CloudCustodianLatestTo, targetTag: "0.9.52.0", targetCommit: "427a1a3244a9bdae52e3fc56ca4416ff6af7cd5e",
			origins: []string{"0.9.47", "0.9.48", "0.9.49", "0.9.50", "0.9.51"}, targetSourceCount: 4,
		},
		{
			name: "OpenCost", raw: openCostLatestSourceContract,
			digest: OpenCostLatestSourceContractDigest, component: OpenCostComponent,
			targetVersion: OpenCostLatestTo, targetTag: "v1.121.2", targetCommit: "e22df84a4fb1113534514c44616f979f6455c0a7",
			origins: []string{"1.116.0", "1.117.6", "1.118.0", "1.119.2", "1.120.4"}, targetSourceCount: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sourceContractDigest(test.raw); got != test.digest {
				t.Fatalf("contract digest = %s, want %s", got, test.digest)
			}
			var contract latestSourceContract
			if err := json.Unmarshal(test.raw, &contract); err != nil {
				t.Fatal(err)
			}
			tag := contract.Target.Tag
			if tag == "" {
				tag = contract.Target.ReleaseTag
			}
			if contract.Schema != "prufyx.io/cncf-source-contract/v1alpha1" || contract.Component != test.component || contract.Target.Version != test.targetVersion || tag != test.targetTag || contract.Target.Commit != test.targetCommit || contract.RuntimeClaims != "none" || len(contract.TargetSources) != test.targetSourceCount {
				t.Fatalf("unexpected contract identity: %+v", contract)
			}
			origins := make([]string, len(contract.Origins))
			for index, origin := range contract.Origins {
				origins[index] = origin.Version
				if origin.Commit == "" || (origin.Tag == "" && origin.ReleaseTag == "") {
					t.Fatalf("origin is not source-bound: %+v", origin)
				}
			}
			if !reflect.DeepEqual(origins, test.origins) {
				t.Fatalf("origins = %v, want %v", origins, test.origins)
			}
			for _, source := range contract.TargetSources {
				if source.ID == "" || source.Path == "" || source.Commit != test.targetCommit || source.ContentDigest == "" || source.StartLine < 1 || source.EndLine < source.StartLine {
					t.Fatalf("target source is not content-bound: %+v", source)
				}
			}
		})
	}
}

func TestCorrectedLatestSourceContractScope(t *testing.T) {
	var custodian latestSourceContract
	if err := json.Unmarshal(cloudCustodianLatestSourceContract, &custodian); err != nil {
		t.Fatal(err)
	}
	wantCustodian := map[string][2]int{
		"target-iam-access-key-resource": {3339, 3354},
		"target-query-typeinfo-default":  {797, 991},
	}
	for _, source := range custodian.TargetSources {
		if want, ok := wantCustodian[source.ID]; ok && [2]int{source.StartLine, source.EndLine} != want {
			t.Fatalf("%s span = %d-%d, want %d-%d", source.ID, source.StartLine, source.EndLine, want[0], want[1])
		}
		delete(wantCustodian, source.ID)
	}
	if len(wantCustodian) != 0 {
		t.Fatalf("missing corrected Custodian sources: %v", wantCustodian)
	}

	var openCost latestSourceContract
	if err := json.Unmarshal(openCostLatestSourceContract, &openCost); err != nil {
		t.Fatal(err)
	}
	for _, origin := range openCost.Origins {
		if origin.Version == "1.120.4" {
			if origin.InitializationSemantics == "" {
				t.Fatal("OpenCost 1.120.4 prior nil initialization is not recorded")
			}
			return
		}
	}
	t.Fatal("OpenCost 1.120.4 origin is missing")
}
