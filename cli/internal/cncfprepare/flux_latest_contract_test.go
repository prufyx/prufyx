// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestFluxLatestSourceContractBindsTargetAndUnion(t *testing.T) {
	raw, err := os.ReadFile("flux-latest-source-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Schema string `json:"schema"`
		Target struct {
			Version                  string            `json:"version"`
			TagCommit                string            `json:"tagCommit"`
			ControllerVersions       map[string]string `json:"controllerVersions"`
			ControllerVersionsSource struct {
				URL      string   `json:"url"`
				Revision string   `json:"revision"`
				Digest   string   `json:"contentDigest"`
				Spans    []string `json:"spans"`
			} `json:"controllerVersionsSource"`
		} `json:"target"`
		Previous []struct {
			Version string `json:"version"`
			Commit  string `json:"tagCommit"`
		} `json:"previousMinorHeads"`
		Removed []string `json:"removedAPIs"`
		Sources []struct {
			URL      string   `json:"url"`
			Revision string   `json:"revision"`
			Digest   string   `json:"contentDigest"`
			Spans    []string `json:"spans"`
		} `json:"sources"`
		TargetCRDs []struct {
			Group string            `json:"apiGroup"`
			Kinds map[string]string `json:"kindServedVersions"`
		} `json:"targetCRDs"`
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256(raw)); got != FluxLatestSourceContractDigest {
		t.Fatalf("source contract digest=%s want=%s", got, FluxLatestSourceContractDigest)
	}
	if contract.Schema != "prufyx.io/flux-removed-api-source-contract/v1" || contract.Target.Version != FluxLatestTo || len(contract.Target.TagCommit) != 40 || len(contract.Previous) != 5 || len(contract.Removed) != len(fluxLatestRemovedAPIs) || len(contract.Target.ControllerVersions) != 7 || contract.Target.ControllerVersionsSource.Revision != contract.Target.TagCommit || len(contract.Target.ControllerVersionsSource.Spans) != 1 || !strings.Contains(contract.Scope, "source-watcher") || !strings.Contains(contract.Scope, "not classified") {
		t.Fatalf("contract identity=%#v", contract)
	}
	for i, api := range fluxLatestRemovedAPIs {
		if contract.Removed[i] != api {
			t.Fatalf("removed API[%d]=%q want %q", i, contract.Removed[i], api)
		}
	}
	for _, source := range contract.Sources {
		if source.URL == "" || len(source.Revision) != 40 || len(source.Digest) != len("sha256:")+64 || len(source.Spans) == 0 {
			t.Fatalf("incomplete source=%#v", source)
		}
	}
	if len(contract.TargetCRDs) != 6 {
		t.Fatalf("target CRD source count=%d", len(contract.TargetCRDs))
	}
	gotServed := map[string]map[string]string{}
	for _, crd := range contract.TargetCRDs {
		if crd.Group == "" || len(crd.Kinds) == 0 {
			t.Fatal("target CRD has no per-kind served-version declarations")
		}
		if gotServed[crd.Group] == nil {
			gotServed[crd.Group] = map[string]string{}
		}
		for _, version := range crd.Kinds {
			if version == "" {
				t.Fatal("target CRD contains empty served version")
			}
		}
		for kind, version := range crd.Kinds {
			if gotServed[crd.Group][kind] != "" {
				t.Fatalf("duplicate served kind %s/%s", crd.Group, kind)
			}
			gotServed[crd.Group][kind] = version
		}
	}
	if !reflect.DeepEqual(gotServed, fluxLatestServedVersions) {
		t.Fatalf("served versions=%#v want %#v", gotServed, fluxLatestServedVersions)
	}
}
