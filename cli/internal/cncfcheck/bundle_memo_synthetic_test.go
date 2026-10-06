// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"reflect"
	"testing"
)

// Synthetic build: load never serves a cached bundle, so a synthetic run
// sees the synthetic pack and, once restored, the production pack again.
func TestSyntheticBuildIsolatedFromProductionLoad(t *testing.T) {
	before, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if before.pack.Revision == "synthetic-test-only" {
		t.Fatal("synthetic pack active before UseSyntheticKnowledge")
	}
	restore, err := UseSyntheticKnowledge(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	during, err := load()
	if err != nil {
		restore()
		t.Fatal(err)
	}
	if during.pack.Revision != "synthetic-test-only" {
		restore()
		t.Fatalf("synthetic run saw revision %q", during.pack.Revision)
	}
	restore()
	after, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("production bundle not restored after synthetic run")
	}
}
