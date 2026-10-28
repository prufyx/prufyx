// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"strings"
	"testing"
)

func TestPathLabelShowsDetectedCurrent(t *testing.T) {
	path := Path{Component: "istio", From: "1.21.0", To: "1.22.0", Gap: ReasonVersionNotDetected}
	declared := Report{Inventory: []Component{{Name: "istio", CurrentSource: "flag"}}}
	detected := Report{Inventory: []Component{{Name: "istio", CurrentSource: "detected"}}}
	if strings.Contains(pathLabel(declared, path), "detected from the manifests") {
		t.Fatal("a declared version was labelled as detected")
	}
	if !strings.Contains(pathLabel(detected, path), "detected from the manifests") {
		t.Fatal("a detected version was not labelled")
	}
}
