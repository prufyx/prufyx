// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/k8sremovals"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// maxNativeGapLines bounds the lines NativeAPIVersionGaps returns.
const maxNativeGapLines = 5

// NativeAPIVersionGaps is the API-version backstop of scan for the objects of
// a check cncf --project kubernetes --native-resource input. It returns one
// human-readable line per distinct object type that the target release line
// does not serve or that the review cannot show served: a version removed on a
// line at or below the target, an alpha version of a Kubernetes API group, or
// a version the target's current served list does not name (no usable list is
// also a gap). Any returned line means the route may not report a pass.
func NativeAPIVersionGaps(policy cncfcheck.TrustPolicy, documents []intake.Document, to string, now time.Time) []string {
	const unreviewed = "no reviewed served-API list for the target release line; the API versions of the supplied resources cannot be shown served"
	if len(documents) == 0 {
		return nil
	}
	targetLine, ok := lineattest.LineOf(to)
	if !ok {
		return []string{"target version " + to + " is not a release line; the API versions of the supplied resources cannot be shown served"}
	}
	embedded, err := LoadEmbedded()
	if err != nil {
		return []string{unreviewed}
	}
	component, _ := embedded.Component(kubernetesSlug)
	status := embedded.ServedAPIs(component, targetLine, now)
	usable := status.Found && status.Freshness == lineattest.FreshnessCurrent && status.List.Line == targetLine &&
		status.List.Component == component && policy.Admits(status.List.Basis)
	servedGroups := servedGroupSet(status)
	removed := k8sremovals.AdmissionRemovedVersions()
	reasons := map[string]bool{}
	for _, document := range documents {
		group, version, found := strings.Cut(document.APIVersion, "/")
		if !found {
			group, version = "", document.APIVersion
		}
		object := document.APIVersion + " " + document.Kind
		matched := false
		for _, removal := range removed {
			if removalApplies(removal, group, version, document.Kind, targetLine) {
				reasons[fmt.Sprintf("%s was removed in Kubernetes %s and is not served by %s", object, removal.Line, targetLine)] = true
				matched = true
				break
			}
		}
		if matched || !builtInGroup(group, servedGroups) {
			continue
		}
		switch {
		case alphaVersionRE.MatchString(version):
			reasons[object+" is an alpha API version; alpha APIs are not covered"] = true
		case !usable:
			reasons[object+": "+unreviewed] = true
		case !status.List.APIs[object]:
			reasons[object+" is not in the reviewed served-API list of "+targetLine] = true
		}
	}
	lines := make([]string, 0, len(reasons))
	for line := range reasons {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	if len(lines) > maxNativeGapLines {
		lines = append(lines[:maxNativeGapLines], fmt.Sprintf("and %d more", len(lines)-maxNativeGapLines))
	}
	return lines
}
