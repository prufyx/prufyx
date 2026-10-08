// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The Kubernetes apply-set route turns a missing declaration into rules that
// cannot read their fact. The engine can only say that a fact is missing; this
// route knows which declaration is missing and which flag makes it, so the
// human output says that in the words of the command line.

const (
	reasonFactUnavailable = "RULE_FACT_UNAVAILABLE"

	kubernetesActionScope      = "the file is not declared to be the complete apply set; if it is, add --resource-scope-complete and run again"
	kubernetesActionApply      = "it is not declared that this file is applied to the target Kubernetes API (if it is, add --target-api-apply-required)"
	kubernetesActionDistroNone = "the Kubernetes distribution is not declared (for upstream builds, add --distribution official_upstream)"
	kubernetesActionDistroCust = "only the official_upstream distribution is evaluated (check your distribution's release notes by hand)"
	kubernetesActionPagination = "the file is a paginated list, so objects are missing; fetch every page and pass the complete list"
	kubernetesActionTemplated  = "the file still contains template syntax; render it (for example with helm template) and check the output"
	kubernetesActionUnresolved = "the file holds objects that cannot be read as Kubernetes manifests with a valid apiVersion and kind; pass only rendered manifests"
)

// kubernetesDeclarationAction is the user-facing next action for an UNKNOWN
// removed-API rule, from the reason the apply set was not evaluated. It is ""
// when the reason is not one this route can name.
func kubernetesDeclarationAction(reason cncfprepare.Reason, targetApplyRequired bool, distribution string) string {
	switch reason {
	case cncfprepare.ReasonKubernetesScopeIncomplete:
		return kubernetesActionScope
	case cncfprepare.ReasonKubernetesPagination:
		return kubernetesActionPagination
	case cncfprepare.ReasonKubernetesTemplated:
		return kubernetesActionTemplated
	case cncfprepare.ReasonKubernetesUnresolved:
		return kubernetesActionUnresolved
	case cncfprepare.ReasonKubernetesTargetGuard:
		var missing []string
		if !targetApplyRequired {
			missing = append(missing, kubernetesActionApply)
		}
		switch distribution {
		case "official_upstream":
		case "":
			missing = append(missing, kubernetesActionDistroNone)
		default:
			missing = append(missing, kubernetesActionDistroCust)
		}
		if len(missing) == 0 {
			return ""
		}
		text := missing[0]
		if len(missing) > 1 {
			text += " and " + missing[1]
		}
		if distribution == "custom_build" {
			return text
		}
		return text + "; then run again"
	}
	return ""
}

// withKubernetesDeclarationActions returns claims with the next action of
// every fact-unavailable claim replaced for display. The report itself, its
// digests and its JSON are unchanged.
func withKubernetesDeclarationActions(claims []constraintengine.Claim, action string) []constraintengine.Claim {
	if action == "" {
		return claims
	}
	out := append([]constraintengine.Claim(nil), claims...)
	for index := range out {
		if out[index].Status == "UNKNOWN" && out[index].ReasonCode == reasonFactUnavailable {
			out[index].NextAction = action
		}
	}
	return out
}
