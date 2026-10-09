// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The Kubernetes apply-set route turns a missing declaration into rules that
// cannot read their fact. The engine can only say that a fact is missing; this
// route knows which declaration is missing and which flag makes it, so the
// human output says that in the words of the command line.

const (
	reasonFactUnavailable = "RULE_FACT_UNAVAILABLE"

	kubernetesDeclareScope      = "--resource-scope-complete if the file is the complete apply set"
	kubernetesDeclareApply      = "--target-api-apply-required if the file is applied to the target Kubernetes API"
	kubernetesDeclareDistroNone = "--distribution official_upstream for an upstream build"
	kubernetesActionDistroCust  = "only the official_upstream distribution is evaluated (check your distribution's release notes by hand)"
	kubernetesActionPagination  = "the file is a paginated list, so objects are missing; fetch every page and pass the complete list"
	kubernetesActionTemplated   = "the file still contains template syntax; render it (for example with helm template) and check the output"
	kubernetesActionUnresolved  = "the file holds objects that cannot be read as Kubernetes manifests with a valid apiVersion and kind; pass only rendered manifests"
)

// kubernetesDeclarationAction is the user-facing next action for an UNKNOWN
// removed-API rule, from the reason the apply set was not evaluated. It is ""
// when the reason is not one this route can name. When a declaration is the
// reason, every declaration still missing is named in one line, so a user
// does not learn about the next one only on the next run.
func kubernetesDeclarationAction(reason cncfprepare.Reason, scopeComplete, targetApplyRequired bool, distribution string) string {
	switch reason {
	case cncfprepare.ReasonKubernetesPagination:
		return kubernetesActionPagination
	case cncfprepare.ReasonKubernetesTemplated:
		return kubernetesActionTemplated
	case cncfprepare.ReasonKubernetesUnresolved:
		return kubernetesActionUnresolved
	case cncfprepare.ReasonKubernetesScopeIncomplete, cncfprepare.ReasonKubernetesTargetGuard:
		var missing []string
		if !scopeComplete {
			missing = append(missing, kubernetesDeclareScope)
		}
		if !targetApplyRequired {
			missing = append(missing, kubernetesDeclareApply)
		}
		custom := false
		switch distribution {
		case "official_upstream":
		case "":
			missing = append(missing, kubernetesDeclareDistroNone)
		default:
			custom = true
		}
		var text string
		if len(missing) > 0 {
			text = "not everything the check needs is declared; if it is true, add " + strings.Join(missing, ", ")
			if custom {
				text += "; " + kubernetesActionDistroCust
			}
			return text + "; then run again"
		}
		if custom {
			return kubernetesActionDistroCust
		}
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
