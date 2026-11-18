package scanrun

import (
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// customResourceReport lists every custom resource of the input (an object
// outside the Kubernetes API groups) and what scan did with it. Each is
// EVALUATED (a reviewed rule or line review applied to its component pair;
// the verdict is BLOCKED or NO_FINDING, never a pass) or NOT_EVALUATED with
// a typed reason and the next bounded action. Nothing is skipped silently.
// The list never changes the verdict, the headline or the exit code.
func customResourceReport(workspace intake.Workspace, inventory map[string]*scanreport.Component, isChart func(string) bool, runs map[string]*customResourceRun) []scanreport.CustomResource {
	index := customresources.DefaultIndex()
	var out []scanreport.CustomResource
	for _, document := range workspace.Documents {
		group := customresources.GroupOf(document.APIVersion)
		if customresources.KubernetesGroup(group) {
			continue
		}
		cr := scanreport.CustomResource{
			APIVersion: document.APIVersion, Kind: document.Kind, Namespace: document.Namespace, Name: document.Name,
			File: document.Source.Display, Document: document.Source.Document, Item: document.Source.Item, Line: document.Source.Line,
			Status: scanreport.CRStatusNotEvaluated,
		}
		owner, attribution := index.OwnerOf(group, document.Kind)
		if attribution != customresources.Owned {
			cr.Reason = scanreport.CRKindNotInKnowledge
			cr.Next = "no reviewed knowledge attributes this group and kind to one component, so nothing checks it; verify its upgrade notes by hand"
			out = append(out, cr)
			continue
		}
		cr.Component = owner
		component, known := inventory[owner]
		run := runs[owner]
		switch {
		case run != nil && run.ran && run.decided:
			cr.Status = scanreport.CRStatusEvaluated
			cr.Verdict = scanreport.CRVerdictNoFinding
			if run.blocked[document.Source] {
				cr.Verdict = scanreport.CRVerdictBlocked
			}
			cr.Next = "only the custom-resource version check ran (schema, conversion and stored versions are not evaluated)"
		case run != nil && run.ran && run.unknownVersion:
			cr.Reason = scanreport.CRComponentVersionUnknown
			cr.Next = "pass --from " + owner + "=<current version> (the input does not identify it)"
		case !known || component.Target == "" || component.Current == "":
			cr.Reason = scanreport.CRComponentVersionUnknown
			cr.Next = versionNext(owner, component, known)
		case isChart(owner):
			cr.Reason = scanreport.CRPairNotCovered
			cr.Next = owner + " is declared as a chart hop; custom-resource rules run on application versions, so scan --from/--to " + owner + " with application versions"
		default:
			cr.Reason = scanreport.CRPairNotCovered
			cr.Next = "no reviewed rule or line review decides " + owner + " " + component.Current + " -> " + component.Target + "; scan each minor upgrade separately or verify by hand"
		}
		out = append(out, cr)
	}
	return out
}

// versionNext names the version flags that are missing for a component.
func versionNext(owner string, component *scanreport.Component, known bool) string {
	switch {
	case !known || component.Current == "" && component.Target == "":
		return "pass --from " + owner + "=<current> --to " + owner + "=<target>"
	case component.Current == "":
		return "pass --from " + owner + "=<current version>"
	default:
		return "pass --to " + owner + "=<target version>"
	}
}
