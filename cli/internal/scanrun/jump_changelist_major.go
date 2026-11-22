// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// changeListMajorSuffix exposes a source-bound minor suffix after an unresolved
// prefix. The prefix is not a release-line inventory or a reviewed major hop.
// Only the first suffix anchor has this exception: later joins still require
// the same release and commit in both adjacent line reviews.
func changeListMajorSuffix(knowledge Knowledge, now time.Time, report *scanreport.Report, slug, component, from, to string, trust cncfcheck.TrustPolicy) (scanreport.Path, bool) {
	if lineattest.CalverComponent(component) || lineattest.PublishedLineComponent(component) ||
		upgradepath.PlanPath(component, from, to, nil).Gap != upgradepath.GapNone {
		return scanreport.Path{}, false
	}
	fromLine, _ := lineattest.LineOf(from)
	toLine, _ := lineattest.LineOf(to)
	fm, _, fok := splitLine(fromLine)
	tm, minor, tok := splitLine(toLine)
	if !fok || !tok || tm != fm+1 || minor < 1 || minor >= upgradepath.MaxHops {
		return scanreport.Path{}, false
	}
	major := strconv.FormatUint(tm, 10)
	firstLine := major + ".1"
	var anchor lineattest.Release
	found := false
	for _, family := range changeListFamilies {
		statuses := knowledge.AttestationsFor(component, firstLine, family, now)
		if len(statuses) == 0 {
			continue
		}
		if found || len(statuses) != 1 {
			return scanreport.Path{}, false
		}
		a := statuses[0].Attestation
		if a.Releases == nil || len(a.Releases.From) != 1 || len(a.Releases.To) != 1 || !statuses[0].Current() || a.Freshness(now) != lineattest.FreshnessCurrent {
			return scanreport.Path{}, false
		}
		candidate, end := a.Releases.From[0], a.Releases.To[0]
		startLine, ok := lineattest.LineOf(candidate.Version)
		endLine, endOK := lineattest.LineOf(end.Version)
		if !ok || !endOK || startLine != major+".0" || endLine != firstLine || constraintengine.PreRelease(candidate.Version) || constraintengine.PreRelease(end.Version) {
			return scanreport.Path{}, false
		}
		if order, ok := constraintengine.CompareVersions(from, candidate.Version); !ok || order >= 0 {
			return scanreport.Path{}, false
		}
		if order, ok := constraintengine.CompareVersions(end.Version, to); !ok || order > 0 {
			return scanreport.Path{}, false
		}
		hop := upgradepath.Hop{From: upgradepath.Endpoint{Version: candidate.Version}, To: upgradepath.Endpoint{Version: end.Version}}
		items, err := changeListItems(family, component, slug, firstLine, statuses, hop, now, trust, io.Discard)
		if err != nil || len(items) != 1 {
			return scanreport.Path{}, false
		}
		anchor, found = candidate, true
	}
	if !found {
		return scanreport.Path{}, false
	}
	// Conflicting identities cannot be reconciled by picking another family or
	// another record. Include the optional anchor-line review in this check.
	commits := map[string]string{}
	for n := uint64(0); n <= minor; n++ {
		for _, family := range changeListFamilies {
			line := major + "." + strconv.FormatUint(n, 10)
			statuses := knowledge.AttestationsFor(component, line, family, now)
			if len(statuses) > 1 {
				return scanreport.Path{}, false
			}
			for _, status := range statuses {
				a := status.Attestation
				if a.Freshness(now) != lineattest.FreshnessCurrent {
					return scanreport.Path{}, false
				}
				window := upgradepath.Hop{From: upgradepath.Endpoint{Version: from}, To: upgradepath.Endpoint{Version: to}}
				if _, err := changeListItems(family, component, slug, line, statuses, window, now, trust, io.Discard); err != nil {
					return scanreport.Path{}, false
				}
				for _, release := range append(append([]lineattest.Release{}, a.Releases.From...), a.Releases.To...) {
					if old, ok := commits[release.Version]; ok && old != release.Commit {
						return scanreport.Path{}, false
					}
					commits[release.Version] = release.Commit
				}
			}
		}
	}
	// Build on a temporary report: refusal must leave no partial additions.
	var suffixReport scanreport.Report
	path, ok := changeListJump(knowledge, now, &suffixReport, slug, component, anchor.Version, to, trust)
	if !ok || path.Jump == nil {
		return scanreport.Path{}, false
	}
	// The first anchor exception cannot make later line-bounded windows
	// composable. Every subsequent join must be an exact shared release.
	for i := 1; i < len(path.Hops); i++ {
		if path.Hops[i-1].To.Version == "" || path.Hops[i-1].To.Version != path.Hops[i].From.Version {
			return scanreport.Path{}, false
		}
	}
	ref := scanreport.HopRef{Index: 1, From: from, To: anchor.Version}
	lineGap := scanreport.NewGap(slug, &ref, scanreport.GapLinesNotListed, fromLine, major)
	majorGap := scanreport.NewGap(slug, &ref, scanreport.GapMajorHopNotCovered, from, anchor.Version)
	// CSV and SARIF already render gap details. Carry scope there as well as
	// Jump.Scope, without adding result kinds or changing notification caps.
	lineGap.Detail = lineGap.Reason + ": " + lineGap.Detail + "; scope: " + scanreport.ChangeListPartialScope
	majorGap.Detail = majorGap.Reason + ": " + majorGap.Detail + "; scope: " + scanreport.ChangeListPartialScope
	for i := range path.Hops {
		path.Hops[i].Index++
	}
	for i := range path.Jump.Hops {
		path.Jump.Hops[i].Index++
	}
	for i := range suffixReport.Gaps {
		if suffixReport.Gaps[i].Hop != nil {
			suffixReport.Gaps[i].Hop.Index++
		}
	}
	reasons := []string{lineGap.Reason, majorGap.Reason}
	path.Hops = append([]scanreport.Hop{{Index: 1, From: scanreport.Endpoint{Version: from}, To: scanreport.Endpoint{Version: anchor.Version}, Status: scanreport.HopNoData, Reasons: reasons}}, path.Hops...)
	jumpHops := append([]scanreport.JumpHop{{Index: 1, From: from, To: anchor.Version, Status: scanreport.JumpHopUndecided, ObjectSetDigest: path.Jump.ObjectSetDigest, Reasons: reasons}}, path.Jump.Hops...)
	actions := map[int]string{1: lineGap.Action + "; " + majorGap.Action}
	for _, gap := range suffixReport.Gaps {
		if gap.Hop != nil {
			actions[gap.Hop.Index] = strings.TrimSpace(actions[gap.Hop.Index] + " " + gap.Action)
		}
	}
	releases := append([]scanreport.JumpRelease{{Line: major + ".0", Version: anchor.Version, Commit: anchor.Commit}}, path.Jump.Releases...)
	jump := scanreport.NewJump(jumpHops, path.Jump.ObjectSetDigest, releases, actions)
	jump.Scope = scanreport.ChangeListPartialScope
	path.From, path.Jump = from, &jump
	// A policy used inside the minor suffix does not review the major prefix.
	path.Policy = ""
	report.Gaps = append(report.Gaps, lineGap, majorGap)
	report.Gaps = append(report.Gaps, suffixReport.Gaps...)
	return path, true
}
