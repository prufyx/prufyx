// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// changeListFamilies are the families whose records list the change-list
// entries of a line, in the order their records are read.
var changeListFamilies = []string{lineattest.FamilyChangelogListedEntries, lineattest.FamilyChangelogAttestedEntries}

// changeListSourcePrefix starts the id of the source that cites one release's
// entry.
const changeListSourcePrefix = "changelog-"

// changeListJump returns the path of a multi-minor upgrade of a component of
// the change-list families, with its jump, or false. The component is
// otherwise not covered: this only adds the per-hop table. A hop is never
// PASS: it is ATTENTION when a valid current record of its line cites change
// lists, and UNDECIDED with a named gap otherwise. The path is the stepwise
// path (one hop per minor line, the refusals of the custom-resource jump
// apply); an intermediate release is only one that the records of the two
// lines both read, at one commit, so no intermediate is guessed.
func changeListJump(knowledge Knowledge, now time.Time, report *scanreport.Report, slug, component, from, to string, trust cncfcheck.TrustPolicy) (scanreport.Path, bool) {
	if from == "" || to == "" {
		return scanreport.Path{}, false
	}
	admitted := false
	for _, id := range changeListFamilies {
		if family, ok := lineattest.LookupFamily(id); ok && family.Admits(component) {
			admitted = true
		}
	}
	if !admitted {
		return scanreport.Path{}, false
	}
	status := knowledge.PathPolicyFor(component, now)
	policy := status.Policy()
	if status.RecordNotCurrent() || (policy != nil && (!trust.Admits(status.Record.Evidence.Basis) || policy.Policy != upgradepath.PolicySequentialMinor)) {
		return scanreport.Path{}, false
	}
	plan := upgradepath.PlanPath(component, from, to, &upgradepath.PathPolicy{Component: component, Policy: upgradepath.PolicySequentialMinor})
	if plan.Gap != upgradepath.GapNone || len(plan.Hops) < 2 || plan.Component != component {
		return scanreport.Path{}, false
	}
	previous, ok := endpointLine(plan.Hops[0].From)
	if !ok {
		return scanreport.Path{}, false
	}
	var lines []string
	for _, hop := range plan.Hops {
		line, ok := endpointLine(hop.To)
		if !ok || !lineattest.LineHop(component, previous, line) {
			return scanreport.Path{}, false
		}
		lines = append(lines, line)
		previous = line
	}
	// The intermediate ends come from the records' own line windows.
	reader := &customResourceRun{knowledge: knowledge, now: now, component: component, policy: trust}
	hops := append([]upgradepath.Hop(nil), plan.Hops...)
	commits := map[string]string{}
	for i := 0; i < len(hops)-1; i++ {
		for _, id := range changeListFamilies {
			family, _ := lineattest.LookupFamily(id)
			if release, found := reader.commonRelease(family, lines[i], lines[i+1]); found {
				hops[i].To = upgradepath.Endpoint{Version: release.Version}
				hops[i+1].From = upgradepath.Endpoint{Version: release.Version}
				commits[release.Version] = release.Commit
				break
			}
		}
	}

	path := scanreport.Path{Component: slug, From: from, To: to}
	if policy != nil {
		path.Policy = policy.Policy
	}
	digest := sha256.New()
	var jumpHops []scanreport.JumpHop
	for i, planned := range hops {
		ref := scanreport.HopRef{Index: planned.Index, From: planned.From.String(), To: planned.To.String()}
		hop := scanreport.Hop{
			Index:  planned.Index,
			From:   scanreport.Endpoint{Version: planned.From.Version, Line: planned.From.Line},
			To:     scanreport.Endpoint{Version: planned.To.Version, Line: planned.To.Line},
			Status: scanreport.HopNoData, Reasons: []string{scanreport.ReasonComponentNotCovered},
		}
		jump := scanreport.JumpHop{Index: hop.Index, From: ref.From, To: ref.To, Status: scanreport.JumpHopUndecided}
		records, problem := 0, ""
		for _, id := range changeListFamilies {
			statuses := knowledge.AttestationsFor(component, lines[i], id, now)
			if len(statuses) == 0 {
				continue
			}
			records++
			items, err := changeListItems(id, component, slug, lines[i], statuses, planned, now, trust, digest)
			if err != nil {
				problem = err.Error()
				break
			}
			jump.Entries = append(jump.Entries, items...)
		}
		switch {
		case problem != "":
			jump.Entries = nil
			hop.Reasons = append(hop.Reasons, gapOf(report, slug, &ref, scanreport.GapChangeListJumpRecord, lines[i], problem, slug))
		case records == 0:
			hop.Reasons = append(hop.Reasons, gapOf(report, slug, &ref, scanreport.GapChangeListJumpNoRecord, lines[i], slug))
		case len(jump.Entries) > 0:
			jump.Status = scanreport.JumpHopAttention
		default:
			// A valid record that lists no release inside the hop's window.
			hop.Reasons = append(hop.Reasons, gapOf(report, slug, &ref, scanreport.GapChangeListJumpRecord, lines[i], "NO_RELEASE_IN_HOP", slug))
		}
		jump.Reasons = append([]string(nil), hop.Reasons[1:]...)
		path.Hops = append(path.Hops, hop)
		jumpHops = append(jumpHops, jump)
	}
	setDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	var releases []scanreport.JumpRelease
	actions := map[int]string{}
	for _, gap := range report.Gaps {
		if gap.Hop != nil && !gap.Hop.WholeUpgrade && gap.Component == slug && actions[gap.Hop.Index] == "" {
			actions[gap.Hop.Index] = gap.Action
		}
	}
	for i := range jumpHops {
		jumpHops[i].ObjectSetDigest = setDigest
		jumpHops[i].Reasons = uniqueStrings(jumpHops[i].Reasons)
		if i < len(hops)-1 && hops[i].To.Version != "" {
			if line, ok := lineattest.LineOf(hops[i].To.Version); ok {
				releases = append(releases, scanreport.JumpRelease{Line: line, Version: hops[i].To.Version, Commit: commits[hops[i].To.Version]})
			}
		}
	}
	jump := scanreport.NewJump(jumpHops, setDigest, releases, actions)
	path.Jump = &jump
	return path, true
}

func gapOf(report *scanreport.Report, slug string, ref *scanreport.HopRef, key scanreport.GapKey, args ...any) string {
	gap := scanreport.NewGap(slug, ref, key, args...)
	report.Gaps = append(report.Gaps, gap)
	return gap.Reason
}

// changeListItems reads the one record of a change-list family for the line a
// hop enters, in full, and returns one cited item per release entry inside the
// hop (the line it leaves is excluded; the end release is included). A record
// that is not the one valid, current, admitted record of the line, that names
// a source it does not pin, or whose sources are not exactly its releases, is
// an error: it is never read partly. The items state that a change list lists
// changes and cite it; they claim nothing about an entry.
func changeListItems(id, component, slug, line string, statuses []lineattest.Status, hop upgradepath.Hop, now time.Time, trust cncfcheck.TrustPolicy, digest interface{ Write([]byte) (int, error) }) ([]string, error) {
	const (
		invalid = "CHANGE_LIST_RECORD_INVALID"
		stale   = "CHANGE_LIST_RECORD_NOT_CURRENT"
		basis   = "CHANGE_LIST_RECORD_BASIS_NOT_ADMITTED"
	)
	family, ok := lineattest.LookupFamily(id)
	if !ok || !family.Admits(component) || len(statuses) != 1 {
		return nil, fmt.Errorf(invalid)
	}
	a := statuses[0].Attestation
	if a.Line != line || a.FactFamily != id || a.Component != component || a.Releases == nil || len(a.Evidence.Sources) == 0 || a.Validate() != nil {
		return nil, fmt.Errorf(invalid)
	}
	if !statuses[0].Current() {
		return nil, fmt.Errorf(stale)
	}
	if !trust.Admits(a.Evidence.Basis) {
		return nil, fmt.Errorf(basis)
	}
	pinned := map[string]string{}
	for _, release := range a.Releases.To {
		pinned[release.Version] = release.Commit
	}
	seen := map[string]bool{}
	var items []string
	sources := append([]constraintengine.SourceEvidence(nil), a.Evidence.Sources...)
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	for _, source := range sources {
		version, ok := strings.CutPrefix(source.ID, changeListSourcePrefix)
		commit, isRelease := pinned[version]
		if !ok || !isRelease || seen[version] || source.URL == "" || source.Revision != commit || !strings.HasPrefix(source.ContentDigest, "sha256:") || source.StartLine < 1 || source.EndLine < source.StartLine {
			return nil, fmt.Errorf(invalid)
		}
		seen[version] = true
		fmt.Fprintf(digest, "%s|%s|%s|%s|%s|%d|%d\n", id, line, source.ID, source.Revision, source.ContentDigest, source.StartLine, source.EndLine)
		inside, ok := inHopWindow(hop, version)
		if !ok {
			return nil, fmt.Errorf(invalid)
		}
		if inside {
			items = append(items, fmt.Sprintf("the change list of %s lists changes for %s; read them before upgrading (%s, commit %s, digest %s, lines %d-%d)",
				version, slug, source.URL, source.Revision, source.ContentDigest, source.StartLine, source.EndLine))
		}
	}
	if len(seen) != len(pinned) {
		return nil, fmt.Errorf(invalid)
	}
	return items, nil
}

// inHopWindow reports whether a release of the entered line lies after the
// hop's start (exclusive) and up to its end (inclusive), where each end is an
// exact release; a line end bounds nothing.
func inHopWindow(hop upgradepath.Hop, version string) (inside, ok bool) {
	if hop.From.Version != "" {
		order, ok := constraintengine.CompareVersions(hop.From.Version, version)
		if !ok {
			return false, false
		}
		if order >= 0 {
			return false, true
		}
	}
	if hop.To.Version != "" {
		order, ok := constraintengine.CompareVersions(version, hop.To.Version)
		if !ok {
			return false, false
		}
		if order > 0 {
			return false, true
		}
	}
	return true, true
}
