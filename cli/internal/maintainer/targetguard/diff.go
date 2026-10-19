// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Finding is one failed check.
type Finding struct {
	Check   string
	Subject string
	Message string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s", f.Check, f.Subject, f.Message)
}

// Check names of the removal guard.
const (
	CheckRemovalUnlisted = "removal-not-listed"
	CheckRemovalStale    = "removal-without-change"
	CheckRemovalDropped  = "removal-entry-deleted"
)

// Diff lists what head removed or narrowed compared with base, as the
// Removal entries (Reason empty) that would justify each. It reports only
// what shrinks: an added row, an added target or a widened range is not
// listed.
func Diff(base, head Inputs) []Removal {
	var out []Removal
	headProjects := map[string]customresources.Project{}
	for _, p := range head.Projects {
		headProjects[p.Slug] = p
	}
	for _, bp := range base.Projects {
		hp, ok := headProjects[bp.Slug]
		if !ok {
			out = append(out, Removal{Kind: KindProject, Project: bp.Slug})
			continue
		}
		out = append(out, projectIdentity(bp, hp)...)
		have := map[string]bool{}
		headSource := map[string]string{}
		for _, g := range hp.Groups {
			have[g.Name] = true
			headSource[g.Name] = g.Source
		}
		for _, g := range bp.Groups {
			if !have[g.Name] {
				out = append(out, Removal{Kind: KindGroup, Project: bp.Slug, Detail: g.Name})
			} else if a, b := sourceRepo(g.Source), sourceRepo(headSource[g.Name]); a != b {
				out = append(out, Removal{Kind: KindIdentity, Project: bp.Slug, Detail: "groupRepo:" + g.Name + ":" + b})
			}
		}
	}
	reserved := map[string]customresources.ReservedGroup{}
	for _, r := range head.Reserved {
		reserved[r.Name] = r
	}
	for _, r := range base.Reserved {
		hr, ok := reserved[r.Name]
		switch {
		case !ok:
			out = append(out, Removal{Kind: KindReserved, Project: r.Owner, Detail: r.Name})
		case hr.Owner != r.Owner || hr.Repository != r.Repository:
			out = append(out, Removal{Kind: KindIdentity, Project: r.Owner, Detail: "reserved:" + r.Name + ":" + hr.Owner + ":" + hr.Repository})
		}
	}
	headTargets := map[string]crdversions.Target{}
	for _, t := range head.Targets {
		headTargets[t.Project] = t
	}
	for _, bt := range base.Targets {
		ht, ok := headTargets[bt.Project]
		if !ok {
			out = append(out, Removal{Kind: KindTarget, Project: bt.Project})
			continue
		}
		for _, d := range targetIdentity(bt, ht) {
			out = append(out, Removal{Kind: KindIdentity, Project: bt.Project, Detail: d})
		}
		for _, d := range narrowed(bt, ht) {
			out = append(out, Removal{Kind: KindNarrowed, Project: bt.Project, Detail: d})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func line(l [2]int) string { return fmt.Sprintf("%d.%d", l[0], l[1]) }

func lineLess(a, b [2]int) bool { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]) }

// narrowed lists how head covers less than base. Each string is the Detail
// of a KindNarrowed entry. Any change of a retained path's shape (directory,
// recursion, patterns) is listed too: a reviewer, not this check, decides
// whether it still covers every file.
func narrowed(b, h crdversions.Target) []string {
	var out []string
	if lineLess(b.MinFrom, h.MinFrom) {
		out = append(out, "minFrom:"+line(h.MinFrom))
	}
	for _, p := range b.TagPrefixes {
		if !containsString(h.TagPrefixes, p) {
			out = append(out, "tagPrefix:"+p)
		}
	}
	if !samePrefixOrder(b.TagPrefixes, h.TagPrefixes) {
		out = append(out, "tagPrefixOrder")
	}
	if b.Attest && !h.Attest {
		out = append(out, "attest")
	}
	out = append(out, pathChanges("path", b.Paths, h.Paths)...)
	headChannels := map[string]crdversions.Channel{}
	for _, c := range h.Channels {
		headChannels[c.Name] = c
	}
	for _, c := range b.Channels {
		hc, ok := headChannels[c.Name]
		if !ok {
			out = append(out, "channel:"+c.Name)
			continue
		}
		out = append(out, pathChanges("channelPath:"+c.Name, c.Paths, hc.Paths)...)
	}
	if b.DeclaredChannel != h.DeclaredChannel {
		out = append(out, "declaredChannel:"+h.DeclaredChannel)
	}
	baseExcl := map[string]crdversions.Exclusion{}
	for _, e := range b.Exclude {
		baseExcl[e.Path+"\x00"+e.Repo] = e
	}
	for _, e := range h.Exclude {
		name := e.Path
		if e.Repo != "" {
			name += "@" + e.Repo
		}
		be, ok := baseExcl[e.Path+"\x00"+e.Repo]
		switch {
		case !ok:
			out = append(out, "exclude:"+name)
		case be.Copies != e.Copies || be.PrePatch != e.PrePatch:
			out = append(out, "excludeChanged:"+name)
		}
	}
	out = append(out, remoteChanges(b.Remote, h.Remote)...)
	sort.Strings(out)
	return out
}

func pathChanges(label string, b, h []crdversions.PathSpec) []string {
	var out []string
	head := map[string]crdversions.PathSpec{}
	for _, p := range h {
		head[p.Path] = p
	}
	for _, p := range b {
		hp, ok := head[p.Path]
		if !ok {
			out = append(out, label+":"+p.Path)
			continue
		}
		if shape(p) != shape(hp) {
			out = append(out, label+"Changed:"+p.Path)
		}
	}
	return out
}

func shape(p crdversions.PathSpec) string {
	m, g := "", ""
	if p.Match != nil {
		m = p.Match.String()
	}
	if p.Guard != nil {
		g = p.Guard.String()
	}
	return fmt.Sprintf("%t|%t|%t|%s|%s", p.Dir, p.Recursive, p.Optional, m, g)
}

func remoteChanges(b, h *crdversions.Remote) []string {
	if b == nil {
		if h != nil {
			return []string{"remoteAdded:" + h.Repo}
		}
		return nil
	}
	if h == nil {
		return []string{"remote"}
	}
	var out []string
	if b.FromLine != h.FromLine {
		out = append(out, "remoteFrom:"+line(h.FromLine))
	}
	if b.Repo != h.Repo || b.Directory != h.Directory || b.Kustomization != h.Kustomization {
		out = append(out, "remoteSource")
	}
	pins := map[string]string{}
	for _, p := range h.Pins {
		pins[p.Tag] = p.Commit
	}
	for _, p := range b.Pins {
		switch c, ok := pins[p.Tag]; {
		case !ok:
			out = append(out, "remotePin:"+p.Tag)
		case c != p.Commit:
			out = append(out, "remotePinChanged:"+p.Tag)
		}
	}
	return out
}

func containsString(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// CheckRemovals compares head with base. Every removal or narrowing needs a
// matching entry that head's list has and base's list does not: the entry
// whose Seq equals the number of base entries for the same kind, project and
// detail. An entry that matches no change, or a base entry that head dropped,
// is refused: the list is append-only, so an approval cannot be pre-placed
// for a later change or reused.
func CheckRemovals(base, head Inputs) []Finding {
	var out []Finding
	baseCount := map[string]int{}
	for _, r := range base.Guard.Removals {
		baseCount[r.id()]++
	}
	baseListed := map[string]bool{}
	for _, r := range base.Guard.Removals {
		baseListed[r.key()] = true
	}
	headListed := map[string]bool{}
	for _, r := range head.Guard.Removals {
		headListed[r.key()] = true
	}
	for _, r := range base.Guard.Removals {
		if !headListed[r.key()] {
			out = append(out, Finding{CheckRemovalDropped, subject(r), "an entry of the reviewed removals list was deleted; the list is append-only"})
		}
	}
	required := map[string]bool{}
	for _, r := range Diff(base, head) {
		r.Seq = baseCount[r.id()]
		required[r.key()] = true
		if !headListed[r.key()] {
			out = append(out, Finding{CheckRemovalUnlisted, subject(r), fmt.Sprintf("removed or narrowed without a new entry in %s (kind %s, project %s, detail %q, seq %d)", GuardPath, r.Kind, r.Project, r.Detail, r.Seq)})
		}
	}
	for _, r := range head.Guard.Removals {
		if baseListed[r.key()] || required[r.key()] {
			continue
		}
		out = append(out, Finding{CheckRemovalStale, subject(r), "new removals entry matches no removal in this change (check its seq)"})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func subject(r Removal) string {
	if r.Detail == "" {
		return r.Kind + " " + r.Project
	}
	return r.Kind + " " + r.Project + " " + r.Detail
}

func sourceRepo(source string) string {
	if b, ok := ParseBlob(source); ok {
		return strings.ToLower(b.Owner + "/" + b.Repo)
	}
	return source
}

func projectIdentity(b, h customresources.Project) []Removal {
	var out []Removal
	add := func(detail string) { out = append(out, Removal{Kind: KindIdentity, Project: b.Slug, Detail: detail}) }
	if b.Component != h.Component {
		add("component:" + h.Component)
	}
	if b.Catalog != h.Catalog {
		add("catalog:" + string(h.Catalog))
	}
	if b.FactProject != h.FactProject {
		add("factProject:" + h.FactProject)
	}
	if b.Upstream.License != h.Upstream.License {
		add("license:" + h.Upstream.License)
	}
	if b.Upstream.Repository != h.Upstream.Repository {
		add("upstreamRepository:" + h.Upstream.Repository)
	}
	if sourceRepo(b.Upstream.LicenseSource) != sourceRepo(h.Upstream.LicenseSource) {
		add("licenseSource:" + sourceRepo(h.Upstream.LicenseSource))
	}
	return out
}

func targetIdentity(b, h crdversions.Target) []string {
	var out []string
	if b.Repo != h.Repo {
		out = append(out, "repo:"+h.Repo)
	}
	if b.Component != h.Component {
		out = append(out, "component:"+h.Component)
	}
	if b.FactProject != h.FactProject {
		out = append(out, "factProject:"+h.FactProject)
	}
	if b.Catalog != h.Catalog {
		out = append(out, "catalog:"+h.Catalog)
	}
	return out
}

// samePrefixOrder reports whether the prefixes both lists share keep their
// order of preference.
func samePrefixOrder(b, h []string) bool {
	var common []string
	for _, p := range b {
		if containsString(h, p) {
			common = append(common, p)
		}
	}
	i := 0
	for _, p := range h {
		if containsString(common, p) {
			if common[i] != p {
				return false
			}
			i++
		}
	}
	return true
}
