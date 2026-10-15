// SPDX-License-Identifier: AGPL-3.0-only

package targetguard

import (
	"fmt"
	"sort"

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
		have := map[string]bool{}
		for _, g := range hp.Groups {
			have[g.Name] = true
		}
		for _, g := range bp.Groups {
			if !have[g.Name] {
				out = append(out, Removal{Kind: KindGroup, Project: bp.Slug, Detail: g.Name})
			}
		}
	}
	reserved := map[string]bool{}
	for _, r := range head.Reserved {
		reserved[r.Name] = true
	}
	for _, r := range base.Reserved {
		if !reserved[r.Name] {
			out = append(out, Removal{Kind: KindReserved, Project: r.Owner, Detail: r.Name})
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
	baseExcl := map[string]bool{}
	for _, e := range b.Exclude {
		baseExcl[e.Path+"\x00"+e.Repo] = true
	}
	for _, e := range h.Exclude {
		if !baseExcl[e.Path+"\x00"+e.Repo] {
			out = append(out, "exclude:"+e.Path)
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
		return nil
	}
	if h == nil {
		return []string{"remote"}
	}
	var out []string
	if lineLess(b.FromLine, h.FromLine) {
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
// matching entry that head's list has and base's list does not; an entry
// that matches no change, or a base entry that head dropped, is refused: the
// list is append-only, so an approval cannot be pre-placed for a later
// change or reused.
func CheckRemovals(base, head Inputs) []Finding {
	var out []Finding
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
	changes := map[string]Removal{}
	for _, r := range Diff(base, head) {
		changes[r.key()] = r
		if !headListed[r.key()] || baseListed[r.key()] {
			out = append(out, Finding{CheckRemovalUnlisted, subject(r), "removed or narrowed without a new entry in " + GuardPath + " (kind " + r.Kind + ", project " + r.Project + ", detail " + r.Detail + ")"})
		}
	}
	for _, r := range head.Guard.Removals {
		if baseListed[r.key()] {
			continue
		}
		if _, ok := changes[r.key()]; !ok {
			out = append(out, Finding{CheckRemovalStale, subject(r), "new removals entry matches no removal in this change"})
		}
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
