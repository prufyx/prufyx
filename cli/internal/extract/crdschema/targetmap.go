// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"path"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// The target mapper. It is inert and unwired: nothing registers the crdschema
// extractor, and nothing calls TargetFromCRDVersions outside tests. It exists
// so that a later wiring change can derive a crdschema Target from the
// reviewed crdversions target table without a second, hand-kept list, and so
// that a feature crdschema cannot honour is refused instead of being dropped.
//
// A crdversions target is mapped only when everything it says is something
// crdschema does itself. Otherwise TargetFromCRDVersions returns the zero
// Target and one reason per refused feature; there is never a partial Mapping.
//
// Refused, and why:
//
//   - tag prefixes other than "v", "" or the pair "v" and "": crdschema reads
//     exactly v?X.Y.Z (numbers canonical, a padded number withholds the line,
//     a release named by both spellings at different commits withholds the
//     line, pre-releases are not releases). A chart or product prefix
//     ("jenkins-", "knative-v") is not read at all.
//   - a release scheme (calver): crdschema groups lines by major.minor only.
//   - exclude entries: crdschema has no exclusion model, and ignoring one
//     would change which files count. cert-manager, kuma and mariadb-operator
//     are refused for this today.
//   - declared channel or channels: crdschema reads one set of files.
//   - remote: crdschema reads only the repository it is given.
//   - a target that does not attest.
//   - paths that are recursive, optional, or use a match or guard other than
//     the default pair, and anything that is not a clean path: crdschema reads
//     a directory one level deep and treats a missing path as a fault.
//   - a repository key that is not github.com/<owner>/<name>.
//
// Not carried: MinFrom. crdschema has no such field and pairs every two
// consecutive minor lines; the wiring layer must apply the crdversions MinFrom
// to the pairs it keeps (a mapped Target says nothing about it).
//
// Tag prefixes are carried in Mapping.TagPrefixes. crdschema itself reads both
// the v-prefixed and the bare spelling whichever the target names. That
// superset is NOT safe by itself: a v-only target in a repository with bare
// sibling tags (another component's 2.0.0) would get a line crdversions never
// treats as a release, and a pair could be attested for a version the target
// rejects. The wiring change MUST pass the release index through FilterIndex
// (or FilterTags) with Mapping.TagPrefixes before any release-line derivation.

// Mapper refusal codes. They are stable: the real-table test pins them.
const (
	ReasonMapRepo          = "MAP_REPO"
	ReasonMapNotAttested   = "MAP_NOT_ATTESTED"
	ReasonMapTagPrefix     = "MAP_TAG_PREFIX"
	ReasonMapReleaseScheme = "MAP_RELEASE_SCHEME"
	ReasonMapExclude       = "MAP_EXCLUDE"
	ReasonMapChannels      = "MAP_CHANNELS"
	ReasonMapRemote        = "MAP_REMOTE"
	ReasonMapPath          = "MAP_PATH"
)

// Mapping is a mapped target and the exact tag prefixes of the crdversions
// target (in its order). The zero Mapping means refused.
type Mapping struct {
	Target      Target
	TagPrefixes []string
}

// FilterTags returns the tags that are final releases of one of the prefixes,
// in the input order, using the crdversions final-tag grammar (a padded or
// duplicate spelling is kept, so that the line derivation withholds it).
// Anything else (other prefixes, chart or component names, pre-releases) is
// dropped, as crdversions ignores it.
func FilterTags(tags []string, prefixes []string) []string {
	out := []string{}
	for _, t := range tags {
		for _, p := range prefixes {
			if _, _, ok := crdversions.ReadFinalTag(p, 4, t); ok {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// FilterIndex returns the release index reduced to the tags FilterTags keeps.
func FilterIndex(index extract.ReleaseIndex, prefixes []string) extract.ReleaseIndex {
	names := make([]string, len(index.Tags))
	for i, t := range index.Tags {
		names[i] = t.Name
	}
	keep := map[string]bool{}
	for _, n := range FilterTags(names, prefixes) {
		keep[n] = true
	}
	out := index
	out.Tags = nil
	for _, t := range index.Tags {
		if keep[t.Name] {
			out.Tags = append(out.Tags, t)
		}
	}
	return out
}

// Reason is one refusal: a stable code and a short detail naming the
// feature (a path, a prefix), never file content.
type Reason struct {
	Code   string
	Detail string
}

// Reasons is the list of refusals; empty means the target mapped.
type Reasons []Reason

var (
	mapMatchRE = regexp.MustCompile(`^[^.][^/]*\.ya?ml$`)
	mapGuardRE = regexp.MustCompile(`(?i)crd`)
)

func equalPrefixes(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TargetFromCRDVersions maps a crdversions target to a crdschema Mapping, or
// refuses it with every reason found (in a fixed order).
func TargetFromCRDVersions(c crdversions.Target) (Mapping, Reasons) {
	var rs Reasons
	add := func(code, detail string) { rs = append(rs, Reason{code, detail}) }

	repo, err := extract.ParseRepo(c.Repo)
	if err != nil {
		add(ReasonMapRepo, c.Repo)
	}
	if c.ReleaseScheme != "" {
		add(ReasonMapReleaseScheme, c.ReleaseScheme)
	} else if !(equalPrefixes(c.TagPrefixes, "v") || equalPrefixes(c.TagPrefixes, "") ||
		equalPrefixes(c.TagPrefixes, "v", "") || equalPrefixes(c.TagPrefixes, "", "v")) {
		add(ReasonMapTagPrefix, strings.Join(c.TagPrefixes, ","))
	}
	if len(c.Exclude) > 0 {
		add(ReasonMapExclude, c.Exclude[0].Path)
	}
	if c.DeclaredChannel != "" || len(c.Channels) > 0 {
		add(ReasonMapChannels, c.DeclaredChannel)
	}
	if c.Remote != nil {
		add(ReasonMapRemote, c.Remote.Repo)
	}
	if !c.Attest {
		add(ReasonMapNotAttested, c.Project)
	}

	var files, dirs []string
	if len(c.Paths) == 0 {
		add(ReasonMapPath, "no path")
	}
	for _, p := range c.Paths {
		switch {
		case p.Path == "" || p.Path == "." || p.Path != path.Clean(p.Path) || strings.HasPrefix(p.Path, "/") || p.Path == ".." || strings.HasPrefix(p.Path, "../"):
			add(ReasonMapPath, p.Path)
		case p.Recursive || p.Optional:
			add(ReasonMapPath, p.Path)
		case !p.Dir:
			if p.Match != nil || p.Guard != nil {
				add(ReasonMapPath, p.Path)
				continue
			}
			files = append(files, p.Path)
		default:
			if p.Match == nil || p.Guard == nil || p.Match.String() != mapMatchRE.String() || p.Guard.String() != mapGuardRE.String() {
				add(ReasonMapPath, p.Path)
				continue
			}
			dirs = append(dirs, p.Path)
		}
	}
	if len(rs) > 0 {
		return Mapping{}, rs
	}
	t := Target{Repo: repo, Files: files, Dirs: dirs}
	if err := t.validate(); err != nil {
		return Mapping{}, Reasons{{ReasonMapPath, err.Error()}}
	}
	return Mapping{Target: t, TagPrefixes: append([]string{}, c.TagPrefixes...)}, nil
}
