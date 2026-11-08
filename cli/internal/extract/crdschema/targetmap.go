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
// Target and one reason per refused feature; there is never a partial Target.
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
// crdschema also reads a bare or v-prefixed tag whichever the target names, so
// for a single prefix it reads a superset of the tags; a tag of the other
// spelling at another commit can only add a withheld line, never a claim.

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

// TargetFromCRDVersions maps a crdversions target to a crdschema Target, or
// refuses it with every reason found (in a fixed order).
func TargetFromCRDVersions(c crdversions.Target) (Target, Reasons) {
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
		return Target{}, rs
	}
	t := Target{Repo: repo, Files: files, Dirs: dirs}
	if err := t.validate(); err != nil {
		return Target{}, Reasons{{ReasonMapPath, err.Error()}}
	}
	return t, nil
}
