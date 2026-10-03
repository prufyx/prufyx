// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// admitPathPolicies parses the pack's path-policy section (as
// lineattest.PackMemberSection located it) strictly and requires every
// record's component to be the subject component of a catalog project, the
// identity that project's rules use. Any problem rejects the whole pack.
func admitPathPolicies(section json.RawMessage, present bool, projects []projectIdentity) (upgradepath.Index, error) {
	if !present {
		return upgradepath.NewIndex(nil), nil
	}
	records, err := upgradepath.Parse(section)
	if err != nil {
		return upgradepath.Index{}, ErrIntegrity
	}
	subjects := subjectComponents(projects)
	for _, record := range records {
		if !subjects[record.Component] {
			return upgradepath.Index{}, ErrIntegrity
		}
	}
	return upgradepath.NewIndex(records), nil
}

func subjectComponents(projects []projectIdentity) map[string]bool {
	out := make(map[string]bool, len(projects))
	for _, project := range projects {
		if component := subjectComponent(project.Slug, project.RepositoryURL); component != "" {
			out[component] = true
		}
	}
	return out
}

// CatalogSubjectComponents lists, in order, the subject components of the
// embedded catalog's projects: the only components a path-policy record (or
// a rule) of this pack may name.
func CatalogSubjectComponents() ([]string, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	set := subjectComponents(b.landscape.Projects)
	out := make([]string, 0, len(set))
	for component := range set {
		out = append(out, component)
	}
	sort.Strings(out)
	return out, nil
}

// PathPolicyFor returns the embedded pack's upgrade-path policy record for a
// component with its freshness at now. Status.Found is false when the pack
// has no record for the component. Only Status.Policy may be used to plan: it
// is nil unless the record is current. A record that exists but is not
// current (Status.RecordNotCurrent: stale, withdrawn or not yet reviewed) is
// a gap of its own, never a fallback to a direct hop. No record is never a
// licence to skip lines either: the planner then plans a single direct hop
// that the caller must still decide.
func PathPolicyFor(component string, now time.Time) (upgradepath.Status, error) {
	b, err := load()
	if err != nil {
		return upgradepath.Status{}, err
	}
	return b.pathPolicyFor(component, now), nil
}

func (b bundle) pathPolicyFor(component string, now time.Time) upgradepath.Status {
	return b.pathPolicies.Lookup(component, now)
}
