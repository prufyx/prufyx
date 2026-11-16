package targetdraft

import "github.com/prufyx/prufyx/cli/internal/customresources"

// reservedStop reports whether a group of a CustomResourceDefinition stops
// the generator as reserved: every group of a Kubernetes-reserved namespace
// does, except a group for which the reviewed ownership list holds a record
// naming exactly this project (slug) and this upstream repository. A carrier
// of the group, a project without a record and any other repository keep the
// stop.
func reservedStop(group, slug, ownerRepo string) bool {
	if !customresources.ReservedNamespace(group) && !customresources.KubernetesGroup(group) {
		return false
	}
	return !ownsReserved(customresources.ReservedGroups(), group, slug, ownerRepo)
}

// ownsReserved reports whether records holds a record of group for slug whose
// repository is exactly https://github.com/<ownerRepo>. The comparison is an
// exact, case-sensitive string compare; ownerRepo is already canonical
// (repoCanonical), so a spelling that is not byte-equal (case, .git, ssh,
// trailing dot or slash) is not accepted. customresources validates that a
// group has at most one record, so the first match is the only one.
func ownsReserved(records []customresources.ReservedGroup, group, slug, ownerRepo string) bool {
	if group == "" || slug == "" || ownerRepo == "" {
		return false
	}
	for _, r := range records {
		if r.Name == group {
			return r.Owner == slug && r.Repository == "https://github.com/"+ownerRepo
		}
	}
	return false
}
