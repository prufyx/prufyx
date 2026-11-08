// SPDX-License-Identifier: AGPL-3.0-only

package scanconfig

// FlagKind is the value type of a route flag a declaration maps to.
type FlagKind string

const (
	// FlagBool is a boolean flag.
	FlagBool FlagKind = "bool"
	// FlagString is a string flag.
	FlagString FlagKind = "string"
)

// Declaration maps one configuration key to the route flag it stands for.
type Declaration struct {
	// Key is the dotted path of the key in the configuration file.
	Key string
	// Project is the catalog slug of the route the flag belongs to.
	Project string
	// Flag is the flag name without leading dashes.
	Flag string
	Kind FlagKind
	// Values lists the accepted string values; empty for booleans.
	Values []string
}

// Distribution values accepted for a Kubernetes distribution declaration.
const (
	DistributionOfficialUpstream = "official_upstream"
	DistributionCustomBuild      = "custom_build"
)

// ProviderDistributions are the managed and packaged Kubernetes providers a
// caller may declare. Declaring one is not upstream: the Kubernetes rules
// treat it as not covered (as custom_build), and the advisory provider facts
// (providerfacts) are evaluated for it.
var ProviderDistributions = []string{"aks", "eks", "gke", "k3s"}

// DistributionValues is every accepted value of a Kubernetes distribution
// declaration.
func DistributionValues() []string {
	return append([]string{DistributionOfficialUpstream, DistributionCustomBuild}, ProviderDistributions...)
}

// ValidDistribution reports whether v is an accepted distribution value.
func ValidDistribution(v string) bool {
	for _, d := range DistributionValues() {
		if v == d {
			return true
		}
	}
	return false
}

// Declarations lists every declaration the configuration file can carry, in a
// fixed order. Version 1 covers Kubernetes only.
func Declarations() []Declaration {
	return []Declaration{
		{Key: "declarations.kubernetes.distribution", Project: "kubernetes", Flag: "distribution", Kind: FlagString,
			Values: DistributionValues()},
		{Key: "declarations.kubernetes.resourceScopeComplete", Project: "kubernetes", Flag: "resource-scope-complete", Kind: FlagBool},
		{Key: "declarations.kubernetes.targetApplyRequired", Project: "kubernetes", Flag: "target-api-apply-required", Kind: FlagBool},
	}
}
