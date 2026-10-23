// SPDX-License-Identifier: AGPL-3.0-only

package scanconfig

// Provenance says where an effective value came from.
type Provenance string

const (
	FromFile Provenance = "file"
	FromFlag Provenance = "flag"
)

// Value is one effective setting. Set is false when neither the file nor a
// flag supplied it; an absent setting is never defaulted.
type Value[T any] struct {
	Value  T
	Set    bool
	Source Provenance
}

// FlagDeclarations carries the values given on the command line. A nil
// pointer, nil map or nil slice means the flag was not given.
type FlagDeclarations struct {
	Inputs                []string
	Current               map[string]string
	Target                map[string]string
	Distribution          *string
	ResourceScopeComplete *bool
	TargetApplyRequired   *bool
	MinimumKubeletVersion *string
	MaximumKubeletVersion *string
	// Helm holds, by project, the chart declarations given on the command
	// line; nil when none was given.
	Helm map[string]HelmFlags
}

// HelmFlags is one project's chart declaration on the command line. An
// empty Chart, a nil slice or a nil pointer means that flag was not given.
type HelmFlags struct {
	Chart    string
	Values   []string
	Set      []string
	Complete *bool
}

// HelmEffective is one project's chart declaration after flags have
// overridden the file, key by key.
type HelmEffective struct {
	Chart    Value[string]
	Values   Value[[]string]
	Set      Value[[]string]
	Complete Value[bool]
}

// Effective is the configuration after flags have overridden the file, key by
// key. Merge does not validate flag values; the route that consumes them does.
type Effective struct {
	Inputs                Value[[]string]
	Current               map[string]Value[string]
	Target                map[string]Value[string]
	Distribution          Value[string]
	ResourceScopeComplete Value[bool]
	TargetApplyRequired   Value[bool]
	// MinimumKubeletVersion and MaximumKubeletVersion are the declared
	// kubelet versions; not validated here.
	MinimumKubeletVersion Value[string]
	MaximumKubeletVersion Value[string]
	// Helm holds the chart declarations by project; nil when neither the
	// file nor a flag declares one.
	Helm map[string]HelmEffective
}

// Merge applies flags over cfg. A flag always wins over the file for the same
// key; a key neither supplies stays absent.
func Merge(cfg Config, flags FlagDeclarations) Effective {
	var out Effective
	out.Inputs = pick(cfg.Inputs, cfg.Inputs != nil, flags.Inputs, flags.Inputs != nil)
	out.Current = mergeVersions(cfg.Current, flags.Current)
	out.Target = mergeVersions(cfg.Target, flags.Target)
	var file KubernetesDeclarations
	if cfg.Declarations.Kubernetes != nil {
		file = *cfg.Declarations.Kubernetes
	}
	out.Distribution = pickPtr(file.Distribution, flags.Distribution)
	out.ResourceScopeComplete = pickPtr(file.ResourceScopeComplete, flags.ResourceScopeComplete)
	out.TargetApplyRequired = pickPtr(file.TargetApplyRequired, flags.TargetApplyRequired)
	out.MinimumKubeletVersion = pickPtr(file.MinimumKubeletVersion, flags.MinimumKubeletVersion)
	out.MaximumKubeletVersion = pickPtr(file.MaximumKubeletVersion, flags.MaximumKubeletVersion)
	out.Helm = mergeHelm(cfg.Declarations.Helm, flags.Helm)
	return out
}

func mergeHelm(file map[string]HelmDeclaration, flags map[string]HelmFlags) map[string]HelmEffective {
	if len(file) == 0 && len(flags) == 0 {
		return nil
	}
	out := map[string]HelmEffective{}
	slugs := map[string]bool{}
	for slug := range file {
		slugs[slug] = true
	}
	for slug := range flags {
		slugs[slug] = true
	}
	for slug := range slugs {
		f, inFile := file[slug]
		g := flags[slug]
		out[slug] = HelmEffective{
			Chart:    pick(f.Chart, inFile && f.Chart != "", g.Chart, g.Chart != ""),
			Values:   pick(f.Values, f.Values != nil, g.Values, g.Values != nil),
			Set:      pick(f.Set, f.Set != nil, g.Set, g.Set != nil),
			Complete: pickPtr(f.Complete, g.Complete),
		}
	}
	return out
}

func pick[T any](fileValue T, fileSet bool, flagValue T, flagSet bool) Value[T] {
	switch {
	case flagSet:
		return Value[T]{Value: flagValue, Set: true, Source: FromFlag}
	case fileSet:
		return Value[T]{Value: fileValue, Set: true, Source: FromFile}
	}
	return Value[T]{}
}

func pickPtr[T any](fileValue, flagValue *T) Value[T] {
	var zero T
	if fileValue != nil {
		zero = *fileValue
	}
	if flagValue != nil {
		return pick(zero, fileValue != nil, *flagValue, true)
	}
	return pick(zero, fileValue != nil, zero, false)
}

func mergeVersions(file, flags map[string]string) map[string]Value[string] {
	if len(file) == 0 && len(flags) == 0 {
		return nil
	}
	out := make(map[string]Value[string], len(file)+len(flags))
	for slug, version := range file {
		out[slug] = Value[string]{Value: version, Set: true, Source: FromFile}
	}
	for slug, version := range flags {
		out[slug] = Value[string]{Value: version, Set: true, Source: FromFlag}
	}
	return out
}
