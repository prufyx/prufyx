// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Kubebuilder scaffolding and legacy definitions. A kubebuilder project
// keeps, next to its generated definitions (config/crd/bases), a
// kustomization (config/crd/kustomization.yaml) and two kinds of file that
// name the CustomResourceDefinition kind without defining one: strategic
// merge patch fragments (config/crd/patches/webhook_in_*.yaml and
// cainjection_in_*.yaml) that switch on a conversion webhook or a CA
// injection annotation, and a kustomize transformer configuration
// (kustomizeconfig.yaml) that tells kustomize where in a definition the
// webhook service name and namespace live. Older projects also keep
// apiextensions.k8s.io/v1beta1 copies of their definitions for clusters
// before 1.16. The scan recognises each, precisely and fail-closed:
//
//   - a patch fragment (class crd-patch) is a file under a declared
//     definition kustomization directory (a directory, not the repository
//     root, whose kustomization lists a file of the listed paths among its
//     resources) whose every document is an apiextensions.k8s.io/v1 or
//     v1beta1 CustomResourceDefinition of a definition the listed paths
//     hold, with nothing but metadata.name, metadata labels and annotations,
//     spec.conversion and spec.preserveUnknownFields, each of a known shape.
//     None of these can add, remove, serve or unserve a version, or change
//     a group, a kind or a scope. Any other key (a strategic merge
//     directive such as $patch, spec.versions, spec.group, ...) leaves the
//     file unread;
//   - a transformer configuration (class kustomize-config) is a file in
//     such a directory whose single document holds only the nameReference,
//     namespace, varReference, commonLabels and commonAnnotations lists, in
//     which every field spec of the CustomResourceDefinition kind names the
//     apiextensions.k8s.io group and a path under spec/conversion or
//     metadata labels and annotations. A path elsewhere (spec/versions,
//     spec/group, ...) would let kustomize rewrite a definition, and keeps
//     the file a reference;
//   - a legacy copy (class legacy-copy) is a file whose definitions are
//     strictly read, at least one of them an apiextensions.k8s.io/v1beta1
//     definition (version and versions, served and storage flags as the
//     v1beta1 API defines them), and every one in the inventory with the
//     same group, kind, versions and served flags. A v1beta1 definition that
//     serves other versions is a conflict, one the inventory does not hold
//     is an extra definition, exactly as for a v1 copy.
//
// None of the three blocks attestation. Everything else that names the kind
// keeps its class (unread, reference, ...).

// Classes of the kubebuilder scaffolding and legacy copies.
const (
	// ClassCRDPatch: a strategic merge patch fragment under a declared
	// definition kustomization directory that only touches conversion,
	// preserveUnknownFields or metadata labels and annotations of a
	// definition the listed paths hold.
	ClassCRDPatch = "crd-patch"
	// ClassKustomizeConfig: a kustomize transformer configuration under a
	// declared definition kustomization directory whose field specs of the
	// kind only reach conversion settings or metadata labels and
	// annotations.
	ClassKustomizeConfig = "kustomize-config"
	// ClassLegacyCopy: apiextensions.k8s.io/v1beta1 definitions that agree
	// with the inventory (group, kind, versions and served flags).
	ClassLegacyCopy = "legacy-copy"
)

const (
	crdAPIVersionV1beta1 = "apiextensions.k8s.io/v1beta1"
	crdGroup             = "apiextensions.k8s.io"
)

// configPathRE is a field spec path a transformer configuration may give
// for the CustomResourceDefinition kind.
var configPathRE = regexp.MustCompile(`^(spec/conversion|metadata/(annotations|labels))(/[^\x00-\x1f]+)?$`)

// fragmentRead is a file's bytes read as patch fragments.
type fragmentRead struct {
	// names are the definitions the documents patch, sorted, unique.
	names []string
	// problem is why the bytes are not patch fragments ("" when they are).
	problem string
}

// readFragments reads strictly decoded documents as strategic merge patch
// fragments of definitions. Every document must be one.
func readFragments(values []any) *fragmentRead {
	fr := &fragmentRead{}
	if len(values) == 0 {
		fr.problem = "no document"
		return fr
	}
	seen := map[string]bool{}
	for i, v := range values {
		name, why := fragmentDoc(v)
		if why != "" {
			fr.problem = fmt.Sprintf("document %d: %s", i+1, why)
			fr.names = nil
			return fr
		}
		if !seen[name] {
			seen[name] = true
			fr.names = append(fr.names, name)
		}
	}
	sort.Strings(fr.names)
	return fr
}

// fragmentDoc checks one document of a patch fragment and returns the
// definition it patches.
func fragmentDoc(v any) (string, string) {
	obj, ok := v.(map[string]any)
	if !ok {
		return "", "not a mapping"
	}
	for _, k := range sortedKeys(obj) {
		switch k {
		case "apiVersion", "kind", "metadata", "spec":
		default:
			return "", fmt.Sprintf("key %q", k)
		}
	}
	if av, _ := obj["apiVersion"].(string); av != crdAPIVersion && av != crdAPIVersionV1beta1 {
		return "", fmt.Sprintf("apiVersion %q", obj["apiVersion"])
	}
	if k, _ := obj["kind"].(string); k != crdKind {
		return "", fmt.Sprintf("kind %q", obj["kind"])
	}
	meta, ok := obj["metadata"].(map[string]any)
	if !ok {
		return "", "no metadata mapping"
	}
	for _, k := range sortedKeys(meta) {
		switch k {
		case "name":
		case "annotations", "labels":
			if why := stringMap(meta[k]); why != "" {
				return "", fmt.Sprintf("metadata.%s %s", k, why)
			}
		default:
			return "", fmt.Sprintf("metadata key %q", k)
		}
	}
	name, _ := meta["name"].(string)
	if name == "" || len(name) > maxNameBytes {
		return "", "metadata.name is not a definition name"
	}
	raw, present := obj["spec"]
	if !present {
		return name, ""
	}
	spec, ok := raw.(map[string]any)
	if !ok {
		return "", "spec is not a mapping"
	}
	for _, k := range sortedKeys(spec) {
		switch k {
		case "preserveUnknownFields":
			if _, ok := spec[k].(bool); !ok {
				return "", "spec.preserveUnknownFields is not a boolean"
			}
		case "conversion":
			if why := conversionShape(spec[k]); why != "" {
				return "", "spec.conversion " + why
			}
		default:
			return "", fmt.Sprintf("spec key %q", k)
		}
	}
	return name, ""
}

// conversionShape checks a conversion stanza of either API version.
func conversionShape(v any) string {
	c, ok := v.(map[string]any)
	if !ok {
		return "is not a mapping"
	}
	for _, k := range sortedKeys(c) {
		switch k {
		case "strategy":
			if s, _ := c[k].(string); s != "None" && s != "Webhook" {
				return fmt.Sprintf("strategy %q", c[k])
			}
		case "webhook":
			w, ok := c[k].(map[string]any)
			if !ok {
				return "webhook is not a mapping"
			}
			for _, wk := range sortedKeys(w) {
				switch wk {
				case "clientConfig":
					if why := clientConfigShape(w[wk]); why != "" {
						return "webhook.clientConfig " + why
					}
				case "conversionReviewVersions":
					if why := stringList(w[wk]); why != "" {
						return "webhook.conversionReviewVersions " + why
					}
				default:
					return fmt.Sprintf("webhook key %q", wk)
				}
			}
		case "webhookClientConfig":
			if why := clientConfigShape(c[k]); why != "" {
				return "webhookClientConfig " + why
			}
		case "conversionReviewVersions":
			if why := stringList(c[k]); why != "" {
				return "conversionReviewVersions " + why
			}
		default:
			return fmt.Sprintf("key %q", k)
		}
	}
	return ""
}

func clientConfigShape(v any) string {
	cc, ok := v.(map[string]any)
	if !ok {
		return "is not a mapping"
	}
	for _, k := range sortedKeys(cc) {
		switch k {
		case "url", "caBundle":
			if _, ok := cc[k].(string); !ok {
				return k + " is not a string"
			}
		case "service":
			svc, ok := cc[k].(map[string]any)
			if !ok {
				return "service is not a mapping"
			}
			for _, sk := range sortedKeys(svc) {
				switch sk {
				case "namespace", "name", "path":
					if _, ok := svc[sk].(string); !ok {
						return "service." + sk + " is not a string"
					}
				case "port":
					if _, ok := svc[sk].(json.Number); !ok {
						return "service.port is not a number"
					}
				default:
					return fmt.Sprintf("service key %q", sk)
				}
			}
		default:
			return fmt.Sprintf("key %q", k)
		}
	}
	return ""
}

func stringMap(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "is not a mapping"
	}
	for _, k := range sortedKeys(m) {
		if _, ok := m[k].(string); !ok {
			return fmt.Sprintf("value of %q is not a string", k)
		}
	}
	return ""
}

func stringList(v any) string {
	l, ok := v.([]any)
	if !ok {
		return "is not a list"
	}
	for _, it := range l {
		if _, ok := it.(string); !ok {
			return "holds a value that is not a string"
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// transformerConfigKeys are the keys a kustomize transformer configuration
// may hold to be read as one.
var transformerConfigKeys = map[string]bool{"nameReference": true, "namespace": true, "varReference": true, "commonLabels": true, "commonAnnotations": true}

// transformerConfig reports why a decoded single document is not a
// transformer configuration whose field specs of the kind only reach
// conversion settings or metadata ("" when it is one). Every key, entry and
// value is checked, so every mapping of the kind in an accepted
// configuration is one of its field specs.
func transformerConfig(v any) string {
	obj, ok := v.(map[string]any)
	if !ok {
		return "not a mapping"
	}
	for _, k := range sortedKeys(obj) {
		if !transformerConfigKeys[k] {
			return fmt.Sprintf("key %q", k)
		}
		list, ok := obj[k].([]any)
		if !ok {
			return fmt.Sprintf("%s is not a list", k)
		}
		for _, it := range list {
			if why := configEntry(it); why != "" {
				return k + ": " + why
			}
		}
	}
	return ""
}

// configEntry checks one entry of a transformer configuration list: a field
// spec, or (nameReference) a referenced kind with its field specs.
func configEntry(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "an entry is not a mapping"
	}
	if raw, present := m["fieldSpecs"]; present {
		list, ok := raw.([]any)
		if !ok {
			return "fieldSpecs is not a list"
		}
		for _, it := range list {
			if why := fieldSpec(it); why != "" {
				return why
			}
		}
		// The referenced kind (a Service) is named beside its field
		// specs; it must not be the definition kind itself.
		for _, k := range sortedKeys(m) {
			switch k {
			case "fieldSpecs":
			case "kind", "group", "version":
				if s, ok := m[k].(string); !ok || s == crdKind {
					return fmt.Sprintf("a referenced %s that is not a plain value", k)
				}
			default:
				return fmt.Sprintf("key %q", k)
			}
		}
		return ""
	}
	return fieldSpec(m)
}

// fieldSpec checks one field spec. A spec of the CustomResourceDefinition
// kind must name the apiextensions.k8s.io group, and it and a spec without a
// kind (which applies to every kind) a path under spec/conversion or
// metadata labels and annotations.
func fieldSpec(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "a field spec is not a mapping"
	}
	for _, k := range sortedKeys(m) {
		switch k {
		case "kind", "group", "version", "path":
			if _, ok := m[k].(string); !ok {
				return fmt.Sprintf("field spec %s is not a string", k)
			}
		case "create":
			if _, ok := m[k].(bool); !ok {
				return "field spec create is not a boolean"
			}
		default:
			return fmt.Sprintf("field spec key %q", k)
		}
	}
	for _, k := range []string{"kind", "group", "version"} {
		if v, present := m[k]; present && v == "" {
			// kustomize reads an empty field as a wildcard.
			return fmt.Sprintf("a field spec with an empty %s", k)
		}
	}
	kind, hasKind := m["kind"].(string)
	switch {
	case hasKind && kind != crdKind:
		// Another kind: the transformer never touches a definition.
		return ""
	case hasKind:
		if g, _ := m["group"].(string); g != crdGroup {
			return fmt.Sprintf("a field spec of the kind without the %s group", crdGroup)
		}
		if ver, present := m["version"]; present && ver != "v1" && ver != "v1beta1" {
			return fmt.Sprintf("a field spec of the kind with version %q", ver)
		}
	}
	// A field spec of the kind, or of every kind (no kind given).
	if p, _ := m["path"].(string); !configPathRE.MatchString(p) || strings.Contains(p, "..") {
		return fmt.Sprintf("a field spec that reaches definitions with path %q, outside conversion settings and metadata labels and annotations", m["path"])
	}
	return ""
}

// parseLegacy reads the bytes as manifests that may hold
// apiextensions.k8s.io/v1beta1 definitions. It returns nil when no document
// is one (the v1 reader's verdict stands), and a problem when any definition
// is not complete.
func parseLegacy(data []byte) ([]CRD, error) {
	if len(data) > MaxFileBytes || strings.Contains(string(data), templateMarker) {
		return nil, nil
	}
	nodes, values, err := decodeStrict(data)
	if err != nil {
		return nil, nil
	}
	legacy := false
	for _, v := range values {
		if obj, ok := v.(map[string]any); ok {
			if av, _ := obj["apiVersion"].(string); av == crdAPIVersionV1beta1 {
				legacy = true
			}
		}
	}
	if !legacy {
		return nil, nil
	}
	lines := splitLines(data)
	var crds []CRD
	for i, v := range values {
		doc := i + 1
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, problemf("%s document %d is not a mapping", fileWord, doc)
		}
		apiVersion, _ := obj["apiVersion"].(string)
		kind, _ := obj["kind"].(string)
		if kind == "List" || strings.HasSuffix(kind, "List") {
			return nil, problemf("%s document %d is a %s: list items are not read", fileWord, doc, kind)
		}
		if !strings.HasPrefix(apiVersion, crdAPIGroupPrefix) && kind != crdKind {
			continue
		}
		if kind != crdKind {
			return nil, problemf("%s document %d has apiVersion %s and kind %q", fileWord, doc, apiVersion, kind)
		}
		var c CRD
		switch apiVersion {
		case crdAPIVersion:
			next := 0
			if i+1 < len(nodes) {
				next = nodes[i+1].Line
			}
			c, err = parseCRD(fileWord, doc, obj, nodes[i], next, lines)
		case crdAPIVersionV1beta1:
			c, err = parseCRDV1beta1(doc, obj, nodes[i])
		default:
			return nil, problemf("%s document %d is a CustomResourceDefinition of apiVersion %q", fileWord, doc, apiVersion)
		}
		if err != nil {
			return nil, err
		}
		c.Path = ""
		crds = append(crds, c)
	}
	if len(crds) == 0 {
		return nil, problemf("%s holds no complete CustomResourceDefinition", fileWord)
	}
	return crds, nil
}

// parseCRDV1beta1 reads one apiextensions.k8s.io/v1beta1 definition: the
// same names, group and scope as v1, and its versions from spec.versions
// (each with served and storage flags, the first one equal to spec.version
// when both are given) or, without a list, from spec.version alone (served
// and stored).
func parseCRDV1beta1(doc int, obj map[string]any, root *yaml.Node) (CRD, error) {
	where := fmt.Sprintf("%s document %d", fileWord, doc)
	meta, spec := mapping(obj, "metadata"), mapping(obj, "spec")
	if meta == nil || spec == nil {
		return CRD{}, problemf("%s: a CustomResourceDefinition without metadata or spec", where)
	}
	names := mapping(spec, "names")
	c := CRD{Name: str(meta, "name"), Group: str(spec, "group"), Kind: str(names, "kind"), Plural: str(names, "plural"), Scope: str(spec, "scope"), Document: doc, StartLine: root.Line}
	switch {
	case len(c.Group) > maxNameBytes || !groupRE.MatchString(c.Group):
		return CRD{}, problemf("%s: spec.group %q is not a valid API group", where, c.Group)
	case !pluralRE.MatchString(c.Plural):
		return CRD{}, problemf("%s: spec.names.plural %q is not valid", where, c.Plural)
	case !kindRE.MatchString(c.Kind):
		return CRD{}, problemf("%s: spec.names.kind %q is not valid", where, c.Kind)
	case c.Name != c.Plural+"."+c.Group:
		return CRD{}, problemf("%s: metadata.name %q is not <plural>.<group>", where, c.Name)
	case c.Scope != "Namespaced" && c.Scope != "Cluster":
		return CRD{}, problemf("%s: spec.scope %q is not Namespaced or Cluster", where, c.Scope)
	}
	single, hasSingle := spec["version"]
	singleName, _ := single.(string)
	if hasSingle && (!versionRE.MatchString(singleName) || len(singleName) > maxVersionNameByte) {
		return CRD{}, problemf("%s: spec.version of %s is %q, not a valid version name", where, c.Name, single)
	}
	raw, hasList := spec["versions"]
	switch {
	case !hasList && !hasSingle:
		return CRD{}, problemf("%s: CustomResourceDefinition %s has neither spec.version nor spec.versions", where, c.Name)
	case !hasList:
		c.Versions = []CRDVersion{{Name: singleName, Served: true, Storage: true}}
	default:
		items, ok := raw.([]any)
		if !ok || len(items) == 0 {
			return CRD{}, problemf("%s: CustomResourceDefinition %s has no spec.versions list", where, c.Name)
		}
		if len(items) > MaxVersionsPerCRD {
			return CRD{}, problemf("%s: CustomResourceDefinition %s has %d versions, over the bound of %d", where, c.Name, len(items), MaxVersionsPerCRD)
		}
		seen := map[string]bool{}
		for i, item := range items {
			vm, ok := item.(map[string]any)
			if !ok {
				return CRD{}, problemf("%s: spec.versions[%d] of %s is not a mapping", where, i, c.Name)
			}
			served, sok := vm["served"].(bool)
			stored, tok := vm["storage"].(bool)
			v := CRDVersion{Name: str(vm, "name"), Served: served, Storage: stored}
			if !versionRE.MatchString(v.Name) || len(v.Name) > maxVersionNameByte {
				return CRD{}, problemf("%s: spec.versions[%d] of %s has name %q, not a valid version name", where, i, c.Name, v.Name)
			}
			if !sok || !tok {
				return CRD{}, problemf("%s: version %s of %s does not state served and storage as booleans", where, v.Name, c.Name)
			}
			if seen[v.Name] {
				return CRD{}, problemf("%s: version %s of %s is listed twice", where, v.Name, c.Name)
			}
			seen[v.Name] = true
			c.Versions = append(c.Versions, v)
		}
		if hasSingle && singleName != c.Versions[0].Name {
			return CRD{}, problemf("%s: spec.version %s of %s is not the first entry of spec.versions", where, singleName, c.Name)
		}
	}
	storage := 0
	for _, v := range c.Versions {
		if v.Storage {
			storage++
			c.StorageVersion = v.Name
		}
		if !constraintengine.ValidSetMember(member(c.Group, v.Name, c.Kind)) {
			return CRD{}, problemf("%s: %s is not representable as a set member", where, member(c.Group, v.Name, c.Kind))
		}
	}
	if storage != 1 {
		return CRD{}, problemf("%s: CustomResourceDefinition %s has %d storage versions, not exactly one", where, c.Name, storage)
	}
	return c, nil
}

// definitionDirs are the declared definition kustomization directories at
// one tag: the directories (not the repository root) of the kustomization
// files whose local resources or bases name a file of the inventory, or a
// directory that holds one.
func definitionDirs(files []scanFile, infos []*blobInfo, inv *Inventory) map[string]bool {
	out := map[string]bool{}
	if inv == nil || len(inv.Files) == 0 {
		return out
	}
	for i, f := range files {
		k := infos[i].kust
		if k == nil || !isKustomizationName(path.Base(f.path)) {
			continue
		}
		// A kustomization at the repository root is never a declared
		// directory: underDefinitionDir stops below the root.
		dir := path.Dir(f.path)
		for _, rel := range k.local {
			full := path.Join(dir, rel)
			if strings.HasPrefix(rel, "/") || !cleanRepoPath(full) {
				continue
			}
			for _, inf := range inv.Files {
				if inf.Path == full || strings.HasPrefix(inf.Path, full+"/") {
					out[dir] = true
				}
			}
		}
	}
	return out
}

// underDefinitionDir reports a path below a declared definition
// kustomization directory.
func underDefinitionDir(p string, dirs map[string]bool) bool {
	for d := path.Dir(p); d != "." && d != "/"; d = path.Dir(d) {
		if dirs[d] {
			return true
		}
	}
	return false
}

// knownNames reports why the names a fragment patches are not all
// definitions of the inventory ("" when they are).
func knownNames(names []string, inv *Inventory) string {
	byName := map[string]bool{}
	if inv != nil {
		for _, c := range inv.CRDs {
			byName[c.Name] = true
		}
	}
	for _, n := range names {
		if !byName[n] {
			return fmt.Sprintf("it patches %s, which the listed paths do not define", n)
		}
	}
	return ""
}

// fragmentClass classifies a file whose bytes are patch fragments: class
// crd-patch below a declared definition kustomization directory when every
// definition it patches is in the inventory, unread otherwise (unread is
// the v1 reader's reason).
func fragmentClass(p string, fr *fragmentRead, inv *Inventory, dirs map[string]bool, unread string) (string, string) {
	if !underDefinitionDir(p, dirs) {
		return ClassUnread, unread + "; a patch fragment outside a declared definition kustomization directory"
	}
	if why := knownNames(fr.names, inv); why != "" {
		return ClassUnread, unread + "; a patch fragment: " + why
	}
	return ClassCRDPatch, "a patch fragment that only sets conversion, preserveUnknownFields or metadata labels and annotations of " + strings.Join(fr.names, ", ")
}
