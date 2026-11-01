// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"sort"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

// This file observes which custom-resource spec paths and enum tokens a
// caller's rendered manifests set, so that a rule naming a removed field can
// be decided from the manifests. It is a collector and nothing else: it
// registers no fact, wires no scan route and carries no rule.
//
// What is kept is decided by an allowlist of members the caller passes in
// (the public rule members of one project). Only a member of the allowlist, in
// its pattern form (_item_ for an array item, _any_ for a map value), is ever
// retained. The path an instance really uses, any value, the object name and
// namespace, labels, annotations, status, and everything under a Secret are
// never retained, counted, hashed or reported. Name and namespace are read
// for one purpose, to see that the same object is written twice, and stay in
// memory of the call.
//
// The result is a pair of set values per project, members and complete. A
// set is complete only when nothing at all could be missed: any omission,
// whatever its code, makes both sets incomplete, and an incomplete set never
// lets an absent member count as absent (the engine returns UNKNOWN, while a
// listed member that was found still BLOCKS).

// CRInstanceOmissionCode names why a project's sets are incomplete. A code is
// a fixed word with a count; it never carries a key, path, value or name.
type CRInstanceOmissionCode string

// Omission codes of the custom-resource instance collector.
const (
	// CRScopeNotComplete: the caller did not declare the manifests to be the
	// complete set that is applied.
	CRScopeNotComplete CRInstanceOmissionCode = "CR_INSTANCE_SCOPE_NOT_DECLARED_COMPLETE"
	// CRListPaginated: a list in the input is paginated.
	CRListPaginated CRInstanceOmissionCode = "CR_INSTANCE_LIST_PAGINATED"
	// CRWrapperKind: a document of a wrapper kind (see CRInstanceWrapperKinds)
	// is present. It can carry custom resources inside its own fields, which
	// the collector does not read, so no project's absence is claimed.
	CRWrapperKind CRInstanceOmissionCode = "CR_INSTANCE_WRAPPER_KIND_PRESENT"
	// CRDocumentUnparsed: a document or file holds template syntax or does not
	// parse as a bounded document.
	CRDocumentUnparsed CRInstanceOmissionCode = "CR_INSTANCE_DOCUMENT_UNPARSED"
	// CRDocumentNotPlaced: a document could not be placed as one Kubernetes
	// object (not Kubernetes shaped, a nested or invalid list, an object with
	// a top-level items array, a skipped file or directory, no document).
	CRDocumentNotPlaced CRInstanceOmissionCode = "CR_INSTANCE_DOCUMENT_NOT_PLACED"
	// CRNotRendered: a kustomization or Helm chart file is present; it is not
	// rendered, so the objects it produces are not seen.
	CRNotRendered CRInstanceOmissionCode = "CR_INSTANCE_KUSTOMIZE_OR_CHART_NOT_RENDERED"
	// CRKindNotAttributed: an object of a custom-resource group and kind that
	// the reviewed table does not attribute to exactly one project.
	CRKindNotAttributed CRInstanceOmissionCode = "CR_INSTANCE_KIND_NOT_ATTRIBUTED"
	// CRDuplicateIdentity: the same kind, namespace and name is written more
	// than once. The members of every copy are kept, so a member that only an
	// overridden copy sets still counts (it can over-block). apiVersion is not
	// consulted either: a copy under another apiVersion is the same object.
	CRDuplicateIdentity CRInstanceOmissionCode = "CR_INSTANCE_DUPLICATE_IDENTITY"
	// CRKeyNotEncodable: a key beside an allowlisted path cannot be written as
	// a member segment (a slash, a character outside the member charset, the
	// reserved _item_ or _any_, or a member that would be too long), so a
	// field the allowlist could not name may be set there.
	CRKeyNotEncodable CRInstanceOmissionCode = "CR_INSTANCE_KEY_NOT_ENCODABLE"
	// CRShapeMismatch: the value under an allowlisted path has another shape
	// than the path expects (_item_ on a map, _any_ on an array, a property
	// of a scalar, a scalar expected for an enum). It is never read as absent.
	CRShapeMismatch CRInstanceOmissionCode = "CR_INSTANCE_SHAPE_MISMATCH"
	// CRInstanceCapExceeded: a project has more than CRInstanceCap objects.
	CRInstanceCapExceeded CRInstanceOmissionCode = "CR_INSTANCE_CAP_EXCEEDED"
	// CRMemberOverflow: more members were found than a set value may hold.
	// None is dropped; the caller must not declare an oversized set.
	CRMemberOverflow CRInstanceOmissionCode = "CR_INSTANCE_MEMBER_OVERFLOW"
	// CRAllowlistRejected: an allowlist member is not a valid member of the
	// project (not decodable, not under spec, not a kind of the project).
	CRAllowlistRejected CRInstanceOmissionCode = "CR_INSTANCE_ALLOWLIST_MEMBER_REJECTED"
)

const (
	// CRInstanceCap is the number of objects of one project that is read
	// before the project's sets are declared incomplete. Reading does not stop.
	CRInstanceCap = 1000
	// crAllowlistLimit bounds the allowlist of one project.
	crAllowlistLimit = 4096
)

// CRInstanceAllow is the allowlist of one project: pattern-form members of the
// project's crd_fields_set and crd_enum_values_set, as the public rules name
// them. A field member is group/Kind/spec/..., an enum member is
// group/Kind/spec/.../value.
type CRInstanceAllow struct {
	Fields     []string
	EnumValues []string
}

// CRInstanceAllowlist maps a project slug of the reviewed custom-resource
// table to its allowlist. It is the only thing that is looked for.
type CRInstanceAllowlist map[string]CRInstanceAllow

// CRInstanceSet is a set value. Members is ascending and holds only allowlist
// members; it is never truncated.
type CRInstanceSet struct {
	Members  []string
	Complete bool
}

// CRInstanceOmission is an omission code with the number of times it occurred.
type CRInstanceOmission struct {
	Code  CRInstanceOmissionCode
	Count int
}

// CRInstanceFacts is the collector's result for one project.
type CRInstanceFacts struct {
	Fields     CRInstanceSet
	EnumValues CRInstanceSet
	// Omissions are in code order. Complete is false for both sets exactly
	// when this list is not empty.
	Omissions []CRInstanceOmission
	// NonMemberEnumValues counts the enum paths that were set to a value no
	// allowlist member names. The value is not kept.
	NonMemberEnumValues int
}

// CRInstanceOmissionText is the fixed explanation of a code. It is
// verdict-neutral and never names a key, path, value or object.
func CRInstanceOmissionText(code CRInstanceOmissionCode) string {
	switch code {
	case CRScopeNotComplete:
		return "the manifests were not declared to be the complete set that is applied"
	case CRListPaginated:
		return "a list in the input is paginated, so objects may be missing"
	case CRWrapperKind:
		return "a document of a kind that can carry custom resources in its own fields is present; those fields are not read, so absence is not claimed"
	case CRDocumentUnparsed:
		return "a document holds template syntax or could not be parsed; it was not read"
	case CRDocumentNotPlaced:
		return "a document or file could not be placed as one Kubernetes object; it was not read"
	case CRNotRendered:
		return "a kustomization or Helm chart file is present and was not rendered; the objects it produces were not read"
	case CRKindNotAttributed:
		return "an object of a custom-resource kind that the reviewed table does not attribute to exactly one project is present"
	case CRDuplicateIdentity:
		return "the same object is written more than once; the members of every copy are kept, so a field set only by an overridden copy still counts (can over-block), and apiVersion is not consulted"
	case CRKeyNotEncodable:
		return "a key beside an allowlisted path cannot be written as a member, so a field that cannot be named may be set"
	case CRShapeMismatch:
		return "a value under an allowlisted path has a different shape than the path expects; it is not read as absent"
	case CRInstanceCapExceeded:
		return "a project has more objects than the instance limit"
	case CRMemberOverflow:
		return "more members were found than one set may hold"
	case CRAllowlistRejected:
		return "an allowlist member is not valid for the project and was not looked for"
	}
	return ""
}

// CRInstanceWrapper names a kind that can hold custom resources inside its
// own fields (inline values, patches, templates, embedded manifests).
type CRInstanceWrapper struct {
	Group string
	Kind  string
}

// crInstanceWrappers is the reviewed wrapper list. A document of one of these
// kinds, whatever its version, makes every project's sets incomplete: the
// custom resources it carries are applied by another controller and are not
// visible as documents. A kind is added here when its spec can carry or
// generate an object of another group.
var crInstanceWrappers = []CRInstanceWrapper{
	{"helm.toolkit.fluxcd.io", "HelmRelease"},
	{"kustomize.toolkit.fluxcd.io", "Kustomization"},
	{"kustomize.config.k8s.io", "Kustomization"},
	{"argoproj.io", "Application"},
	{"argoproj.io", "ApplicationSet"},
	{"apiextensions.crossplane.io", "Composition"},
	{"kubernetes.crossplane.io", "Object"},
	{"work.open-cluster-management.io", "ManifestWork"},
	{"fleet.cattle.io", "Bundle"},
	{"helm.cattle.io", "HelmChart"},
	{"helm.cattle.io", "HelmChartConfig"},
}

// CRInstanceWrapperKinds returns the reviewed wrapper list.
func CRInstanceWrapperKinds() []CRInstanceWrapper {
	return append([]CRInstanceWrapper(nil), crInstanceWrappers...)
}

func crInstanceWrapper(group, kind string) bool {
	for _, w := range crInstanceWrappers {
		if w.Group == group && w.Kind == kind {
			return true
		}
	}
	return false
}

// CollectCRInstanceFields observes, for every project of the allowlist, which
// allowlist members the workspace's custom-resource objects set. scopeComplete
// is the caller's statement that the workspace is the complete set that is
// applied. The result is deterministic: it does not depend on document order.
func CollectCRInstanceFields(workspace intake.Workspace, allow CRInstanceAllowlist, scopeComplete bool) (map[string]CRInstanceFacts, error) {
	return collectCRInstanceFields(customresources.DefaultIndex(), workspace, allow, scopeComplete)
}

// CollectCRInstanceFieldsBytes is CollectCRInstanceFields over one
// caller-supplied file of rendered manifests. Bytes the shared decoder
// refuses (anchors, aliases, merge keys, custom tags, duplicate keys, limits)
// are an error, never an empty or partial result.
func CollectCRInstanceFieldsBytes(raw []byte, allow CRInstanceAllowlist, scopeComplete bool) (map[string]CRInstanceFacts, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		// A byte order mark is refused: the shared decoder skips it, but the
		// collector reads only bytes it can account for.
		return nil, ErrInvalid
	}
	workspace, err := intake.Decode("input", raw)
	if err != nil {
		return nil, ErrInvalid
	}
	return CollectCRInstanceFields(workspace, allow, scopeComplete)
}

// crSeen is the set of allowlist members found, by member.
type crSeen map[string]bool

// crMember is one decoded allowlist member.
type crMember struct {
	text  string
	segs  []membercode.Seg
	value string // enum value; meaningful when enum
	enum  bool
}

type crKindKey struct{ group, kind string }

// crDoc is one object attributed to a project.
type crDoc struct {
	key   crKindKey
	value map[string]any
}

func collectCRInstanceFields(index customresources.Index, workspace intake.Workspace, allow CRInstanceAllowlist, scopeComplete bool) (map[string]CRInstanceFacts, error) {
	for _, a := range allow {
		if len(a.Fields) > crAllowlistLimit || len(a.EnumValues) > crAllowlistLimit {
			return nil, ErrInvalid
		}
	}
	set := kubernetesApplySetOf(workspace)
	documents := set.documents
	if set.reason != "" {
		documents = set.readable
	}

	// Omissions that hold for every project.
	global := map[CRInstanceOmissionCode]int{}
	if !scopeComplete {
		global[CRScopeNotComplete]++
	}
	if set.paginated || set.readablePaginated {
		global[CRListPaginated]++
	}
	for _, omission := range workspace.Omissions {
		if omission.Reason == intake.ReasonTemplated || omission.Reason == intake.ReasonUnparseable {
			global[CRDocumentUnparsed]++
		} else {
			global[CRDocumentNotPlaced]++
		}
	}
	if set.reason != "" && global[CRDocumentUnparsed] == 0 && global[CRDocumentNotPlaced] == 0 {
		// Unresolved for a reason that is not an omission (no document, a
		// document that is not an object, an object with an items array).
		global[CRDocumentNotPlaced]++
	}
	if n := len(workspace.Auxiliary); n > 0 {
		global[CRNotRendered] += n
	}

	perProject := map[string][]crDoc{}
	for _, document := range documents {
		api, kind, _ := kubernetesGVK(document.value)
		group := customresources.GroupOf(api)
		if kind == "Secret" {
			// A Secret is refused at parse; it is not read here either.
			continue
		}
		if crInstanceWrapper(group, kind) {
			global[CRWrapperKind]++
		}
		if customresources.KubernetesGroup(group) {
			continue
		}
		owner, attribution := index.OwnerOf(group, kind)
		if attribution != customresources.Owned {
			global[CRKindNotAttributed]++
			continue
		}
		perProject[owner] = append(perProject[owner], crDoc{key: crKindKey{group, kind}, value: document.value})
	}

	projects := make([]string, 0, len(allow))
	for project := range allow {
		projects = append(projects, project)
	}
	sort.Strings(projects)
	out := make(map[string]CRInstanceFacts, len(projects))
	for _, project := range projects {
		out[project] = collectProject(index, project, allow[project], perProject[project], global)
	}
	return out, nil
}

// compileCRMembers decodes an allowlist. A member that is not valid for the
// project is counted as rejected and not looked for.
func compileCRMembers(index customresources.Index, project string, allow CRInstanceAllow) (map[crKindKey][]crMember, int) {
	rejected := 0
	byKind := map[crKindKey][]crMember{}
	seen := map[string]bool{}
	add := func(text string, group, kind string, path []membercode.Seg, value string, enum bool) {
		if seen[text] {
			return
		}
		seen[text] = true
		owner, attribution := index.OwnerOf(group, kind)
		first := len(path) > 0 && path[0].Kind == membercode.Prop && path[0].Name == "spec"
		if attribution != customresources.Owned || owner != project || kind == "Secret" || customresources.KubernetesGroup(group) || !first {
			rejected++
			return
		}
		k := crKindKey{group, kind}
		byKind[k] = append(byKind[k], crMember{text: text, segs: path, value: value, enum: enum})
	}
	for _, m := range allow.Fields {
		group, kind, path, ok := membercode.DecodeField(m)
		if !ok {
			rejected++
			continue
		}
		add(m, group, kind, path, "", false)
	}
	for _, m := range allow.EnumValues {
		group, kind, path, value, ok := membercode.DecodeEnum(m)
		if !ok {
			rejected++
			continue
		}
		add(m, group, kind, path, value, true)
	}
	return byKind, rejected
}

func collectProject(index customresources.Index, project string, allow CRInstanceAllow, docs []crDoc, global map[CRInstanceOmissionCode]int) CRInstanceFacts {
	omissions := map[CRInstanceOmissionCode]int{}
	for code, n := range global {
		omissions[code] = n
	}
	byKind, rejected := compileCRMembers(index, project, allow)
	if rejected > 0 {
		omissions[CRAllowlistRejected] = rejected
	}
	if len(docs) > CRInstanceCap {
		omissions[CRInstanceCapExceeded] = len(docs) - CRInstanceCap
	}
	if n := duplicateIdentities(docs); n > 0 {
		omissions[CRDuplicateIdentity] = n
	}

	fields, enums := crSeen{}, crSeen{}
	w := crWalker{}
	for _, doc := range docs {
		for _, m := range byKind[doc.key] {
			w.group, w.kind = doc.key.group, doc.key.kind
			if m.enum {
				w.walkEnum(doc.value, m, enums)
			} else {
				w.walkField(doc.value, m, fields)
			}
		}
	}
	if w.unencodable > 0 {
		omissions[CRKeyNotEncodable] = w.unencodable
	}
	if w.mismatch > 0 {
		omissions[CRShapeMismatch] = w.mismatch
	}
	if over := max(len(fields)-constraintengine.MaxSetMembers, 0) + max(len(enums)-constraintengine.MaxSetMembers, 0); over > 0 {
		omissions[CRMemberOverflow] = over
	}

	facts := CRInstanceFacts{NonMemberEnumValues: w.nonMember}
	for code, n := range omissions {
		if n > 0 {
			facts.Omissions = append(facts.Omissions, CRInstanceOmission{Code: code, Count: n})
		}
	}
	sort.Slice(facts.Omissions, func(i, j int) bool { return facts.Omissions[i].Code < facts.Omissions[j].Code })
	complete := len(facts.Omissions) == 0
	facts.Fields = CRInstanceSet{Members: sortedMembers(fields), Complete: complete}
	facts.EnumValues = CRInstanceSet{Members: sortedMembers(enums), Complete: complete}
	return facts
}

func sortedMembers(seen crSeen) []string {
	out := make([]string, 0, len(seen))
	for member := range seen {
		out = append(out, member)
	}
	sort.Strings(out)
	return out
}

// duplicateIdentities counts the objects written again: the same group, kind,
// namespace and name. The identity is compared in memory by sorting; it is
// never stored in the result and never hashed. An object without a name
// (generateName) has no identity to compare.
func duplicateIdentities(docs []crDoc) int {
	identities := make([][4]string, 0, len(docs))
	for _, doc := range docs {
		metadata, _ := doc.value["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if name == "" {
			continue
		}
		namespace, _ := metadata["namespace"].(string)
		identities = append(identities, [4]string{doc.key.group, doc.key.kind, namespace, name})
	}
	sort.Slice(identities, func(i, j int) bool {
		for k := range identities[i] {
			if identities[i][k] != identities[j][k] {
				return identities[i][k] < identities[j][k]
			}
		}
		return false
	})
	duplicates := 0
	for i := 1; i < len(identities); i++ {
		if identities[i] == identities[i-1] {
			duplicates++
		}
	}
	return duplicates
}

// crWalker follows an allowlist member's segments through one object. It only
// ever looks up keys the member names, so nothing outside the member is read.
type crWalker struct {
	group, kind string
	unencodable int
	mismatch    int
	nonMember   int
}

// walkField records the member when its path exists. A key that is present
// with null, and a container that is present and empty, count as present.
func (w *crWalker) walkField(root map[string]any, m crMember, seen crSeen) {
	w.walk(root, m.segs, 0, func(any) { seen[m.text] = true }, func() { seen[m.text] = true })
}

// walkEnum records the member when the scalar at its path, as text, equals
// the member's value.
func (w *crWalker) walkEnum(root map[string]any, m crMember, seen crSeen) {
	w.walk(root, m.segs, 0, func(leaf any) {
		if leaf == nil {
			return
		}
		text, scalar := scalarText(leaf)
		switch {
		case !scalar:
			w.mismatch++
		case text == m.value:
			seen[m.text] = true
		default:
			w.nonMember++
		}
	}, func() {})
}

func scalarText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case json.Number:
		return t.String(), true
	}
	return "", false
}

// walk follows segs[depth:] from node. leaf is called for every node the full
// path reaches, empty for an array or map that is present and holds no
// element where the path ends in _item_ or _any_.
func (w *crWalker) walk(node any, segs []membercode.Seg, depth int, leaf func(any), empty func()) {
	if node == nil {
		// null (or an absent value) holds nothing below it.
		return
	}
	last := depth == len(segs)-1
	switch seg := segs[depth]; seg.Kind {
	case membercode.Prop:
		object, ok := node.(map[string]any)
		if !ok {
			w.mismatch++
			return
		}
		if depth > 0 {
			w.checkKeys(object, segs[:depth])
		}
		child, found := object[seg.Name]
		if !found {
			return
		}
		if last {
			leaf(child)
			return
		}
		w.walk(child, segs, depth+1, leaf, empty)
	case membercode.Item:
		items, ok := node.([]any)
		if !ok {
			w.mismatch++
			return
		}
		if last && len(items) == 0 {
			empty()
			return
		}
		for _, item := range items {
			if last {
				leaf(item)
			} else {
				w.walk(item, segs, depth+1, leaf, empty)
			}
		}
	case membercode.Any:
		object, ok := node.(map[string]any)
		if !ok {
			w.mismatch++
			return
		}
		if last && len(object) == 0 {
			empty()
			return
		}
		for _, child := range object {
			if last {
				leaf(child)
			} else {
				w.walk(child, segs, depth+1, leaf, empty)
			}
		}
	}
}

// checkKeys counts the keys of a map that sits on an allowlisted path and
// that membercode would refuse as the next segment. The keys themselves are
// not kept.
func (w *crWalker) checkKeys(object map[string]any, prefix []membercode.Seg) {
	path := make([]membercode.Seg, len(prefix)+1)
	copy(path, prefix)
	for key := range object {
		path[len(prefix)] = membercode.Seg{Kind: membercode.Prop, Name: key}
		if _, err := membercode.Field(w.group, w.kind, path); err != nil {
			w.unencodable++
		}
	}
}
