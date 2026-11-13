// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Pinned foreign bundles (see ForeignBundle). A project sometimes vendors a
// third-party manifest bundle (an example that installs another project's
// definitions) that a kustomization lists, so the install-surface guard
// voids a plain exclusion of it. A reviewed entry may instead pin the exact
// file by content digest: the claim "this file only defines other groups"
// is then a question about bytes a reviewer read once, which the scan holds
// the file to at every tag.

const (
	// maxForeignList bounds the groups and the digests of one entry.
	maxForeignList = 16
	// maxForeignBytes bounds a pinned file.
	maxForeignBytes = 1 << 20
	sha256Prefix    = "sha256:"
)

var (
	// apiGroupRE is a DNS-subdomain API group with at least one dot (a
	// group without one is a core or built-in group, never a vendored
	// project's).
	apiGroupRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	sha256DigRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// bundle converts the JSON member (nil stays nil).
func (f *foreignJSON) bundle() *ForeignBundle {
	if f == nil {
		return nil
	}
	return &ForeignBundle{Groups: slices.Clone(f.Groups), SHA256: slices.Clone(f.SHA256), IdentityOnly: f.IdentityOnly}
}

// Equal reports whether two declarations are the same (nil equals nil).
func (b *ForeignBundle) Equal(o *ForeignBundle) bool {
	if b == nil || o == nil {
		return b == o
	}
	return b.IdentityOnly == o.IdentityOnly && slices.Equal(b.Groups, o.Groups) && slices.Equal(b.SHA256, o.SHA256)
}

// strictSortedUnique reports a list that is not sorted, duplicate-free and
// within bounds, or has an item that does not match re ("" when it is).
func strictSortedUnique(what string, items []string, re *regexp.Regexp) string {
	if len(items) == 0 || len(items) > maxForeignList {
		return fmt.Sprintf("%s: 1 to %d items are required", what, maxForeignList)
	}
	for i, it := range items {
		if !re.MatchString(it) || len(it) > 253 {
			return fmt.Sprintf("%s: %q is not well formed", what, it)
		}
		if i > 0 && items[i-1] >= it {
			return fmt.Sprintf("%s are not sorted and unique at %q", what, it)
		}
	}
	return ""
}

// validForeign checks the shape of a pinned-bundle entry ("" when it is
// accepted): exactly one file (no directory, no pattern) whose extension is
// lower-case yaml, yml or json, not a kustomization, chart or values file,
// not with copies, prePatch or defines, with a digest list and a group list.
func validForeign(ej exclusionJSON) string {
	base := path.Base(ej.Path)
	switch {
	case ej.Copies || ej.PrePatch != "" || ej.Defines != "":
		return "excludes copies, prePatch and defines"
	case strings.HasSuffix(ej.Path, "/"):
		return "names one file, not a directory"
	case strings.ContainsAny(ej.Path, globMeta+"\\{}"):
		return "names one file exactly: no pattern"
	}
	switch path.Ext(base) {
	case ".yaml", ".yml", ".json":
	default:
		return "names a file that ends in .yaml, .yml or .json (lower case)"
	}
	for _, n := range definesNoneRefused {
		if strings.EqualFold(base, n) {
			return fmt.Sprintf("%s is read by kustomize or Helm: it is never a pinned bundle", n)
		}
	}
	if why := strictSortedUnique("groups", ej.Foreign.Groups, apiGroupRE); why != "" {
		return why
	}
	return strictSortedUnique("sha256", ej.Foreign.SHA256, sha256DigRE)
}

// targetGroups are the API groups of the definitions the target itself
// serves at a release: the inventory's definitions and those of its other
// channels, sorted and unique. Nil when they are not known.
func targetGroups(inv *Inventory) []string {
	if inv == nil || !inv.Complete {
		return nil
	}
	set := map[string]bool{}
	for _, c := range inv.CRDs {
		set[c.Group] = true
	}
	for _, ch := range inv.Channels {
		for _, c := range ch.CRDs {
			set[c.Group] = true
		}
	}
	delete(set, "")
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// foreignBundleProblem checks the bytes of a pinned file at one release
// ("" when every check holds, the reason otherwise). It is a function of the
// bytes, the entry and the groups the target defines. Every check fails
// closed:
//
//   - the SHA-256 of the bytes is one of the entry's digests;
//   - the file is within the size bound, holds no template syntax and
//     decodes strictly (the decoder of a defines-none entry: no duplicate
//     keys, anchors, aliases or merge keys; one value per document);
//   - the release defines at least one group, none of the declared groups is
//     one of them, and no group the target defines appears anywhere in the
//     file (any letter case, in any string, description or annotation);
//   - every document is a mapping with a kind; a CustomResourceDefinition is
//     apiextensions.k8s.io/v1, of one of the declared groups, named
//     <plural>.<group>; any other document is none of an apiextensions
//     object, a Kustomization or Component, a kustomize or Helm file, and
//     holds no mapping that names the kind with a spec nor a manifest in a
//     string.
func foreignBundleProblem(b *ForeignBundle, data []byte, groups []string) string {
	if b == nil || len(b.Groups) == 0 || len(b.SHA256) == 0 {
		return "the entry declares no pin"
	}
	if len(data) > maxForeignBytes {
		return fmt.Sprintf("the file is over the %d-byte bound", maxForeignBytes)
	}
	sum := sha256.Sum256(data)
	if !slices.Contains(b.SHA256, sha256Prefix+hex.EncodeToString(sum[:])) {
		return "the file's digest is not one of the pinned digests"
	}
	if bytes.Contains(data, []byte(templateMarker)) {
		return "the file holds template syntax"
	}
	if len(groups) == 0 {
		return "the groups the target defines at this release are not known"
	}
	lower := bytes.ToLower(data)
	for _, g := range groups {
		if slices.Contains(b.Groups, g) {
			return fmt.Sprintf("the declared foreign group %s is a group the target defines", g)
		}
		if bytes.Contains(lower, []byte(strings.ToLower(g))) {
			return fmt.Sprintf("the file names the target's group %s", g)
		}
	}
	if b.IdentityOnly {
		return foreignIdentityProblem(b, data, groups)
	}
	_, values, err := decodeStrict(data)
	if err != nil {
		return "the file is not decodable within the strict YAML subset"
	}
	if len(values) == 0 {
		return "the file holds no document"
	}
	for i, v := range values {
		obj, ok := v.(map[string]any)
		if !ok {
			return fmt.Sprintf("document %d is not a mapping", i+1)
		}
		kind, _ := obj["kind"].(string)
		apiVersion, _ := obj["apiVersion"].(string)
		if kind == "" {
			return fmt.Sprintf("document %d has no kind", i+1)
		}
		if kind == crdKind {
			if why := foreignDefinitionProblem(b, obj, apiVersion); why != "" {
				return fmt.Sprintf("document %d: %s", i+1, why)
			}
			continue
		}
		_, deps := obj["dependencies"]
		switch {
		case strings.HasPrefix(apiVersion, crdAPIGroupPrefix):
			return fmt.Sprintf("document %d is an %s object that is not a definition", i+1, strings.TrimSuffix(crdAPIGroupPrefix, "/"))
		case strings.HasPrefix(apiVersion, "kustomize.config.k8s.io/"), kind == "Kustomization", kind == "Component", !emptyKustomization(readKustomization(obj)):
			return fmt.Sprintf("document %d reads as a kustomization", i+1)
		case deps:
			return fmt.Sprintf("document %d names dependencies", i+1)
		}
		if why := definitionInside(v); why != "" {
			return fmt.Sprintf("document %d: %s", i+1, why)
		}
	}
	return ""
}

// foreignDefinitionProblem checks one CustomResourceDefinition document.
func foreignDefinitionProblem(b *ForeignBundle, obj map[string]any, apiVersion string) string {
	if apiVersion != crdAPIGroupPrefix+"v1" {
		return "a definition that is not apiextensions.k8s.io/v1"
	}
	spec, _ := obj["spec"].(map[string]any)
	group, _ := spec["group"].(string)
	if !slices.Contains(b.Groups, group) {
		return fmt.Sprintf("a definition of the group %q, which is not declared", group)
	}
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	if !strings.HasSuffix(name, "."+group) {
		return fmt.Sprintf("a definition named %q outside its group %s", name, group)
	}
	return ""
}

// plainKustomization reports bytes that are one kustomization of the exact
// shape apiVersion kustomize.config.k8s.io/v1beta1, kind Kustomization and
// a resources list of local strings, and nothing else: no patches,
// replacements, generators, transformers, components, name or namespace
// changes. Such a file only lists files; it cannot rewrite what they hold.
func plainKustomization(data []byte) bool {
	if len(data) > maxForeignBytes || bytes.Contains(data, []byte(templateMarker)) {
		return false
	}
	_, values, err := decodeStrict(data)
	if err != nil || len(values) != 1 {
		return false
	}
	obj, ok := values[0].(map[string]any)
	if !ok {
		return false
	}
	for k := range obj {
		if k != "apiVersion" && k != "kind" && k != "resources" {
			return false
		}
	}
	if obj["apiVersion"] != "kustomize.config.k8s.io/v1beta1" || obj["kind"] != "Kustomization" {
		return false
	}
	items, ok := obj["resources"].([]any)
	if !ok || len(items) == 0 {
		return false
	}
	for _, it := range items {
		s, ok := it.(string)
		if !ok || s == "" || remoteSource(s) || strings.HasPrefix(s, "/") {
			return false
		}
	}
	return true
}
