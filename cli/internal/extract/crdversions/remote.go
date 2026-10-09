// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// RemoteRecord is the proof of where a release's definitions were read when
// it installs from another repository (Remote): the release's Kustomization
// and the tag it names, the commit the table pins for that tag, and the
// kustomization of the remote directory that lists the definition files.
type RemoteRecord struct {
	Kustomization       FileDigest `json:"kustomization"`
	Ref                 string     `json:"ref"`
	Repo                string     `json:"repo"`
	Commit              string     `json:"commit"`
	Directory           string     `json:"directory"`
	DirectoryManifest   FileDigest `json:"directoryKustomization"`
	Resources           []string   `json:"resources"`
	UnlistedYAMLIgnored int        `json:"unlistedYamlIgnored"`
}

// FileDigest names a file and the digest of its bytes.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func digestOf(path string, data []byte) FileDigest {
	sum := sha256.Sum256(data)
	return FileDigest{Path: path, SHA256: "sha256:" + hex.EncodeToString(sum[:])}
}

const kustomizationAPIVersion = "kustomize.config.k8s.io/v1beta1"

var (
	refQueryRE     = regexp.MustCompile(`^ref=(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?)$`)
	resourceFileRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$`)
)

// kustomizationResources reads a kustomization file and returns its
// resources. The file must be one strictly decodable document of exactly
// the keys apiVersion, kind and resources, with the kustomize v1beta1
// apiVersion and kind Kustomization, and resources a non-empty list of
// plain strings. A kustomization that does anything else (patches, a name
// prefix, images, generators, replacements, components) changes what is
// installed in ways this reading does not model, so it is refused.
func kustomizationResources(file string, data []byte) ([]string, error) {
	_, values, err := decodeStrict(data)
	if err != nil || len(values) != 1 || strings.Contains(string(data), templateMarker) {
		return nil, problemf("%s is not one strictly decodable document without template syntax", file)
	}
	doc, ok := values[0].(map[string]any)
	if !ok {
		return nil, problemf("%s is not a mapping", file)
	}
	for key := range doc {
		switch key {
		case "apiVersion", "kind", "resources":
		default:
			return nil, problemf("%s has the key %q: only apiVersion, kind and resources are modelled", file, key)
		}
	}
	if doc["apiVersion"] != kustomizationAPIVersion || doc["kind"] != "Kustomization" {
		return nil, problemf("%s is not a %s Kustomization", file, kustomizationAPIVersion)
	}
	items, ok := doc["resources"].([]any)
	if !ok || len(items) == 0 || len(items) > MaxCRDsPerTag {
		return nil, problemf("%s has no resources list of a supported size", file)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok || s == "" {
			return nil, problemf("%s has a resource that is not a string", file)
		}
		out = append(out, s)
	}
	return out, nil
}

// remoteRef reads the one remote resource of a release's Kustomization and
// returns the tag it names. The resource must be exactly
// https://github.com/<repo>/<directory>?ref=<tag> of the declared Remote.
func remoteRef(t *Remote, file string, data []byte) (string, error) {
	resources, err := kustomizationResources(file, data)
	if err != nil {
		return "", err
	}
	if len(resources) != 1 {
		return "", problemf("%s lists %d resources: exactly one remote resource is modelled", file, len(resources))
	}
	u, err := url.Parse(resources[0])
	want := strings.TrimPrefix(t.Repo, "github.com/") + "/" + t.Directory
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.Fragment != "" || u.Opaque != "" || !strings.EqualFold(strings.TrimPrefix(u.Path, "/"), want) {
		return "", problemf("%s names the resource %q, not https://github.com/%s?ref=<tag>", file, resources[0], want)
	}
	m := refQueryRE.FindStringSubmatch(u.RawQuery)
	if m == nil {
		return "", problemf("%s names the resource %q without exactly one ref=<release tag>", file, resources[0])
	}
	return m[1], nil
}

// readRemoteInventory reads the definitions of a release that installs from
// another repository: the tag the release's Kustomization names, resolved
// through the table's pins, and the files the remote directory's own
// kustomization lists, at the pinned commit.
func readRemoteInventory(r extract.PinnedReader, repo extract.RepoRef, t Target, commit string) (*Inventory, error) {
	inv := &Inventory{Commit: commit, Paths: []PathRecord{}, Files: []FileRecord{}, CRDs: []CRD{}}
	rm := t.Remote
	data, err := r.Read(repo, commit, rm.Kustomization)
	if isNotFound(err) {
		return inv, problemf("the release's kustomization %s does not exist", rm.Kustomization)
	}
	if err != nil {
		return inv, err
	}
	ref, err := remoteRef(rm, rm.Kustomization, data)
	if err != nil {
		return inv, err
	}
	pinned, ok := rm.pinFor(ref)
	if !ok {
		return inv, problemf("%s names the tag %s of %s, which targets.json does not pin to a commit", rm.Kustomization, ref, rm.Repo)
	}
	remote, err := extract.ParseRepo(rm.Repo)
	if err != nil {
		return inv, err
	}
	dirFile := path.Join(rm.Directory, "kustomization.yaml")
	dirData, err := r.Read(remote, pinned, dirFile)
	if isNotFound(err) {
		return inv, problemf("%s does not exist in %s at %s (tag %s)", dirFile, rm.Repo, pinned, ref)
	}
	if err != nil {
		return inv, err
	}
	resources, err := kustomizationResources(rm.Repo+"/"+dirFile, dirData)
	if err != nil {
		return inv, err
	}
	seen := map[string]bool{}
	files := make([]string, 0, len(resources))
	for _, name := range resources {
		if !resourceFileRE.MatchString(name) || name == "kustomization.yaml" || seen[name] {
			return inv, problemf("%s lists the resource %q: only distinct plain file names of the directory are modelled", dirFile, name)
		}
		seen[name] = true
		files = append(files, path.Join(rm.Directory, name))
	}
	listed, err := r.List(remote, pinned, rm.Directory)
	if err != nil {
		if isNotFound(err) {
			return inv, problemf("directory %s does not exist in %s at %s (tag %s)", rm.Directory, rm.Repo, pinned, ref)
		}
		return inv, err
	}
	ignored := 0
	for _, e := range listed {
		name := e.Path[strings.LastIndex(e.Path, "/")+1:]
		if e.Type == "blob" && resourceFileRE.MatchString(name) && name != "kustomization.yaml" && !seen[name] {
			ignored++
		}
	}
	for _, f := range files {
		for _, e := range listed {
			if e.Path == f && e.Mode == "120000" {
				return inv, problemf("%s is a symbolic link", f)
			}
		}
	}
	inv.Paths = append(inv.Paths, PathRecord{Path: rm.Repo + "/" + rm.Directory, Kind: "directory", Files: len(files), Ignored: ignored})
	inv.Remote = &RemoteRecord{
		Kustomization: digestOf(rm.Kustomization, data), Ref: ref, Repo: rm.Repo, Commit: pinned, Directory: rm.Directory,
		DirectoryManifest: digestOf(dirFile, dirData), Resources: append([]string(nil), resources...), UnlistedYAMLIgnored: ignored,
	}
	return readDefinitions(r, remote, pinned, files, inv, &origin{repo: remote, commit: pinned})
}
