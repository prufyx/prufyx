// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

const antreaComponent = "pkg:github/antrea-io/antrea"

// ClassAntreaModePatch identifies a whole-definition delete whose complete
// install-mode source and serving views were verified at this commit.
const ClassAntreaModePatch = "antrea-mode-patch"

// These source profiles cover the committed four-mode distribution at the
// reviewed releases. A different file inventory, recipe, tool selector or
// transform needs a new review; this is not a Kustomize renderer. Each digest
// binds sorted path, mode, type, Git object id and freshly read body SHA256,
// including directories and files that contain no CRD kind word.
var antreaModePins = map[string]string{
	"a13d931239e8ac2c94e002dc82ce923d0a28b71d": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"98a0bf1af4125dc9579df7185bdb68f74c048141": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"f44704f47b27ec03711324465867f81f5f7a14ce": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"f3f4dffd0782baef62a71c41cfdfe9748cc9c27d": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"b3b1788d42f40ab2aaf68db964a6e41e7271d83c": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"0f476c3058375f2c9a6d9570b1c228ec7e565234": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"89d1bfe8acded45230041a144a3a14ea08322f80": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"de0b42dcb79f5c3d814f96b726510903c154ac56": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"be9a8a2518ab7f2cf28aa435a845a1e4f0c74f9d": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"1476be6930f5dd47940938b5713fa461ef1fd086": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"55628032a87d448f137fb458b6bff26a990e903b": "cc08b512da257278b524fc868e2924be0cb3ca42a224371961349312ce1121bb",
	"efdd370826f89400b3d5639a5482d76bc9f3331b": "b963f50b08ea8bcb60bea1fabe209d4cbdde0cd14fe841631ef2dbcda24470f4",
	"b249a64afc5f0a50bdcf3d00c6ff21a979c8ed3c": "d3f5f88beee82490f162012cb177052729ddb4fa070c4b57492f20c6b5654813",
	"a41e955dffc530bdcdd1641b2cac8c0b14a47152": "d3f5f88beee82490f162012cb177052729ddb4fa070c4b57492f20c6b5654813",
	"a7bea5d6661be93427a5b7541b0b8a4711050423": "d3f5f88beee82490f162012cb177052729ddb4fa070c4b57492f20c6b5654813",
	"c57fe033ba3c8fbd0015913d91e11c9c3f13a4a3": "d3f5f88beee82490f162012cb177052729ddb4fa070c4b57492f20c6b5654813",
	"a1045cc3b504bc30cf2a5fdb6918a9708bd7349b": "d3f5f88beee82490f162012cb177052729ddb4fa070c4b57492f20c6b5654813",
	"a73fcb92084c897fa149e37642989ed01f7f17d1": "d3f5f88beee82490f162012cb177052729ddb4fa070c4b57492f20c6b5654813",
	"384f784fb34420bd11b59ca3e2660d5d70dd8af3": "d7a52695a7bae91aa01ba1974e8f7e45b6319cfd5700945b8c469ea819c79cb1",
	"08603530d80943f0b2f816a807c5242f633f0372": "d7a52695a7bae91aa01ba1974e8f7e45b6319cfd5700945b8c469ea819c79cb1",
	"e59003c2c1b13a961ff58a6d7b8f1133049d0bf0": "f9191f0d9a0356f54395fbe888292bba1e9ad5ea479f081498cd6f2f70aa779a",
}

var antreaModes = []string{"leader", "leader-global", "leader-ns", "member"}

// AntreaModeRecord is a source-bound serving view, never an input authority.
// verified is deliberately not serialized: observations cannot authorize a
// clean scan or line attestation without the source read.
type AntreaModeRecord struct {
	SourceSHA256 string              `json:"sourceSHA256"`
	Modes        map[string][]string `json:"modes"`
	verified     bool
	dependencies map[string]CRD
}

type antreaDependency struct {
	name, group, kind, version, file, sha256 string
}

var antreaMCSDependencies = []antreaDependency{
	{"serviceexports.multicluster.x-k8s.io", "multicluster.x-k8s.io", "ServiceExport", "v1alpha1", "multicluster/config/crd/k8smcs/multicluster.x-k8s.io_serviceexports.yaml", "sha256:09373a675b24a9c926c1c3df19b43a9bf401807e87604f71fdf1311c0f190bb1"},
	{"serviceimports.multicluster.x-k8s.io", "multicluster.x-k8s.io", "ServiceImport", "v1alpha1", "multicluster/config/crd/k8smcs/multicluster.x-k8s.io_serviceimports.yaml", "sha256:99df9b742043f4e69c8b9b4cfc2140d539f368cd94b96468469594923045074d"},
}

var antreaNADDependency = antreaDependency{
	"network-attachment-definitions.k8s.cni.cncf.io", "k8s.cni.cncf.io", "NetworkAttachmentDefinition", "v1",
	"test/e2e-secondary-network/infra/network-attachment-definition-crd.yml", "sha256:75ba5b4649517f01674f0809ce8840311959f3333648019166361c81f46d0960",
}

func antreaModeScope(p string) bool {
	for _, root := range []string{"multicluster/config", "multicluster/build/yamls", "multicluster/Makefile", "multicluster/hack/generate-manifest.sh", "multicluster/hack/update-checksum.sh", "hack/verify-kustomize.sh"} {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

// readAntreaModeSource reads all scoped bytes, not just metadata supplied by
// the tree or a previous witness. Scope inventory changes alter the digest.
func readAntreaModeSource(r extract.PinnedReader, repo extract.RepoRef, commit string, entries []extract.TreeEntry) (map[string][]byte, string, error) {
	data, seen := map[string][]byte{}, map[string]bool{}
	var lines []string
	totalBytes := 0
	for _, e := range entries {
		if !antreaModeScope(e.Path) {
			continue
		}
		if !cleanRepoPath(e.Path) || seen[e.Path] || !extract.IsCommitSHA(e.SHA) || len(seen) >= 512 {
			return nil, "", problemf("invalid or repeated mode source path %q", e.Path)
		}
		seen[e.Path] = true
		bodyHash := "-"
		switch {
		case e.Type == "tree" && e.Mode == "040000":
		case e.Type == "blob" && (e.Mode == "100644" || e.Mode == "100755"):
			body, err := r.Read(repo, commit, e.Path)
			if err != nil {
				return nil, "", err
			}
			totalBytes += len(body)
			if len(body) > MaxFileBytes || totalBytes > 16<<20 {
				return nil, "", problemf("mode source %s exceeds the file bound", e.Path)
			}
			data[e.Path] = body
			bodyHash = fmt.Sprintf("%x", sha256.Sum256(body))
		default:
			return nil, "", problemf("mode source %s is not a regular file or tree", e.Path)
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", e.Path, e.Mode, e.Type, e.SHA, bodyHash))
	}
	if len(lines) == 0 {
		return nil, "", problemf("the mode source inventory is empty")
	}
	sort.Strings(lines)
	return data, fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(lines, "")))), nil
}

func readAntreaModes(r extract.PinnedReader, repo extract.RepoRef, commit string, entries []extract.TreeEntry) (*AntreaModeRecord, error) {
	if repo.Key != "github.com/antrea-io/antrea" {
		return nil, problemf("the mode profile belongs to another source repository")
	}
	pin := antreaModePins[commit]
	if pin == "" {
		return nil, problemf("the Antrea four-mode source profile does not cover commit %s", commit)
	}
	data, digest, err := readAntreaModeSource(r, repo, commit, entries)
	if err != nil {
		return nil, err
	}
	if digest != pin {
		return nil, problemf("the Antrea mode inventory, generator or transform bytes differ from the reviewed source profile")
	}
	dependencies, err := readAntreaDependencies(data)
	if err != nil {
		return nil, err
	}
	// NAD is outside the multicluster source scope. Read and authenticate its
	// own body at this same commit before it can become a foreign dependency.
	nadBody, err := r.Read(repo, commit, antreaNADDependency.file)
	if err != nil {
		if isNotFound(err) {
			return nil, problemf("installed dependency %s is missing at this commit", antreaNADDependency.file)
		}
		return nil, err
	}
	nad, err := readAntreaDependency(antreaNADDependency, nadBody)
	if err != nil {
		return nil, err
	}
	dependencies[nad.Name] = nad
	modes, err := projectAntreaModes(data)
	if err != nil {
		return nil, err
	}
	return &AntreaModeRecord{SourceSHA256: digest, Modes: modes, verified: true, dependencies: dependencies}, nil
}

// These installed dependencies have a fixed source identity, not an Antrea
// ownership assignment. The independent pins remain mandatory even if a
// future reviewed mode profile adds a new source digest.
func readAntreaDependencies(data map[string][]byte) (map[string]CRD, error) {
	dependencies := map[string]CRD{}
	for _, spec := range antreaMCSDependencies {
		body, ok := data[spec.file]
		if !ok {
			return nil, problemf("installed MCS dependency %s is missing or has changed bytes", spec.file)
		}
		crd, err := readAntreaDependency(spec, body)
		if err != nil {
			return nil, err
		}
		dependencies[spec.name] = crd
	}
	return dependencies, nil
}

func readAntreaDependency(spec antreaDependency, body []byte) (CRD, error) {
	if len(body) > MaxFileBytes || fmt.Sprintf("sha256:%x", sha256.Sum256(body)) != spec.sha256 {
		return CRD{}, problemf("installed dependency %s has changed bytes", spec.file)
	}
	crds, err := antreaDefinitions(spec.file, map[string][]byte{spec.file: body})
	if err != nil {
		return CRD{}, err
	}
	if len(crds) != 1 || !antreaDependencyIdentity(crds[0], spec) {
		return CRD{}, problemf("installed dependency %s has a different identity or serving set", spec.file)
	}
	return crds[0], nil
}

func antreaDependencyIdentity(c CRD, spec antreaDependency) bool {
	return c.Name == spec.name && c.Group == spec.group && c.Kind == spec.kind &&
		c.Plural+"."+c.Group == spec.name && c.Scope == "Namespaced" && c.SourceAPIVersion == "" &&
		c.StorageVersion == spec.version && len(c.Versions) == 1 &&
		c.Versions[0].Name == spec.version && c.Versions[0].Served && c.Versions[0].Storage
}

// attributedAntreaInventory runs only after raw source parsing and the full
// mode proof. The cached raw inventory is never changed or pre-attributed.
func (x *Extractor) attributedAntreaInventory(repo extract.RepoRef, raw *Inventory, proof *AntreaModeRecord) (*Inventory, error) {
	if x.target.Component != antreaComponent || x.target.Project != "antrea" ||
		x.target.Repo != "github.com/antrea-io/antrea" || repo.Key != x.target.Repo ||
		raw == nil || !raw.Complete || len(raw.Foreign) != 0 || proof == nil || !proof.verified ||
		antreaModePins[raw.Commit] == "" || proof.SourceSHA256 != antreaModePins[raw.Commit] ||
		len(proof.dependencies) != len(antreaMCSDependencies)+1 ||
		len(antreaModeProblems(antreaComponent, []*tagState{{scan: &ScanRecord{AntreaModes: proof}}})) != 0 {
		return nil, problemf("installed dependencies require the exact repository and fresh complete source proofs")
	}
	for _, spec := range append(slices.Clone(antreaMCSDependencies), antreaNADDependency) {
		fresh := proof.dependencies[spec.name]
		if !antreaDependencyIdentity(fresh, spec) || fresh.Path != spec.file {
			return nil, problemf("the fresh installed dependency identity is missing or changed")
		}
		files, objects := 0, 0
		for _, f := range raw.Files {
			if f.Path == spec.file {
				if f.Repo != "" || f.Commit != "" || f.SHA256 != spec.sha256 || f.CRDs != 1 {
					return nil, problemf("the listed dependency receipt differs from the pinned local source")
				}
				files++
			}
		}
		for _, c := range raw.CRDs {
			if c.Name == spec.name {
				if c.Path != spec.file || c.Repo != "" || c.Commit != "" || !antreaDependencyIdentity(c, spec) || !sameServing(&fresh, &c) {
					return nil, problemf("the listed dependency object differs from the freshly verified source")
				}
				objects++
			}
		}
		owner, attribution := x.index.OwnerOf(fresh.Group, fresh.Kind)
		if files != 1 || objects != 1 || owner == x.target.Project || attribution == customresources.Ambiguous {
			return nil, problemf("installed dependency %s is missing, repeated, owned by Antrea or ambiguously attributed", spec.name)
		}
	}
	inv := *raw
	inv.Paths, inv.Files = slices.Clone(raw.Paths), slices.Clone(raw.Files)
	inv.CRDs, inv.Foreign = []CRD{}, []string{}
	for _, c := range raw.CRDs {
		if _, dependency := proof.dependencies[c.Name]; dependency || x.attribution().foreign(c.Group, c.Kind) {
			inv.Foreign = append(inv.Foreign, c.Name)
		} else {
			inv.CRDs = append(inv.CRDs, c)
		}
	}
	sort.Strings(inv.Foreign)
	return &inv, nil
}

func antreaDefinitions(p string, data map[string][]byte) ([]CRD, error) {
	body, ok := data[p]
	if !ok {
		return nil, problemf("mode source %s is missing", p)
	}
	_, crds, err := parseFile(p, body)
	return crds, err
}

func antreaDeletes(body []byte, known map[string]CRD) ([]string, error) {
	_, values, err := decodeStrict(body)
	if err != nil || len(values) == 0 {
		return nil, problemf("the deletion patch is not strictly decoded")
	}
	var names []string
	for _, value := range values {
		obj, ok := value.(map[string]any)
		if !ok || len(obj) != 4 || obj["apiVersion"] != crdAPIVersion || obj["kind"] != crdKind || obj["$patch"] != "delete" {
			return nil, problemf("the patch is not an exact whole-definition deletion")
		}
		meta, _ := obj["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		if len(meta) != 1 || known[name].Name == "" || slices.Contains(names, name) {
			return nil, problemf("the deletion target is unknown, repeated or has extra metadata")
		}
		names = append(names, name)
	}
	return names, nil
}

// projectAntreaModes checks the finite reviewed recipe's CRD set projection
// against all four shipped outputs. The source digest above binds every
// Kustomization (including no-CRD files), helper and generated transform.
func projectAntreaModes(data map[string][]byte) (map[string][]string, error) {
	_, values, err := decodeStrict(data["multicluster/config/crd/kustomization.yaml"])
	if err != nil || len(values) != 1 {
		return nil, problemf("the mode CRD resource list is not strictly decoded")
	}
	config, _ := values[0].(map[string]any)
	resources, _ := config["resources"].([]any)
	if len(resources) != 9 {
		return nil, problemf("the reviewed mode resource list does not contain nine CRDs")
	}
	known := map[string]CRD{}
	for _, raw := range resources {
		rel, ok := raw.(string)
		p := path.Join("multicluster/config/crd", rel)
		if !ok || !cleanRepoPath(rel) || !strings.HasPrefix(p, "multicluster/config/crd/") {
			return nil, problemf("a mode resource is not a local definition")
		}
		crds, err := antreaDefinitions(p, data)
		if err != nil {
			return nil, err
		}
		if len(crds) != 1 || known[crds[0].Name].Name != "" {
			return nil, problemf("a mode resource does not define one unique CRD")
		}
		known[crds[0].Name] = crds[0]
	}
	modes := map[string][]string{}
	for _, mode := range antreaModes {
		output := mode
		if mode == "leader-ns" {
			output = "leader-namespaced"
		}
		shipped, err := antreaDefinitions("multicluster/build/yamls/antrea-multicluster-"+output+".yml", data)
		if err != nil {
			return nil, err
		}
		projected := map[string]CRD{}
		if mode != "leader-ns" {
			for name, c := range known {
				projected[name] = c
			}
			deletes, err := antreaDeletes(data["multicluster/config/overlays/"+mode+"/crd_patch.yaml"], known)
			if err != nil {
				return nil, err
			}
			for _, name := range deletes {
				delete(projected, name)
			}
		}
		if len(shipped) != len(projected) {
			return nil, problemf("mode %s differs from its projected CRD inventory", mode)
		}
		var served []string
		seen := map[string]bool{}
		for _, c := range shipped {
			want, ok := projected[c.Name]
			if !ok || seen[c.Name] || !sameServing(&want, &c) {
				return nil, problemf("mode %s has a different or repeated served definition", mode)
			}
			seen[c.Name] = true
			for _, v := range c.Versions {
				if v.Served {
					served = append(served, member(c.Group, v.Name, c.Kind))
				}
			}
		}
		sort.Strings(served)
		modes[mode] = served
	}
	return modes, nil
}

func (x *Extractor) checkAntreaModes(r extract.PinnedReader, repo extract.RepoRef, commit string, entries []extract.TreeEntry, rec *ScanRecord) error {
	if x.target.Component != antreaComponent {
		return nil
	}
	proof, err := readAntreaModes(r, repo, commit, entries)
	if err != nil {
		if _, ok := asProblem(err); !ok {
			return err
		}
		rec.Findings = append(rec.Findings, Finding{Path: "multicluster/config", Class: ClassReference, Reason: "antrea-mode-profile", Detail: err.Error()})
		return nil
	}
	rec.AntreaModes = proof
	for i := range rec.Findings {
		f := &rec.Findings[i]
		for _, mode := range []string{"leader", "leader-global", "member"} {
			if f.Path == "multicluster/config/overlays/"+mode+"/crd_patch.yaml" && f.Class == ClassUnread && f.Reason == ReasonPatchNotStrict {
				f.Class, f.Reason, f.Detail = ClassAntreaModePatch, "antrea-mode-delete", "whole-definition deletions checked against the source-bound four-mode inventories"
			}
		}
	}
	return nil
}

func antreaModeProblems(component string, states []*tagState) []string {
	if component != antreaComponent {
		return nil
	}
	if len(states) == 0 {
		return []string{"the four-mode release census is empty"}
	}
	seen := map[string]map[string]bool{}
	previousMCS := map[string][]string{}
	for _, st := range states {
		if st.scan == nil || st.scan.AntreaModes == nil || !st.scan.AntreaModes.verified || len(st.scan.AntreaModes.Modes) != len(antreaModes) || len(st.scan.AntreaModes.dependencies) != len(antreaMCSDependencies)+1 {
			return []string{fmt.Sprintf("%s: the four-mode serving proof is missing or unverified", st.tag.Name)}
		}
		for _, mode := range antreaModes {
			members, ok := st.scan.AntreaModes.Modes[mode]
			if !ok || mode == "leader-ns" && len(members) != 0 {
				return []string{fmt.Sprintf("%s: the mode identities or empty namespace-mode proof differ", st.tag.Name)}
			}
			if seen[mode] == nil {
				seen[mode] = map[string]bool{}
			}
			for _, m := range slices.Sorted(maps.Keys(seen[mode])) {
				if !slices.Contains(members, m) {
					return []string{fmt.Sprintf("%s: mode %s no longer serves %s; the global union cannot attest this transition", st.tag.Name, mode, m)}
				}
			}
			for _, m := range members {
				seen[mode][m] = true
			}
			var mcs []string
			for _, m := range members {
				if strings.HasPrefix(m, "multicluster.x-k8s.io/") {
					mcs = append(mcs, m)
				}
			}
			sort.Strings(mcs)
			if previous, ok := previousMCS[mode]; ok && !slices.Equal(previous, mcs) {
				return []string{fmt.Sprintf("%s: mode %s changes an installed MCS dependency serving set", st.tag.Name, mode)}
			}
			previousMCS[mode] = mcs
		}
	}
	return nil
}
