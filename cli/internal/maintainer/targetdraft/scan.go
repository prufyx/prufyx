// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"gopkg.in/yaml.v3"
)

// crd is one CustomResourceDefinition read from a file.
type crd struct {
	Group    string
	Kind     string
	Plural   string   // spec.names.plural
	Scope    string   // spec.scope
	Versions []string // "name:served:storage"
	// SpecDigest is the digest of the full decoded definition (apiVersion
	// and every field of spec) in a canonical structural encoding; empty when
	// it cannot be computed. SpecParts holds the digest per top-level field
	// ("apiVersion" and spec.<field>) so a difference can be named.
	SpecDigest string
	SpecParts  map[string]string
}

// finding is one CRD-bearing file of a tree, keyed by the path of the file
// whose bytes were read (a symbolic link is resolved).
type finding struct {
	Path       string
	Reached    []string // symbolic links that resolve to Path
	CRDs       []crd
	Unreadable string // why the bytes could not be read as definitions
	// fragment marks an unreadable file whose content proves a kustomize
	// patch fragment (see fragment.go); set only with the opt-in.
	fragment bool
}

var testLikeSegments = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range crdversions.DefaultExcludedSegments {
		m[s] = true
	}
	for _, s := range []string{"docs", "doc", "fixtures", "fixture"} {
		m[s] = true
	}
	return m
}()

// testLike reports a path below a directory that is not an install location
// by default (the extractor's default-excluded segments, plus documentation
// and fixture directories).
func testLike(p string) bool {
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		if testLikeSegments[s] {
			return true
		}
	}
	return false
}

func hasDocsSegment(p string) bool {
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		if s == "docs" || s == "doc" {
			return true
		}
	}
	return false
}

func candidateExt(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}

const maxLinkHops = 8

// resolve follows symbolic links inside the tree. A link that leaves the
// tree is an error; a dangling link resolves to "".
func resolve(t Tree, isLink map[string]bool, p string) (string, error) {
	cur := p
	for hop := 0; isLink[cur]; hop++ {
		if hop >= maxLinkHops {
			return "", fmt.Errorf("%s: more than %d link hops", p, maxLinkHops)
		}
		target, err := t.Link(cur)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(target, "/") || strings.Contains(target, "\\") {
			return "", fmt.Errorf("%s: link target leaves the tree", p)
		}
		next := path.Clean(path.Join(path.Dir(cur), target))
		if next == ".." || strings.HasPrefix(next, "../") || next == "." {
			return "", fmt.Errorf("%s: link target leaves the tree", p)
		}
		cur = next
	}
	return cur, nil
}

type specBody struct {
	Group string `yaml:"group"`
	Names struct {
		Kind   string `yaml:"kind"`
		Plural string `yaml:"plural"`
	} `yaml:"names"`
	Scope    string `yaml:"scope"`
	Versions []struct {
		Name    string `yaml:"name"`
		Served  bool   `yaml:"served"`
		Storage bool   `yaml:"storage"`
	} `yaml:"versions"`
}

// specDoc decodes spec twice from the same node: into the typed fields the
// generator reads and into a generic value for the canonical spec digest. A
// failure of the generic decode only leaves the digest empty (not equal to
// anything); the typed decode keeps its original error behaviour.
type specDoc struct {
	typed specBody
	raw   any
	rawOK bool
}

func (s *specDoc) UnmarshalYAML(n *yaml.Node) error {
	if err := n.Decode(&s.typed); err != nil {
		return err
	}
	var raw any
	if err := n.Decode(&raw); err == nil {
		s.raw, s.rawOK = raw, true
	}
	return nil
}

type crdDoc struct {
	APIVersion any     `yaml:"apiVersion"`
	Kind       string  `yaml:"kind"`
	Spec       specDoc `yaml:"spec"`
}

// parseCRDs reads the definitions of a file. A file that mentions no
// definition yields none; a definition that cannot be read as a whole is an
// error (typed unreadable-shape by the caller).
func parseCRDs(data []byte) ([]crd, error) {
	if !bytes.Contains(data, []byte("CustomResourceDefinition")) {
		return nil, nil
	}
	if bytes.Contains(data, []byte("{{")) {
		return nil, errors.New("template syntax")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []crd
	for {
		var doc crdDoc
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("yaml: %v", err)
		}
		if doc.Kind != "CustomResourceDefinition" {
			continue
		}
		spec := doc.Spec.typed
		if spec.Group == "" || spec.Names.Kind == "" {
			return nil, errors.New("definition without spec.group or spec.names.kind (patch or partial shape)")
		}
		if len(spec.Versions) == 0 {
			return nil, errors.New("definition without spec.versions")
		}
		c := crd{Group: spec.Group, Kind: spec.Names.Kind, Plural: spec.Names.Plural, Scope: spec.Scope}
		if doc.Spec.rawOK {
			c.SpecDigest, c.SpecParts = specDigest(doc.APIVersion, doc.Spec.raw)
		}
		for _, v := range spec.Versions {
			if v.Name == "" {
				return nil, errors.New("version without a name")
			}
			c.Versions = append(c.Versions, fmt.Sprintf("%s:%t:%t", v.Name, v.Served, v.Storage))
		}
		out = append(out, c)
	}
	return out, nil
}

// scanTree lists every CRD-bearing file of a tree.
func scanTree(t Tree) ([]*finding, []Stop) {
	fs, stops, _ := scanTreeFragments(t, false)
	return fs, stops
}

// scanTreeFragments is scanTree with the opt-in that sets aside kustomize
// patch fragments: an unreadable file whose content proves a patch fragment
// and that no symbolic link reaches is not returned as a finding but listed
// (sorted) as a fragment. Every other unreadable file stays a finding.
func scanTreeFragments(t Tree, skipFragments bool) ([]*finding, []Stop, []string) {
	entries, err := t.Entries()
	if err != nil {
		return nil, []Stop{stop(StopTreeUnreadable, "", err.Error())}, nil
	}
	isLink := map[string]bool{}
	isFile := map[string]bool{}
	var kdirs map[string]bool
	if skipFragments {
		kdirs = kustomizationDirs(entries)
	}
	for _, e := range entries {
		if e.IsLink {
			isLink[e.Path] = true
		} else {
			isFile[e.Path] = true
		}
	}
	byPath := map[string]*finding{}
	var stops []Stop
	for _, e := range entries {
		if !candidateExt(e.Path) {
			continue
		}
		res, err := resolve(t, isLink, e.Path)
		if err != nil {
			stops = append(stops, stop(StopSymlinkEscapes, e.Path, err.Error()))
			continue
		}
		if !isFile[res] {
			continue // dangling or not a regular file
		}
		f := byPath[res]
		if f == nil {
			data, err := t.Read(res)
			f = &finding{Path: res}
			if err != nil {
				f.Unreadable = err.Error()
			} else if crds, err := parseCRDs(data); err != nil {
				f.Unreadable = err.Error()
				f.fragment = skipFragments && underKustomization(res, kdirs) && isPatchFragment(data)
			} else if len(crds) == 0 {
				byPath[res] = &finding{Path: res} // remember: nothing to report
				continue
			} else {
				f.CRDs = crds
			}
			byPath[res] = f
		}
		if e.IsLink && (len(f.CRDs) > 0 || f.Unreadable != "") {
			f.Reached = append(f.Reached, e.Path)
		}
	}
	var out []*finding
	var fragments []string
	for _, f := range byPath {
		if len(f.CRDs) > 0 || f.Unreadable != "" {
			sort.Strings(f.Reached)
			if f.fragment && len(f.Reached) == 0 {
				fragments = append(fragments, f.Path)
				continue
			}
			// A fragment reached through a symbolic link stays an unreadable
			// file: the link rules judge it exactly as before.
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	sort.Strings(fragments)
	return out, stops, fragments
}
