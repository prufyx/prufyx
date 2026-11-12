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
	Versions []string // "name:served:storage"
}

// finding is one CRD-bearing file of a tree, keyed by the path of the file
// whose bytes were read (a symbolic link is resolved).
type finding struct {
	Path       string
	Reached    []string // symbolic links that resolve to Path
	CRDs       []crd
	Unreadable string // why the bytes could not be read as definitions
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

type crdDoc struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Group string `yaml:"group"`
		Names struct {
			Kind string `yaml:"kind"`
		} `yaml:"names"`
		Versions []struct {
			Name    string `yaml:"name"`
			Served  bool   `yaml:"served"`
			Storage bool   `yaml:"storage"`
		} `yaml:"versions"`
	} `yaml:"spec"`
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
		if doc.Spec.Group == "" || doc.Spec.Names.Kind == "" {
			return nil, errors.New("definition without spec.group or spec.names.kind (patch or partial shape)")
		}
		if len(doc.Spec.Versions) == 0 {
			return nil, errors.New("definition without spec.versions")
		}
		c := crd{Group: doc.Spec.Group, Kind: doc.Spec.Names.Kind}
		for _, v := range doc.Spec.Versions {
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
	entries, err := t.Entries()
	if err != nil {
		return nil, []Stop{stop(StopTreeUnreadable, "", err.Error())}
	}
	isLink := map[string]bool{}
	isFile := map[string]bool{}
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
	for _, f := range byPath {
		if len(f.CRDs) > 0 || f.Unreadable != "" {
			sort.Strings(f.Reached)
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, stops
}
