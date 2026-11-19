// SPDX-License-Identifier: AGPL-3.0-only

package chartapisurface

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Bounds of one read. A chart beyond any of them is refused, never
// truncated: a partial read could only produce a false "complete".
const (
	MaxArchiveBytes   = 32 << 20  // compressed archive
	MaxUnpackedBytes  = 128 << 20 // all files of the archive and its nested archives
	MaxFiles          = 4096      // all entries of the archive and its nested archives
	MaxFileBytes      = 4 << 20   // one file the reader parses
	MaxSubchartDepth  = 4         // nested chart archives and directories
	MaxTemplateDepth  = 8         // helper include depth
	MaxNestDepth      = 64        // control-structure nesting in one template
	MaxHelperWork     = 20000     // helper evaluations in one chart
	MaxEntries        = 4096      // listed (apiVersion, kind) occurrences
	MaxValueSetSize   = 64        // finite alternatives of one value
	maxChartYAMLBytes = 1 << 20
)

// ErrRefused marks input the reader refuses outright (malformed or beyond a
// bound). The caller writes no ledger for it.
var ErrRefused = errors.New("chart archive refused")

type budget struct {
	files int
	bytes int64
}

type dependency struct {
	Name      string   `yaml:"name"`
	Alias     string   `yaml:"alias"`
	Condition string   `yaml:"condition"`
	Tags      []string `yaml:"tags"`
}

type chartMeta struct {
	Name         string       `yaml:"name"`
	Version      string       `yaml:"version"`
	Type         string       `yaml:"type"`
	Dependencies []dependency `yaml:"dependencies"`
}

// chart is one chart of the archive: the root or a subchart.
type chart struct {
	meta  chartMeta
	dir   string // display prefix: "" for the root, "charts/x/" for a subchart
	files map[string][]byte
	subs  []*chart
	// conditional is true for a subchart its parent declares with a
	// condition or tags.
	conditional bool
}

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// keepFile reports whether a file is read into memory; all others only
// count toward the bounds.
func keepFile(rel string) bool {
	switch {
	case rel == "Chart.yaml", rel == "requirements.yaml":
		return true
	case strings.HasPrefix(rel, "templates/"), strings.HasPrefix(rel, "crds/"), strings.HasPrefix(rel, "charts/"):
		return true
	}
	return false
}

func safePath(p string) (string, error) {
	if p == "" || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return "", refuse("unsafe path %q", p)
	}
	clean := path.Clean(p)
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return "", refuse("unsafe path %q", p)
		}
	}
	return clean, nil
}

// readArchive unpacks one gzip tarball into a chart tree.
func readArchive(raw []byte, dir string, depth int, b *budget) (*chart, error) {
	if depth > MaxSubchartDepth {
		return nil, refuse("chart nesting deeper than %d", MaxSubchartDepth)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, refuse("not a gzip archive: %v", err)
	}
	tr := tar.NewReader(zr)
	all := map[string][]byte{}
	root := ""
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, refuse("tar: %v", err)
		}
		b.files++
		if b.files > MaxFiles {
			return nil, refuse("more than %d entries", MaxFiles)
		}
		switch h.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, refuse("entry %q is not a regular file", h.Name)
		}
		name, err := safePath(h.Name)
		if err != nil {
			return nil, err
		}
		if h.Size < 0 || b.bytes+h.Size > MaxUnpackedBytes {
			return nil, refuse("unpacked size beyond %d bytes", MaxUnpackedBytes)
		}
		first, rel, ok := strings.Cut(name, "/")
		if !ok {
			return nil, refuse("file %q outside a chart directory", name)
		}
		if root == "" {
			root = first
		} else if first != root {
			return nil, refuse("more than one top-level directory")
		}
		if _, dup := all[rel]; dup {
			return nil, refuse("duplicate entry %q", name)
		}
		keep := keepFile(rel)
		if keep && h.Size > MaxFileBytes {
			return nil, refuse("file %q beyond %d bytes", name, MaxFileBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return nil, refuse("entry %q is truncated", name)
		}
		b.bytes += h.Size
		if keep {
			all[rel] = data
		} else {
			all[rel] = nil
		}
	}
	return buildChart(all, dir, depth, b)
}

func parseMeta(files map[string][]byte) (chartMeta, error) {
	raw, ok := files["Chart.yaml"]
	if !ok || len(raw) > maxChartYAMLBytes {
		return chartMeta{}, refuse("Chart.yaml missing or too large")
	}
	var m chartMeta
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return chartMeta{}, refuse("Chart.yaml: %v", err)
	}
	if m.Name == "" || m.Version == "" {
		return chartMeta{}, refuse("Chart.yaml has no name or version")
	}
	if len(m.Dependencies) == 0 {
		if req, ok := files["requirements.yaml"]; ok && len(req) <= maxChartYAMLBytes {
			var r struct {
				Dependencies []dependency `yaml:"dependencies"`
			}
			if err := yaml.Unmarshal(req, &r); err != nil {
				return chartMeta{}, refuse("requirements.yaml: %v", err)
			}
			m.Dependencies = r.Dependencies
		}
	}
	return m, nil
}

func buildChart(all map[string][]byte, dir string, depth int, b *budget) (*chart, error) {
	meta, err := parseMeta(all)
	if err != nil {
		return nil, err
	}
	c := &chart{meta: meta, dir: dir, files: map[string][]byte{}}
	subDirs := map[string]map[string][]byte{}
	var tgz []string
	for rel, data := range all {
		if strings.HasPrefix(rel, "charts/") {
			rest := strings.TrimPrefix(rel, "charts/")
			if first, inner, ok := strings.Cut(rest, "/"); ok {
				if subDirs[first] == nil {
					subDirs[first] = map[string][]byte{}
				}
				subDirs[first][inner] = data
			} else if strings.HasSuffix(rest, ".tgz") || strings.HasSuffix(rest, ".tar.gz") {
				tgz = append(tgz, rel)
			}
			continue
		}
		c.files[rel] = data
	}
	names := make([]string, 0, len(subDirs))
	for n := range subDirs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sc, err := buildChart(subDirs[n], dir+"charts/"+n+"/", depth+1, b)
		if err != nil {
			return nil, err
		}
		c.subs = append(c.subs, sc)
	}
	sort.Strings(tgz)
	for _, rel := range tgz {
		// nested archive bytes were already counted by the outer read; the
		// inner files count again, which only tightens the bounds.
		sc, err := readArchive(all[rel], dir+rel+"!/", depth+1, b)
		if err != nil {
			return nil, err
		}
		c.subs = append(c.subs, sc)
	}
	for _, sc := range c.subs {
		for _, d := range meta.Dependencies {
			if d.Name == sc.meta.Name && (d.Condition != "" || len(d.Tags) > 0) {
				sc.conditional = true
			}
		}
	}
	return c, nil
}

// walkCharts visits the chart and its subcharts, parent first.
func walkCharts(c *chart, f func(*chart)) {
	f(c)
	for _, s := range c.subs {
		walkCharts(s, f)
	}
}
