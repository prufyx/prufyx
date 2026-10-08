// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The full-tree scan (completeness condition Q2): at every tag the
// extractor reads, every YAML or JSON file of the repository outside the
// listed paths and the reviewed exclusions is read and searched for a
// CustomResourceDefinition. A file that holds one is classified against the
// tag's inventory. Only a clean scan lets a disappeared definition count as
// removed, and only a pair whose every tag scans clean is attestable.

// Finding classes.
const (
	// ClassCopy: every definition in the file is in the inventory with the
	// same versions and served flags.
	ClassCopy = "copy"
	// ClassSchemaPatch: a kustomization whose only CustomResourceDefinition
	// references are patch targets, and whose patches only touch version
	// schemas or metadata labels and annotations.
	ClassSchemaPatch = "schema-patch"
	// ClassConflict: a definition of an inventory CRD with other versions
	// or served flags. The pair is withheld.
	ClassConflict = "conflict"
	// ClassExtra: a definition the inventory does not hold.
	ClassExtra = "extra"
	// ClassReference: the file names the CustomResourceDefinition kind but
	// defines none and is not a schema-only kustomization.
	ClassReference = "reference"
	// ClassUnread: templated, not strictly decodable, over the bounds, or a
	// submodule.
	ClassUnread = "unread"
)

// Scan bounds.
const (
	// MaxScanFilesPerTag bounds the candidate files read at one tag.
	MaxScanFilesPerTag = 50000
	// maxKustomizePatches bounds the patch files one kustomization names.
	maxKustomizePatches = 64
)

var (
	scanNameRE  = regexp.MustCompile(`(?i)\.(ya?ml|json)$`)
	markerRE    = regexp.MustCompile(`(?m)^[ \t-]*["']?kind["']?[ \t]*:[ \t]*["']?CustomResourceDefinition["']?[ \t]*,?[ \t]*(#.*)?\r?$|"kind"[ \t]*:[ \t]*"CustomResourceDefinition"`)
	patchPathRE = regexp.MustCompile(`^/(spec/versions/(0|[1-9][0-9]{0,2})/schema|metadata/(annotations|labels))(/[^\x00-\x1f]*)?$`)
)

// ScanRecord is what the full-tree scan found at one commit.
type ScanRecord struct {
	// Complete is false when the scan could not be finished (a bound).
	Complete bool   `json:"complete"`
	Problem  string `json:"problem,omitempty"`
	// Files is the number of candidate files read; ExcludedFiles the
	// candidate files under a reviewed exclusion; SkippedDirectories the
	// directories not entered.
	Files              int `json:"files"`
	ExcludedFiles      int `json:"excludedFiles"`
	SkippedDirectories int `json:"skippedDirectories"`
	// Exclusions are the default segments and reviewed entries that
	// skipped something, sorted.
	Exclusions []string `json:"exclusions"`
	// Copies are the files of class copy, sorted.
	Copies []string `json:"copies"`
	// Findings are the files of every other class, sorted by path.
	Findings []Finding `json:"findings"`
}

// Finding is one file outside the listed paths that names the
// CustomResourceDefinition kind.
type Finding struct {
	Path   string   `json:"path"`
	SHA256 string   `json:"sha256"`
	Class  string   `json:"class"`
	CRDs   []string `json:"crds,omitempty"`
	Detail string   `json:"detail,omitempty"`
}

// Clean reports a complete scan with nothing but copies and schema-only
// kustomizations.
func (s *ScanRecord) Clean() bool {
	if s == nil || !s.Complete {
		return false
	}
	for _, f := range s.Findings {
		if f.Class != ClassSchemaPatch {
			return false
		}
	}
	return true
}

// conflicts returns the conflict findings.
func (s *ScanRecord) conflicts() []Finding {
	var out []Finding
	if s == nil {
		return nil
	}
	for _, f := range s.Findings {
		if f.Class == ClassConflict {
			out = append(out, f)
		}
	}
	return out
}

// blobInfo is what one file's bytes say, independent of the tag.
type blobInfo struct {
	sha256  string
	markers int
	// unread is the reason the file could not be classified ("" when it
	// could).
	unread string
	crds   []CRD
	kust   *kustomization
}

// kustomization is a decoded kustomization file's patch references.
type kustomization struct {
	// crdTargets counts the patch entries whose target kind is
	// CustomResourceDefinition; patchPaths are their files (relative to
	// the kustomization's directory).
	crdTargets int
	patchPaths []string
	// problem is why a CRD patch entry cannot be checked ("" when every
	// one names a local file).
	problem string
}

type scanFile struct {
	path, oid string
}

// scan walks the whole tree at commit. Reader errors abort (the mirror
// must hold every file); bounds make the record incomplete.
func (x *Extractor) scan(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string, inv *Inventory) (*ScanRecord, error) {
	x.mu.Lock()
	if s, ok := x.scans[commit]; ok {
		x.mu.Unlock()
		return s, nil
	}
	x.mu.Unlock()
	rec := &ScanRecord{Complete: true, Exclusions: []string{}, Copies: []string{}, Findings: []Finding{}}
	declared := x.declaredFiles(inv)
	hits := map[string]bool{}
	var files []scanFile
	dirs := []string{""}
	for len(dirs) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dir := dirs[0]
		dirs = dirs[1:]
		entries, err := r.List(repo, commit, dir)
		if err != nil {
			return nil, fmt.Errorf("scan listing %q at %s: %w", dir, commit, err)
		}
		for _, e := range entries {
			name := path.Base(e.Path)
			switch e.Type {
			case "tree":
				if why, skip := x.target.excludedDir(e.Path); skip {
					rec.SkippedDirectories++
					hits[why] = true
					continue
				}
				dirs = append(dirs, e.Path)
			case "commit":
				if why, skip := x.target.excludedFile(e.Path); skip {
					hits[why] = true
					continue
				}
				rec.Findings = append(rec.Findings, Finding{Path: e.Path, Class: ClassUnread, Detail: "a submodule: its files are not in this repository"})
			case "blob":
				if !scanNameRE.MatchString(name) || e.Mode == "120000" || declared[e.Path] {
					continue
				}
				if why, skip := x.target.excludedFile(e.Path); skip {
					rec.ExcludedFiles++
					hits[why] = true
					continue
				}
				files = append(files, scanFile{e.Path, e.SHA})
			}
		}
	}
	if len(files) > MaxScanFilesPerTag {
		rec.Complete, rec.Problem = false, fmt.Sprintf("%d candidate files, over the bound of %d", len(files), MaxScanFilesPerTag)
		return x.storeScan(commit, rec), nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	rec.Files = len(files)
	infos := make([]*blobInfo, len(files))
	errs := make([]error, len(files))
	x.parallel(len(files), func(i int) {
		infos[i], errs[i] = x.blob(r, repo, commit, files[i])
	})
	for i, f := range files {
		if errs[i] != nil {
			return nil, errs[i]
		}
		info := infos[i]
		if info.markers == 0 {
			continue
		}
		fd, err := x.classify(r, repo, commit, f.path, info, inv)
		if err != nil {
			return nil, err
		}
		if fd.Class == ClassCopy {
			rec.Copies = append(rec.Copies, f.path)
			continue
		}
		rec.Findings = append(rec.Findings, fd)
	}
	for h := range hits {
		rec.Exclusions = append(rec.Exclusions, h)
	}
	sort.Strings(rec.Exclusions)
	sort.Slice(rec.Findings, func(i, j int) bool { return rec.Findings[i].Path < rec.Findings[j].Path })
	return x.storeScan(commit, rec), nil
}

func (x *Extractor) storeScan(commit string, rec *ScanRecord) *ScanRecord {
	x.mu.Lock()
	defer x.mu.Unlock()
	if s, ok := x.scans[commit]; ok {
		return s
	}
	x.scans[commit] = rec
	return rec
}

// declaredFiles are the files the inventory read: the scan does not read
// them again.
func (x *Extractor) declaredFiles(inv *Inventory) map[string]bool {
	out := map[string]bool{}
	if inv != nil {
		for _, f := range inv.Files {
			out[f.Path] = true
		}
	}
	for _, p := range x.target.Paths {
		if !p.Dir {
			out[p.Path] = true
		}
	}
	return out
}

// blob reads one file (or reuses an earlier read of the same blob id) and
// summarises it.
func (x *Extractor) blob(r extract.PinnedReader, repo extract.RepoRef, commit string, f scanFile) (*blobInfo, error) {
	x.mu.Lock()
	info, ok := x.blobs[f.oid]
	x.mu.Unlock()
	if ok && f.oid != "" {
		if _, reused := extract.Reuse(r, repo, commit, f.path, f.oid); reused {
			return info, nil
		}
	}
	data, err := r.Read(repo, commit, f.path)
	if err != nil {
		return nil, fmt.Errorf("scan reading %s at %s: %w", f.path, commit, err)
	}
	info = summarize(f.path, data)
	if f.oid != "" {
		x.mu.Lock()
		x.blobs[f.oid] = info
		x.mu.Unlock()
	}
	return info, nil
}

// summarize decides what a file's bytes hold. Only a file with the marker
// is decoded.
func summarize(p string, data []byte) *blobInfo {
	sum := sha256.Sum256(data)
	info := &blobInfo{sha256: "sha256:" + hex.EncodeToString(sum[:])}
	info.markers = len(markerRE.FindAll(data, -1))
	if info.markers == 0 {
		return info
	}
	_, crds, err := parseFile(p, data)
	if err != nil {
		if pr, ok := asProblem(err); ok {
			info.unread = pr.msg
		} else {
			info.unread = err.Error()
		}
		return info
	}
	info.crds = crds
	if len(crds) == 0 {
		if k, ok := readKustomization(p, data); ok {
			info.kust = k
		}
	}
	return info
}

// classify places a marker file against the inventory of its tag.
func (x *Extractor) classify(r extract.PinnedReader, repo extract.RepoRef, commit, p string, info *blobInfo, inv *Inventory) (Finding, error) {
	fd := Finding{Path: p, SHA256: info.sha256}
	if info.unread != "" {
		fd.Class, fd.Detail = ClassUnread, info.unread
		return fd, nil
	}
	if len(info.crds) == 0 {
		if info.kust == nil {
			fd.Class, fd.Detail = ClassReference, "names the CustomResourceDefinition kind but defines none"
			return fd, nil
		}
		why, err := x.checkKustomization(r, repo, commit, p, info)
		if err != nil {
			return fd, err
		}
		if why != "" {
			fd.Class, fd.Detail = ClassReference, why
			return fd, nil
		}
		fd.Class = ClassSchemaPatch
		return fd, nil
	}
	byName := map[string]*CRD{}
	if inv != nil {
		for i := range inv.CRDs {
			byName[inv.CRDs[i].Name] = &inv.CRDs[i]
		}
	}
	fd.Class = ClassCopy
	for i := range info.crds {
		c := &info.crds[i]
		fd.CRDs = append(fd.CRDs, c.Name)
		known, ok := byName[c.Name]
		switch {
		case !ok:
			if fd.Class == ClassCopy {
				fd.Class = ClassExtra
			}
		case !sameServing(known, c):
			fd.Class = ClassConflict
			fd.Detail = fmt.Sprintf("%s: versions %s here, %s in %s", c.Name, servingString(c), servingString(known), known.Path)
		}
	}
	sort.Strings(fd.CRDs)
	if fd.Class == ClassCopy {
		fd.CRDs = nil
	}
	return fd, nil
}

// sameServing reports equal group, kind and version list with equal served
// flags (order-insensitive).
func sameServing(a, b *CRD) bool {
	return a.Group == b.Group && a.Kind == b.Kind && servingString(a) == servingString(b)
}

func servingString(c *CRD) string {
	var parts []string
	for _, v := range c.Versions {
		s := v.Name + ":unserved"
		if v.Served {
			s = v.Name + ":served"
		}
		parts = append(parts, s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// readKustomization decodes a kustomization file's CustomResourceDefinition
// patch entries. ok is false when the file is not a kustomization.
func readKustomization(p string, data []byte) (*kustomization, bool) {
	base := path.Base(p)
	if base != "kustomization.yaml" && base != "kustomization.yml" && base != "Kustomization" {
		return nil, false
	}
	_, values, err := decodeStrict(data)
	if err != nil || len(values) != 1 {
		return nil, false
	}
	obj, ok := values[0].(map[string]any)
	if !ok {
		return nil, false
	}
	if kind, _ := obj["kind"].(string); kind != "" && kind != "Kustomization" {
		return nil, false
	}
	k := &kustomization{}
	for _, field := range []string{"patches", "patchesJson6902"} {
		raw, present := obj[field]
		if !present {
			continue
		}
		items, ok := raw.([]any)
		if !ok {
			k.problem = field + " is not a list"
			return k, true
		}
		for _, it := range items {
			entry, ok := it.(map[string]any)
			if !ok {
				k.problem = field + " entry is not a mapping"
				return k, true
			}
			target, _ := entry["target"].(map[string]any)
			if kind, _ := target["kind"].(string); kind != crdKind {
				continue
			}
			k.crdTargets++
			pp, _ := entry["path"].(string)
			if _, inline := entry["patch"]; inline || pp == "" {
				k.problem = "a CustomResourceDefinition patch is inline or names no file"
				return k, true
			}
			k.patchPaths = append(k.patchPaths, pp)
		}
	}
	if _, smp := obj["patchesStrategicMerge"]; smp {
		k.problem = "strategic merge patches are not checked"
	}
	if len(k.patchPaths) > maxKustomizePatches {
		k.problem = "too many patch files"
	}
	return k, true
}

// checkKustomization returns "" when every CustomResourceDefinition
// reference of the file is a checked patch target and every patch only
// changes version schemas or metadata labels and annotations.
func (x *Extractor) checkKustomization(r extract.PinnedReader, repo extract.RepoRef, commit, p string, info *blobInfo) (string, error) {
	k := info.kust
	switch {
	case k.problem != "":
		return k.problem, nil
	case k.crdTargets == 0 || k.crdTargets != info.markers:
		return "names the CustomResourceDefinition kind outside patch targets", nil
	}
	dir := path.Dir(p)
	for _, rel := range k.patchPaths {
		full := path.Join(dir, rel)
		if !cleanRepoPath(full) || strings.HasPrefix(rel, "/") {
			return fmt.Sprintf("patch %s is outside the repository", rel), nil
		}
		data, err := r.Read(repo, commit, full)
		if err != nil {
			if isNotFound(err) {
				return fmt.Sprintf("patch %s does not exist", full), nil
			}
			return "", err
		}
		if why := schemaOnlyPatch(data); why != "" {
			return fmt.Sprintf("patch %s: %s", full, why), nil
		}
	}
	return "", nil
}

// schemaOnlyPatch accepts a JSON 6902 patch whose every operation path
// (and from) lies under a version's schema or metadata labels/annotations.
func schemaOnlyPatch(data []byte) string {
	if strings.Contains(string(data), templateMarker) {
		return "templated"
	}
	_, values, err := decodeStrict(data)
	if err != nil || len(values) != 1 {
		return "not a single strictly decodable document"
	}
	ops, ok := values[0].([]any)
	if !ok || len(ops) == 0 {
		return "not a JSON 6902 operation list"
	}
	for i, o := range ops {
		op, ok := o.(map[string]any)
		if !ok {
			return fmt.Sprintf("operation %d is not a mapping", i)
		}
		name, _ := op["op"].(string)
		switch name {
		case "add", "remove", "replace", "test", "copy", "move":
		default:
			return fmt.Sprintf("operation %d has op %q", i, name)
		}
		for key := range op {
			switch key {
			case "op", "path", "value", "from":
			default:
				return fmt.Sprintf("operation %d has key %q", i, key)
			}
		}
		for _, key := range []string{"path", "from"} {
			v, present := op[key]
			if !present {
				if key == "path" {
					return fmt.Sprintf("operation %d has no path", i)
				}
				continue
			}
			s, _ := v.(string)
			if !patchPathRE.MatchString(s) {
				return fmt.Sprintf("operation %d %s %q is outside version schemas and metadata labels and annotations", i, key, s)
			}
		}
	}
	return ""
}

// parallel runs fn(0..n-1) on at most x.concurrency goroutines.
func (x *Extractor) parallel(n int, fn func(int)) {
	workers := max(x.concurrency, 1)
	if workers == 1 || n < 2 {
		for i := 0; i < n; i++ {
			fn(i)
		}
		return
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < min(workers, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}
