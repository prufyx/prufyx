// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Pinned Helm chart dependencies. A Chart.yaml whose dependencies come from a
// chart repository is, by default, an external source: its definitions are not
// read and the tag blocks attestation. A target file can list, per chart
// directory, dependency name and repository string, the exact versions a
// reviewer read together with the URL and sha256 of the packaged chart. At a
// tag where a dependency of the Chart.yaml equals an entry and a pinned
// version, and the Chart.lock beside it (when there is one) lists the same
// remote dependencies, the scan fetches the archive through the reader's
// extract.ArchiveSource, requires the bytes to hash to the pin, unpacks it
// within bounds and classifies the files of the packaged chart like those of
// the repository. A dependency passes only if every definition it ships is a
// copy of the inventory or lies in a group the inventory does not have, and no
// manifest or RBAC rule of it names an API service of a group of the
// inventory. Any other result blocks like the same class elsewhere; a fetch
// that fails or a reader without an archive source makes the scan incomplete,
// never a finding that passes.

// ArchiveSource fetches the packaged Helm chart a reviewed target pins, by
// URL, and returns its bytes only if they hash to digest, a sha256 (64
// lower-case hex digits). It fetches over the network: an implementation
// bounds the size and the time of one call and honours ctx. An extractor
// without one (UseArchives) treats the scan of a pinned dependency as
// incomplete. The interface is declared here, not on the pinned reader, so
// that the code digest of the other extractors, which covers the framework
// package, does not move.
type ArchiveSource interface {
	Archive(ctx context.Context, url, digest string) ([]byte, error)
}

// UseArchives sets the source the extractor fetches pinned chart archives
// from. It must be called before the extractor runs.
func (x *Extractor) UseArchives(src ArchiveSource) { x.archives = src }

// HasArchives reports whether the extractor has an archive source.
func (x *Extractor) HasArchives() bool { return x.archives != nil }

// The two classes a dependency adds.
const (
	// ClassDependencyExtra: a definition of a chart dependency the inventory
	// does not hold, in a group the inventory has at this tag: the
	// dependency would install versions the rules never see.
	ClassDependencyExtra = "dependency-extra"
	// ClassDependencyAPIService: a chart dependency names an API service of a
	// group of the inventory ("<version>.<group>"): a program it deploys may
	// serve resources of that group.
	ClassDependencyAPIService = "dependency-apiservice"
)

// dependencyPrefix starts the location of a file of a chart dependency.
const dependencyPrefix = "dependency: "

// depNotRead is recorded in a scan that read a chart dependency.
const depNotRead = "programs a chart dependency deploys (they may register API services of groups outside the inventory or install definitions at run time), and archives of a chart dependency that are not pinned"

// Bounds of a chart dependency archive.
const (
	maxDepArchiveBytes  = 10 << 20
	maxDepUnpackedBytes = 64 << 20
	maxDepEntries       = 4000
	maxDepServices      = 200
	maxDepMatches       = 10000
	maxChartDeps        = 32
	maxDepPins          = 64
)

// ChartDependency is one reviewed remote Helm chart dependency of the chart
// in directory Chart. Name and Repository are the exact strings of the
// dependency in Chart.yaml (a trailing slash of the repository included); the
// pins are the versions a reviewer read, each with the URL of the packaged
// chart and its sha256. Adding an entry or a pin, or changing a pin's URL,
// sha256 or the repository, loosens what the scan accepts: the target guard
// lists it. The repository is an https URL; oci:// repositories are not read.
type ChartDependency struct {
	Chart      string
	Name       string
	Repository string
	Reason     string
	Evidence   string
	Pins       []DependencyPin
}

// DependencyPin is one pinned version of a ChartDependency.
type DependencyPin struct {
	Version string
	URL     string
	SHA256  string
}

type chartDependencyJSON struct {
	Chart      string              `json:"chart"`
	Name       string              `json:"name"`
	Repository string              `json:"repository"`
	Reason     string              `json:"reason"`
	Evidence   string              `json:"evidence"`
	Pins       []dependencyPinJSON `json:"pins"`
}

type dependencyPinJSON struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

var (
	depNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// depVersionRE is one exact version: three numbers and an optional
	// pre-release. No range operator, wildcard, space or build metadata.
	depVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	depDigestRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// httpsURL parses an https URL with a host and nothing else around it (no
// credentials, query or fragment) that prints back as written.
func httpsURL(raw string) (*url.URL, error) {
	if strings.HasPrefix(raw, "oci://") {
		return nil, fmt.Errorf("oci:// repositories are not read")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || len(raw) > 512 || u.String() != raw:
		return nil, fmt.Errorf("%q is not a plain URL", raw)
	case u.Scheme != "https" || u.Hostname() == "" || strings.ToLower(u.Host) != u.Host:
		return nil, fmt.Errorf("%q is not an https URL with a lower-case host", raw)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return nil, fmt.Errorf("%q has credentials, a query or a fragment", raw)
	}
	return u, nil
}

// chartDependencies validates the chartDependencies member of a target file.
func chartDependencies(js []chartDependencyJSON) ([]ChartDependency, error) {
	if len(js) == 0 {
		return nil, nil
	}
	if len(js) > maxChartDeps {
		return nil, fmt.Errorf("more than %d entries", maxChartDeps)
	}
	var out []ChartDependency
	for i, cj := range js {
		label := fmt.Sprintf("%q %q", cj.Chart, cj.Name)
		if !cleanRepoPath(cj.Chart) {
			return nil, fmt.Errorf("%s: chart is not a clean repository directory", label)
		}
		if !depNameRE.MatchString(cj.Name) {
			return nil, fmt.Errorf("%s: name", label)
		}
		repo, err := httpsURL(cj.Repository)
		if err != nil {
			return nil, fmt.Errorf("%s: repository: %w", label, err)
		}
		if i > 0 {
			p := js[i-1]
			if p.Chart+"\x00"+p.Name+"\x00"+p.Repository >= cj.Chart+"\x00"+cj.Name+"\x00"+cj.Repository {
				return nil, fmt.Errorf("%s: entries are not sorted by chart, name and repository, or one is listed twice", label)
			}
		}
		if err := validReasonEvidence(cj.Reason, cj.Evidence); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if len(cj.Pins) == 0 || len(cj.Pins) > maxDepPins {
			return nil, fmt.Errorf("%s: one to %d pins are required", label, maxDepPins)
		}
		dep := ChartDependency{Chart: cj.Chart, Name: cj.Name, Repository: cj.Repository, Reason: cj.Reason, Evidence: cj.Evidence}
		for k, pj := range cj.Pins {
			if !depVersionRE.MatchString(pj.Version) {
				return nil, fmt.Errorf("%s: version %q is not one exact version", label, pj.Version)
			}
			if k > 0 && cj.Pins[k-1].Version >= pj.Version {
				return nil, fmt.Errorf("%s: pins are not sorted by version, or version %q is listed twice", label, pj.Version)
			}
			u, err := httpsURL(pj.URL)
			if err != nil {
				return nil, fmt.Errorf("%s: pin %s: url: %w", label, pj.Version, err)
			}
			if u.Host != repo.Host || !strings.HasSuffix(u.Path, ".tgz") {
				return nil, fmt.Errorf("%s: pin %s: the url must be a .tgz on the host of the repository", label, pj.Version)
			}
			if !depDigestRE.MatchString(pj.SHA256) {
				return nil, fmt.Errorf("%s: pin %s: sha256 is not 64 lower-case hex digits", label, pj.Version)
			}
			dep.Pins = append(dep.Pins, DependencyPin{Version: pj.Version, URL: pj.URL, SHA256: pj.SHA256})
		}
		out = append(out, dep)
	}
	return out, nil
}

// chartDependency returns the entry for a dependency of the Chart.yaml in
// directory dir, matched by exact name and repository string.
func (t Target) chartDependency(dir, name, repository string) *ChartDependency {
	for i := range t.ChartDependencies {
		d := &t.ChartDependencies[i]
		if d.Chart == dir && d.Name == name && d.Repository == repository {
			return d
		}
	}
	return nil
}

// chartDepEntry is one dependency of a Chart.yaml that comes from a chart
// repository.
type chartDepEntry struct {
	name, version, repo string
	// mapping is false for a dependency that is not a mapping.
	mapping bool
	// text is how the dependency is named in an external finding.
	text string
}

// remoteChartDeps lists the dependencies of a Chart.yaml mapping that come
// from another repository (a repository other than a local file:// path or
// none).
func remoteChartDeps(obj map[string]any) []chartDepEntry {
	deps, ok := obj["dependencies"].([]any)
	if !ok {
		return nil
	}
	if _, chart := obj["apiVersion"]; !chart {
		return nil
	}
	var out []chartDepEntry
	for _, d := range deps {
		m, ok := d.(map[string]any)
		if !ok {
			out = append(out, chartDepEntry{text: "a dependency that is not a mapping"})
			continue
		}
		repo, _ := m["repository"].(string)
		if !remoteSource(repo) {
			continue
		}
		name, _ := m["name"].(string)
		version, _ := m["version"].(string)
		out = append(out, chartDepEntry{name: name, version: version, repo: repo, mapping: true, text: fmt.Sprintf("%s %s from %s", name, version, repo)})
	}
	return out
}

func chartDepTexts(entries []chartDepEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.text)
	}
	sort.Strings(out)
	return out
}

// DependencyRecord is the proof of one pinned chart dependency read at a
// commit: what was fetched and how each of its files was classified.
type DependencyRecord struct {
	Chart      string `json:"chart"`
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Version    string `json:"version"`
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	// Problem is why the archive was not read ("" when it was unpacked).
	Problem string `json:"problem,omitempty"`
	// Files are the files of the packaged chart that name the
	// CustomResourceDefinition kind or another repository, sorted by path.
	Files []DependencyFile `json:"files"`
	// APIServices are the names "<version>.<group>" found anywhere in the
	// packaged chart, sorted.
	APIServices []string `json:"apiServices,omitempty"`
}

// DependencyFile is one file of a packaged chart.
type DependencyFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Class  string `json:"class"`
	// CRDs are the definitions of the file; Extra the ones of them the
	// inventory of the tag does not hold.
	CRDs  []string `json:"crds,omitempty"`
	Extra []string `json:"extra,omitempty"`
}

// depFile is one file of an unpacked archive, summarized once.
type depFile struct {
	path string
	kind int
	tgz  bool
	info *blobInfo
}

// depArchive is an unpacked, verified archive. unread is why it could not be
// read ("" when it could).
type depArchive struct {
	unread   string
	files    []depFile
	services []string
}

// apiServiceRE finds the name of an API service, "<version>.<group>", in any
// file: a manifest, or the resourceNames of an RBAC rule. The group has at
// least two labels and ends in a label that starts with a letter.
var apiServiceRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9.-])(v[0-9]+(?:(?:alpha|beta)[0-9]+)?\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?)`)

// groupOf is the part of a definition name ("<plural>.<group>") or of an API
// service name ("<version>.<group>") after its first dot.
func groupOf(name string) string {
	_, g, _ := strings.Cut(name, ".")
	return g
}

// readDependencyArchive unpacks a verified archive within the bounds and
// summarizes its files. The archive must hold one top directory named name,
// regular files and directories only, with clean unique paths, and a
// Chart.yaml whose name and version are the dependency's.
func readDependencyArchive(name, version string, data []byte) *depArchive {
	unread := func(why string) *depArchive { return &depArchive{unread: why} }
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return unread("the archive is not gzip-compressed")
	}
	defer zr.Close()
	lr := &io.LimitedReader{R: zr, N: maxDepUnpackedBytes + 1}
	tr := tar.NewReader(lr)
	type rawFile struct {
		path string
		data []byte
	}
	var raws []rawFile
	seen := map[string]bool{}
	entries, total := 0, 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if lr.N <= 0 {
			return unread(fmt.Sprintf("the archive unpacks to more than %d bytes", maxDepUnpackedBytes))
		}
		if err != nil {
			return unread("the archive is not a readable tar file")
		}
		if entries++; entries > maxDepEntries {
			return unread(fmt.Sprintf("the archive has more than %d entries", maxDepEntries))
		}
		var isDir bool
		switch hdr.Typeflag {
		case tar.TypeReg:
		case tar.TypeDir:
			isDir = true
		default:
			return unread("the archive holds an entry that is neither a regular file nor a directory")
		}
		p := strings.TrimSuffix(hdr.Name, "/")
		switch {
		case p == "" || path.Clean(p) != p || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\\") || p == ".." || strings.HasPrefix(p, "../"):
			return unread("the archive holds a path that is not a clean relative path")
		case !isDir && !strings.HasPrefix(p, name+"/"), isDir && p != name && !strings.HasPrefix(p, name+"/"):
			return unread("the archive holds a path outside the one top directory named after the dependency")
		case seen[p]:
			return unread("the archive holds a path twice")
		}
		seen[p] = true
		if isDir {
			continue
		}
		if hdr.Size < 0 || int64(total)+hdr.Size > maxDepUnpackedBytes {
			return unread(fmt.Sprintf("the archive unpacks to more than %d bytes", maxDepUnpackedBytes))
		}
		body, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil || int64(len(body)) != hdr.Size {
			return unread("the archive is not a readable tar file")
		}
		total += len(body)
		raws = append(raws, rawFile{path: p, data: body})
	}
	if len(raws) == 0 {
		return unread("the archive holds no file")
	}
	sort.Slice(raws, func(i, j int) bool { return raws[i].path < raws[j].path })
	isFile := map[string]bool{}
	for _, f := range raws {
		isFile[f.path] = true
	}
	for _, f := range raws {
		for dir := path.Dir(f.path); dir != "."; dir = path.Dir(dir) {
			if isFile[dir] {
				return unread("the archive holds a file below a file")
			}
		}
	}
	var chart []byte
	for _, f := range raws {
		if f.path == name+"/Chart.yaml" {
			chart = f.data
		}
	}
	if why := dependencyChartIdentity(chart, name, version); why != "" {
		return unread(why)
	}
	da := &depArchive{}
	services := map[string]bool{}
	for _, f := range raws {
		found := apiServiceRE.FindAllSubmatch(f.data, maxDepMatches)
		for _, m := range found {
			services[string(m[1])] = true
		}
		if len(found) == maxDepMatches || len(services) > maxDepServices {
			return unread(fmt.Sprintf("the archive names more than %d API services", maxDepServices))
		}
		if strings.HasSuffix(strings.ToLower(f.path), ".tgz") {
			sum := sha256.Sum256(f.data)
			da.files = append(da.files, depFile{path: f.path, tgz: true, info: &blobInfo{sha256: "sha256:" + hex.EncodeToString(sum[:])}})
			continue
		}
		kind := fileKind(f.path, place{})
		if kind == kindNone {
			continue
		}
		da.files = append(da.files, depFile{path: f.path, kind: kind, info: summarize(kind, f.data)})
	}
	for s := range services {
		da.services = append(da.services, s)
	}
	sort.Strings(da.services)
	return da
}

// dependencyChartIdentity checks that the Chart.yaml of the archive is the
// dependency's: a single mapping whose name and version are the ones pinned.
func dependencyChartIdentity(chart []byte, name, version string) string {
	if chart == nil {
		return "the archive holds no Chart.yaml"
	}
	if len(chart) > MaxFileBytes {
		return "the Chart.yaml of the archive is over the size bound"
	}
	_, values, err := decodeStrict(chart)
	if err != nil || len(values) != 1 {
		return "the Chart.yaml of the archive is not strictly decodable"
	}
	obj, ok := values[0].(map[string]any)
	if !ok {
		return "the Chart.yaml of the archive is not a mapping"
	}
	if n, _ := obj["name"].(string); n != name {
		return "the Chart.yaml of the archive names another chart than the dependency"
	}
	if v, _ := obj["version"].(string); v != version {
		return "the Chart.yaml of the archive is another version than the pin"
	}
	return ""
}

// dependencyArchive returns the unpacked archive of a pin, fetching it once
// per extractor. problem is why the scan cannot be completed (the archive
// could not be fetched, or there is no source to fetch it from); once a fetch
// has failed no other is tried. err is the context's error.
func (x *Extractor) dependencyArchive(ctx context.Context, name string, pin DependencyPin) (da *depArchive, problem string, err error) {
	x.depMu.Lock()
	defer x.depMu.Unlock()
	key := name + "\x00" + pin.Version + "\x00" + pin.URL + "\x00" + pin.SHA256
	if x.deps == nil {
		x.deps = map[string]*depArchive{}
	}
	if got, ok := x.deps[key]; ok {
		return got, "", nil
	}
	if x.depProblem != "" {
		return nil, x.depProblem, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	fail := func(format string, args ...any) (*depArchive, string, error) {
		x.depProblem = fmt.Sprintf(format, args...)
		return nil, x.depProblem, nil
	}
	if x.archives == nil {
		return fail("the chart dependency %s@%s cannot be read: no archive source is configured", name, pin.Version)
	}
	data, ferr := x.archives.Archive(ctx, pin.URL, pin.SHA256)
	if ferr != nil {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		msg := ferr.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fail("the archive of the chart dependency %s@%s could not be fetched: %s", name, pin.Version, msg)
	}
	if len(data) > maxDepArchiveBytes {
		return fail("the archive of the chart dependency %s@%s is over the %d-byte bound", name, pin.Version, maxDepArchiveBytes)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != pin.SHA256 {
		got := &depArchive{unread: "the fetched archive does not hash to the pin"}
		x.deps[key] = got
		return got, "", nil
	}
	got := readDependencyArchive(name, pin.Version, data)
	x.deps[key] = got
	return got, "", nil
}

// matchedDep is a dependency of a Chart.yaml that equals an entry and a pin.
type matchedDep struct {
	name, version, repo string
	entry               *ChartDependency
	pin                 *DependencyPin
}

// Results of the Chart.lock check.
const (
	lockOK = iota
	// lockMismatch: the Chart.lock lists other remote dependencies than the
	// Chart.yaml; the pins are not applied.
	lockMismatch
	// lockBad: the Chart.lock cannot be read.
	lockBad
)

// chartLock compares the remote dependencies of the Chart.lock beside a
// Chart.yaml (when there is one) with those of the Chart.yaml.
func (x *Extractor) chartLock(r extract.PinnedReader, repo extract.RepoRef, commit, dir string, modes map[string]string, entries []chartDepEntry) (int, string, error) {
	lock := path.Join(dir, "Chart.lock")
	mode, present := modes[lock]
	if !present {
		return lockOK, "", nil
	}
	if mode != "100644" && mode != "100755" {
		return lockBad, "the Chart.lock is not a regular file", nil
	}
	data, err := r.Read(repo, commit, lock)
	if err != nil {
		return lockOK, "", fmt.Errorf("scan reading %s at %s: %w", lock, commit, err)
	}
	if len(data) > MaxFileBytes {
		return lockBad, fmt.Sprintf("the Chart.lock is over the %d-byte bound", MaxFileBytes), nil
	}
	_, values, derr := decodeStrict(data)
	if derr != nil || len(values) != 1 {
		return lockBad, "the Chart.lock is not strictly decodable", nil
	}
	obj, ok := values[0].(map[string]any)
	if !ok {
		return lockBad, "the Chart.lock is not a mapping", nil
	}
	var locked []string
	if raw, has := obj["dependencies"]; has && raw != nil {
		list, ok := raw.([]any)
		if !ok {
			return lockBad, "the dependencies of the Chart.lock are not a list", nil
		}
		for _, d := range list {
			m, ok := d.(map[string]any)
			if !ok {
				return lockBad, "a dependency of the Chart.lock is not a mapping", nil
			}
			name, _ := m["name"].(string)
			version, _ := m["version"].(string)
			rp, _ := m["repository"].(string)
			if remoteSource(rp) {
				locked = append(locked, name+"\x00"+version+"\x00"+rp)
			}
		}
	}
	var declared []string
	for _, e := range entries {
		if e.mapping {
			declared = append(declared, e.name+"\x00"+e.version+"\x00"+e.repo)
		}
	}
	sort.Strings(locked)
	sort.Strings(declared)
	if !slices.Equal(locked, declared) {
		return lockMismatch, "", nil
	}
	return lockOK, "", nil
}

// resolveChartDeps reads the pinned dependencies of the Chart.yaml f. It
// records what it read (findings and dependency records) in rec and returns
// the summary to classify the Chart.yaml itself with: the dependencies that
// were read are left out of its external ones, every other stays. A fetch
// that cannot be made leaves the dependency external and the scan incomplete.
func (x *Extractor) resolveChartDeps(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string, f scanFile, info *blobInfo, inv *Inventory, modes map[string]string, rec *ScanRecord) (*blobInfo, error) {
	dir := path.Dir(f.path)
	var matched []matchedDep
	seen := map[matchedKey]bool{}
	for _, d := range info.chartDepEntries {
		if !d.mapping {
			continue
		}
		e := x.target.chartDependency(dir, d.name, d.repo)
		if e == nil {
			continue
		}
		for i := range e.Pins {
			k := matchedKey{d.name, d.version, d.repo}
			if e.Pins[i].Version == d.version && !seen[k] {
				seen[k] = true
				matched = append(matched, matchedDep{name: d.name, version: d.version, repo: d.repo, entry: e, pin: &e.Pins[i]})
			}
		}
	}
	if len(matched) == 0 {
		return info, nil
	}
	status, why, err := x.chartLock(r, repo, commit, dir, modes, info.chartDepEntries)
	if err != nil {
		return nil, err
	}
	switch status {
	case lockMismatch:
		return info, nil
	case lockBad:
		rec.Findings = append(rec.Findings, Finding{Path: path.Join(dir, "Chart.lock"), Class: ClassUnread, Detail: why})
		return info, nil
	}
	sort.Slice(matched, func(i, j int) bool {
		a, b := matched[i], matched[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if a.version != b.version {
			return a.version < b.version
		}
		return a.repo < b.repo
	})
	read := map[matchedKey]bool{}
	for _, m := range matched {
		da, problem, err := x.dependencyArchive(ctx, m.name, *m.pin)
		if err != nil {
			return nil, err
		}
		if problem != "" {
			rec.Complete = false
			if rec.Problem == "" {
				rec.Problem = problem
			}
			continue
		}
		read[matchedKey{m.name, m.version, m.repo}] = true
		loc := fmt.Sprintf("%s%s@%s", dependencyPrefix, m.name, m.version)
		drec := DependencyRecord{Chart: dir, Name: m.name, Repository: m.repo, Version: m.version, URL: m.pin.URL, SHA256: m.pin.SHA256, Files: []DependencyFile{}}
		if da.unread != "" {
			drec.Problem = da.unread
			rec.Findings = append(rec.Findings, Finding{Path: f.path, SHA256: info.sha256, Class: ClassUnread, Location: loc, Detail: da.unread})
		} else {
			x.classifyDependency(inv, loc, f.path, da, &drec, rec)
			if !slicesContains(rec.NotRead, depNotRead) {
				rec.NotRead = append(rec.NotRead, depNotRead)
			}
		}
		rec.Dependencies = append(rec.Dependencies, drec)
	}
	ci := *info
	var left []chartDepEntry
	for _, e := range info.chartDepEntries {
		if e.mapping && read[matchedKey{e.name, e.version, e.repo}] {
			continue
		}
		left = append(left, e)
	}
	ci.chartDeps = chartDepTexts(left)
	return &ci, nil
}

type matchedKey struct{ name, version, repo string }

// infoCRDs are the definitions a file's bytes were read as.
func infoCRDs(info *blobInfo) []CRD {
	switch {
	case info.legacy != nil:
		return info.legacy
	case info.unread != "" && info.template != nil:
		return info.template.crds
	}
	return info.crds
}

// classifyDependency classifies the files of an unpacked dependency against
// the inventory of the tag, as files of the repository are, and records the
// result. A finding is added for everything that does not pass: only copies,
// templated copies, and definitions of a group the inventory does not have
// pass (decided per definition, so one definition of a group of the inventory
// blocks the whole file), and no file of the dependency may name an API
// service of a group of the inventory.
func (x *Extractor) classifyDependency(inv *Inventory, loc, chartPath string, da *depArchive, drec *DependencyRecord, rec *ScanRecord) {
	groups := map[string]bool{}
	byName := map[string]bool{}
	if inv != nil {
		for _, c := range inv.CRDs {
			groups[c.Group] = true
			byName[c.Name] = true
		}
	}
	noDirs := map[string]bool{}
	for _, df := range da.files {
		var fd Finding
		found := false
		switch {
		case df.tgz:
			fd, found = Finding{Class: ClassUnread, Detail: "a packaged chart inside the dependency: its files are not read"}, true
		case isKustomizationName(path.Base(df.path)):
			if df.info.decoded {
				fd, found = Finding{Class: ClassUnread, Detail: "a kustomization inside a chart dependency is not read"}, true
			}
		default:
			var err error
			// A kustomization is the only file whose classification reads the
			// repository: it is refused above, so no reader is needed.
			fd, found, err = x.classifyFile(nil, extract.RepoRef{}, "", scanFile{path: df.path, kind: df.kind}, df.info, inv, noDirs)
			if err != nil {
				fd, found = Finding{Class: ClassUnread, Detail: "the file could not be classified"}, true
			}
		}
		if !found {
			continue
		}
		fd.Path, fd.SHA256, fd.Location = df.path, df.info.sha256, loc
		file := DependencyFile{Path: df.path, SHA256: df.info.sha256}
		file.CRDs, _ = definitionsOf(infoCRDs(df.info))
		blocks := true
		switch fd.Class {
		case ClassCopy, ClassTemplatedCopy:
			blocks = false
		case ClassExtra:
			var inGroup []string
			for _, n := range fd.CRDs {
				if byName[n] {
					continue
				}
				file.Extra = append(file.Extra, n)
				if groups[groupOf(n)] {
					inGroup = append(inGroup, n)
				}
			}
			if len(inGroup) == 0 {
				blocks = false
				break
			}
			fd.Class = ClassDependencyExtra
			fd.Detail = fmt.Sprintf("defines %s, which the inventory does not hold, in a group of the inventory: it would install versions the rules never see", strings.Join(inGroup, ", "))
		case ClassConflict, ClassUnread, ClassReference, ClassExternal, ClassUnsupported, ClassGoDefined:
		default:
			fd.Detail = fmt.Sprintf("%s in a chart dependency is not accepted: %s", fd.Class, fd.Detail)
			fd.Class = ClassUnread
		}
		file.Class = fd.Class
		if blocks {
			rec.Findings = append(rec.Findings, fd)
		}
		drec.Files = append(drec.Files, file)
	}
	drec.APIServices = da.services
	var hit []string
	for _, s := range da.services {
		if groups[groupOf(s)] {
			hit = append(hit, s)
		}
	}
	if len(hit) > 0 {
		rec.Findings = append(rec.Findings, Finding{Path: chartPath, Class: ClassDependencyAPIService, Location: loc,
			Detail: fmt.Sprintf("names the API service %s of a group of the inventory: a program the dependency deploys may serve it", strings.Join(hit, ", "))})
	}
}

// dependencyGroupConflict says why a pair is not attested when a chart
// dependency read at any release of either line ships a definition or names an
// API service in a group that the inventory has at any release of the two
// lines: the single-release checks (dependency-extra, dependency-apiservice)
// look at one inventory, this one at their union. Only the groups of the
// inventories count, never a table outside the digest.
func dependencyGroupConflict(states []*tagState) string {
	groups := map[string]bool{}
	for _, st := range states {
		if st.complete() {
			for _, c := range st.inv.CRDs {
				groups[c.Group] = true
			}
		}
	}
	for _, st := range states {
		if !st.complete() || st.scan == nil {
			continue
		}
		for _, d := range st.scan.Dependencies {
			for _, f := range d.Files {
				for _, n := range f.Extra {
					if groups[groupOf(n)] {
						return fmt.Sprintf("the chart dependency %s@%s at %s ships %s, in a group of the inventory of another release of the pair: the definitions it installs are not the ones the rules were derived from", d.Name, d.Version, st.tag.Name, n)
					}
				}
			}
			for _, s := range d.APIServices {
				if groups[groupOf(s)] {
					return fmt.Sprintf("the chart dependency %s@%s at %s names the API service %s, of a group of the inventory of a release of the pair: a program it deploys may serve it", d.Name, d.Version, st.tag.Name, s)
				}
			}
		}
	}
	return ""
}
