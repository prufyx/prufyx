// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
	"golang.org/x/sys/unix"
)

const (
	catalogueLandscapeFile = "cli/internal/cncfcheck/data/landscape-projects.json"
	catalogueTableFile     = "cli/internal/customresources/table.json"
	catalogueTargetsDir    = "cli/internal/extract/crdversions"
	catalogueMaxFile       = 8 << 20
	catalogueMaxTotal      = 32 << 20
	catalogueMaxOutput     = 1 << 20
	catalogueMaxTargets    = 1024
	catalogueUsage         = "subprojects: usage: prufyx-maintainer subprojects catalogue --root DIR (offline)"
)

type catalogueDigests struct {
	Landscape string  `json:"landscape"`
	Overlay   *string `json:"overlay"`
	Table     string  `json:"table"`
	Targets   string  `json:"targets"`
}
type catalogueRow struct {
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	RepositoryURL string `json:"repositoryURL"`
	RepoPath      string `json:"repoPath"`
	Parent        string `json:"parent"`
}
type subprojectCatalogue struct {
	Schema       string           `json:"schema"`
	OverlayState string           `json:"overlayState"`
	InputDigests catalogueDigests `json:"inputDigests"`
	Rows         []catalogueRow   `json:"rows"`
}
type catalogueLandscape struct {
	Schema              string `json:"schema"`
	Revision            string `json:"revision"`
	SourceURL           string `json:"sourceURL"`
	LandscapeFileDigest string `json:"landscapeFileDigest"`
	Projects            []struct {
		Slug          string `json:"slug"`
		Name          string `json:"name"`
		RepositoryURL string `json:"repositoryURL"`
		CNCFStage     string `json:"cncfStage"`
	} `json:"projects"`
}
type catalogueIdentity struct{ slug, repo string }

var catalogueSlug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var catalogueSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var catalogueDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func runSubprojectsCatalogue(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("subprojects catalogue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "repository root")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *root == "" {
		return &commandError{code: 2, message: catalogueUsage}
	}
	result, err := buildSubprojectsCatalogue(*root)
	if err != nil {
		return &commandError{code: 1, message: "subprojects catalogue: snapshot refused", err: err}
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw)+1 > catalogueMaxOutput {
		return &commandError{code: 1, message: "subprojects catalogue: output exceeds bound"}
	}
	n, err := stdout.Write(append(raw, '\n'))
	if err == nil && n != len(raw)+1 {
		return io.ErrShortWrite
	}
	return err
}

// A catalogue validates a local snapshot, not its origin. Callers separately
// authenticate the executable and the complete export before invoking it.
func buildSubprojectsCatalogue(dir string) (subprojectCatalogue, error) {
	result := subprojectCatalogue{Schema: "prufyx.io/cncf-subproject-catalogue/v1", OverlayState: "absent", Rows: []catalogueRow{}}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("root is not a regular directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return result, errors.New("cannot open root")
	}
	defer root.Close()
	anchor, err := root.Open(".")
	if err != nil {
		return result, errors.New("cannot open root anchor")
	}
	actual, statErr := anchor.Stat()
	closeErr := anchor.Close()
	if statErr != nil || closeErr != nil || !actual.IsDir() || !os.SameFile(info, actual) {
		return result, errors.New("root changed while opening")
	}
	used := 0
	read := func(name string) ([]byte, error) {
		b, e := catalogueReadFile(root, name)
		used += len(b)
		if used > catalogueMaxTotal {
			return nil, errors.New("snapshot exceeds total byte bound")
		}
		return b, e
	}
	landscapeRaw, err := read(catalogueLandscapeFile)
	if err != nil {
		return result, err
	}
	var landscape catalogueLandscape
	if err = catalogueDecode(landscapeRaw, &landscape); err != nil {
		return result, err
	}
	if err = catalogueRequired(landscapeRaw, "schema", "revision", "sourceURL", "landscapeFileDigest", "projects"); err != nil {
		return result, err
	}
	if landscape.Schema != "prufyx.io/cncf-landscape/v1" || !catalogueSHA.MatchString(landscape.Revision) || !catalogueDigest.MatchString(landscape.LandscapeFileDigest) || landscape.SourceURL != "https://github.com/cncf/landscape/blob/"+landscape.Revision+"/landscape.yml" || len(landscape.Projects) == 0 {
		return result, errors.New("invalid landscape metadata")
	}
	var landscapeDoc struct {
		Projects []json.RawMessage `json:"projects"`
	}
	if err = json.Unmarshal(landscapeRaw, &landscapeDoc); err != nil {
		return result, err
	}
	identities := []catalogueIdentity{}
	for i, p := range landscape.Projects {
		if err = catalogueRequired(landscapeDoc.Projects[i], "slug", "name", "cncfStage"); err != nil {
			return result, err
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(landscapeDoc.Projects[i], &fields); err != nil {
			return result, err
		}
		if _, ok := fields["repositoryURL"]; !ok {
			return result, errors.New("missing landscape repositoryURL")
		}
		archived := p.CNCFStage == "archived" && p.RepositoryURL == ""
		if !catalogueSlug.MatchString(p.Slug) || strings.TrimSpace(p.Name) != p.Name || p.Name == "" || (!archived && !catalogueRepository(p.RepositoryURL)) || (i > 0 && landscape.Projects[i-1].Slug >= p.Slug) {
			return result, errors.New("invalid landscape identity/order")
		}
		switch p.CNCFStage {
		case "sandbox", "incubating", "graduated", "archived":
		default:
			return result, errors.New("invalid landscape stage")
		}
		identities = append(identities, catalogueIdentity{p.Slug, strings.ToLower(p.RepositoryURL)})
	}
	tableRaw, err := read(catalogueTableFile)
	if err != nil {
		return result, err
	}
	if err = catalogueRequired(tableRaw, "schema", "projects", "reserved"); err != nil {
		return result, err
	}
	table, _, err := customresources.LoadTable(tableRaw)
	if err != nil {
		return result, errors.New("invalid custom-resource table")
	}
	for _, p := range table {
		repo := ""
		if strings.HasPrefix(p.Component, "pkg:github/") {
			repo = "https://github.com/" + strings.TrimPrefix(p.Component, "pkg:github/")
		}
		if !catalogueGitHubIdentity(repo, false) || repo != strings.ToLower(repo) {
			return result, errors.New("noncanonical table repository identity")
		}
		identities = append(identities, catalogueIdentity{p.Slug, repo})
	}
	if err = catalogueDirectory(root, catalogueTargetsDir); err != nil {
		return result, err
	}
	d, stable, err := catalogueOpenReadOnly(root, catalogueTargetsDir, true)
	if err != nil {
		return result, errors.New("cannot open target directory")
	}
	// Bound all directory entries, including non-target source files, before filtering.
	entries, err := d.ReadDir(4097)
	unchanged := stable()
	closeErr = d.Close()
	if (err != nil && err != io.EOF) || closeErr != nil || !unchanged || len(entries) > 4096 {
		return result, errors.New("cannot enumerate complete target directory")
	}
	names := []string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "target-") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	if len(names) == 0 || len(names) > catalogueMaxTargets {
		return result, errors.New("target count outside bounds")
	}
	members := make([][2]string, 0, len(names))
	targetIdentities := []catalogueIdentity{}
	targetFacts := []string{}
	for _, name := range names {
		raw, e := read(catalogueTargetsDir + "/" + name)
		if e != nil {
			return result, e
		}
		if e = strictjson.Check(raw); e != nil {
			return result, errors.New("ambiguous target JSON")
		}
		if e = catalogueRequired(raw, "schema", "target"); e != nil {
			return result, e
		}
		var doc struct {
			Target json.RawMessage `json:"target"`
		}
		if e = json.Unmarshal(raw, &doc); e != nil {
			return result, e
		}
		if e = catalogueRequired(doc.Target, "project", "name", "repo", "component", "factProject", "minFrom", "paths", "exclude"); e != nil {
			return result, e
		}
		target, e := crdversions.LoadTarget(name, raw)
		if e != nil {
			return result, errors.New("invalid target member")
		}
		id := catalogueIdentity{target.Project, "https://" + target.Repo}
		// Same-source duplicates must refuse even when identities are equal.
		for _, old := range targetIdentities {
			if id.slug == old.slug || id.repo == old.repo {
				return result, errors.New("duplicate target identity")
			}
		}
		for _, fact := range targetFacts {
			if fact == target.FactProject {
				return result, errors.New("duplicate target fact identity")
			}
		}
		targetFacts = append(targetFacts, target.FactProject)
		targetIdentities = append(targetIdentities, id)
		members = append(members, [2]string{name, catalogueHash(raw)})
	}
	identities = append(identities, targetIdentities...)
	// Check every pair before creating maps or filtering already-known rows.
	for i, id := range identities {
		for _, old := range identities[:i] {
			if (id.slug == old.slug && id.repo != "" && old.repo != "" && id.repo != old.repo) || (id.repo != "" && id.repo == old.repo && id.slug != old.slug) {
				return result, errors.New("conflicting neighbour identity")
			}
		}
	}
	neighbours := cncfcheck.SubprojectNeighbours{Landscape: map[string]string{}, OtherSlugs: map[string]bool{}, OtherRepos: map[string]bool{}}
	for _, p := range landscape.Projects {
		neighbours.Landscape[p.Slug] = strings.ToLower(p.RepositoryURL)
	}
	result.InputDigests.Landscape = catalogueHash(landscapeRaw)
	result.InputDigests.Table = catalogueHash(tableRaw)
	memberRaw, err := json.Marshal(members)
	if err != nil {
		return result, err
	}
	result.InputDigests.Targets = catalogueHash(memberRaw)
	// Prove absence through a complete readable parent listing, with the
	// same descriptor and ancestry checks as present-file acquisition.
	parent, parentStable, err := catalogueOpenReadOnly(root, path.Dir(cncfcheck.SubprojectsFile), true)
	if err != nil {
		return result, err
	}
	parentEntries, listErr := parent.ReadDir(4097)
	unchanged = parentStable()
	closeErr = parent.Close()
	if (listErr != nil && listErr != io.EOF) || closeErr != nil || len(parentEntries) > 4096 || !unchanged {
		return result, errors.New("cannot establish overlay presence")
	}
	present := false
	for _, entry := range parentEntries {
		if entry.Name() == path.Base(cncfcheck.SubprojectsFile) {
			present = true
		}
	}
	if !present {
		return result, nil
	}
	overlayRaw, err := read(cncfcheck.SubprojectsFile)
	if err != nil {
		return result, err
	}
	if !parentStable() {
		return result, errors.New("overlay parent changed during read")
	}
	if err = strictjson.Check(overlayRaw); err != nil {
		return result, errors.New("ambiguous overlay JSON")
	}
	if err = catalogueRequired(overlayRaw, "schema", "rows", "rowsDigest"); err != nil {
		return result, err
	}
	// First canonical decode checks row identity/citations against the validated
	// landscape. It is not emitted until the full neighbour closure also passes.
	overlay, err := cncfcheck.LoadSubprojects(overlayRaw, neighbours)
	if err != nil {
		return result, errors.New("invalid subproject overlay")
	}
	for i, row := range overlay.Rows {
		for _, old := range overlay.Rows[:i] {
			if row.RepositoryURL == old.RepositoryURL {
				return result, errors.New("ambiguous subproject repository paths")
			}
		}
	}
	for _, id := range identities[len(landscape.Projects):] {
		exact := false
		for _, row := range overlay.Rows {
			if id.slug == row.Slug && id.repo == row.RepositoryURL {
				exact = true
				break
			}
		}
		if !exact {
			neighbours.OtherSlugs[id.slug] = true
			if id.repo != "" {
				neighbours.OtherRepos[id.repo] = true
			}
		}
	}
	if _, err = cncfcheck.LoadSubprojects(overlayRaw, neighbours); err != nil {
		return result, errors.New("subproject neighbour collision")
	}
	for _, row := range overlay.Rows {
		result.Rows = append(result.Rows, catalogueRow{row.Slug, row.Name, row.RepositoryURL, row.RepoPath, row.Parent})
	}
	digest := catalogueHash(overlayRaw)
	result.InputDigests.Overlay = &digest
	result.OverlayState = "present"
	return result, nil
}

func catalogueHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// The pinned landscape includes mixed-case paths and organization URLs.
// Preserve those shapes without accepting repository aliases as new identities.
func catalogueRepository(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "github.com" || host == "www.github.com" {
		return catalogueGitHubIdentity(raw, true)
	}
	return true
}
func catalogueGitHubIdentity(raw string, allowOrganization bool) bool {
	tail, ok := strings.CutPrefix(raw, "https://github.com/")
	if !ok {
		return false
	}
	parts := strings.Split(tail, "/")
	if len(parts) != 2 && !(allowOrganization && len(parts) == 1) {
		return false
	}
	for _, part := range parts {
		if !catalogueGitHubPart.MatchString(part) {
			return false
		}
	}
	return !strings.HasSuffix(strings.ToLower(tail), ".git")
}

var catalogueGitHubPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func catalogueDecode(raw []byte, v any) error {
	if e := strictjson.Check(raw); e != nil {
		return errors.New("ambiguous snapshot JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("invalid snapshot shape")
	}
	return nil
}
func catalogueRequired(raw []byte, keys ...string) error {
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return errors.New("invalid required object")
	}
	for _, key := range keys {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("missing required member %s", key)
		}
	}
	return nil
}
func catalogueDirectory(root *os.Root, name string) error {
	current := ""
	for _, part := range strings.Split(name, "/") {
		current = path.Join(current, part)
		info, e := root.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("snapshot parent is not a regular directory")
		}
	}
	return nil
}
func catalogueReadFile(root *os.Root, name string) ([]byte, error) {
	if e := catalogueDirectory(root, path.Dir(name)); e != nil {
		return nil, e
	}
	info, e := root.Lstat(name)
	if e != nil || !info.Mode().IsRegular() || info.Size() > catalogueMaxFile {
		return nil, errors.New("snapshot member missing, nonregular or oversized")
	}
	return catalogueReadCheckedFile(root, name, info)
}

func catalogueReadCheckedFile(root *os.Root, name string, info os.FileInfo) ([]byte, error) {
	f, stable, e := catalogueOpenReadOnly(root, name, false)
	if e != nil {
		return nil, errors.New("cannot open snapshot member")
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Size() > catalogueMaxFile || !os.SameFile(info, before) || !stable() {
		return nil, errors.New("snapshot member changed while opening")
	}
	raw, e := io.ReadAll(io.LimitReader(f, catalogueMaxFile+1))
	after, se := f.Stat()
	if e != nil || se != nil || len(raw) > catalogueMaxFile || int64(len(raw)) != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !stable() {
		return nil, errors.New("snapshot member unreadable, changed or oversized")
	}
	return raw, nil
}

// Walk from the held root descriptor. Each parent must be a directory opened
// without following links. Final acquisition is nonblocking, and descriptor
// types are checked before any reads.
func catalogueOpenReadOnly(root *os.Root, name string, directory bool) (*os.File, func() bool, error) {
	if !fs.ValidPath(name) || name == "." {
		return nil, nil, errors.New("invalid snapshot path")
	}
	current, err := root.Open(".")
	if err != nil {
		return nil, nil, errors.New("cannot open root descriptor")
	}
	type ancestor struct {
		name string
		info os.FileInfo
	}
	parents := []ancestor{}
	prefix := ""
	parts := strings.Split(name, "/")
	for i, part := range parts {
		parentInfo, e := current.Stat()
		if e != nil || !parentInfo.IsDir() {
			current.Close()
			return nil, nil, errors.New("invalid snapshot parent descriptor")
		}
		parentName := prefix
		if parentName == "" {
			parentName = "."
		}
		parents = append(parents, ancestor{parentName, parentInfo})
		flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i < len(parts)-1 || directory {
			flags |= unix.O_DIRECTORY
		}
		fd, e := unix.Openat(int(current.Fd()), part, flags, 0)
		current.Close()
		if e != nil {
			return nil, nil, errors.New("cannot acquire snapshot descriptor")
		}
		prefix = path.Join(prefix, part)
		current = os.NewFile(uintptr(fd), prefix)
	}
	actual, err := current.Stat()
	if err != nil || (directory && !actual.IsDir()) || (!directory && !actual.Mode().IsRegular()) {
		current.Close()
		return nil, nil, errors.New("snapshot descriptor has wrong type")
	}
	stable := func() bool {
		for _, parent := range parents {
			now, e := root.Lstat(parent.name)
			if e != nil || !now.IsDir() || !os.SameFile(parent.info, now) || !parent.info.ModTime().Equal(now.ModTime()) {
				return false
			}
		}
		now, e := root.Lstat(name)
		return e == nil && now.Mode().Type() == actual.Mode().Type() && os.SameFile(actual, now) && actual.Size() == now.Size() && actual.ModTime().Equal(now.ModTime())
	}
	if !stable() {
		current.Close()
		return nil, nil, errors.New("snapshot ancestry changed during open")
	}
	return current, stable, nil
}
