// SPDX-License-Identifier: AGPL-3.0-only

package contribution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxPacketBytes = 256 << 10

var shaRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var slugRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var semverRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)

type ValidateOptions struct{ PacketPath, LandscapePath string }
type ScaffoldOptions struct{ Kind, ProjectSlug, DisplayName, Repository, CurrentVersion, ProposedVersion, TargetVersion, Operation, Output string }
type RunOptions struct {
	Mode                               string
	Validate                           ValidateOptions
	Scaffold                           ScaffoldOptions
	CandidatesDirectory, LandscapePath string
	Import                             ImportOptions
	SourceRoot                         string
}

func Run(o RunOptions) ([]byte, error) {
	switch o.Mode {
	case "validate":
		return Validate(o.Validate)
	case "scaffold":
		return nil, Scaffold(o.Scaffold)
	case "candidates":
		return ValidateCandidates(o.CandidatesDirectory, o.LandscapePath)
	case "verify-sources":
		return VerifySources(o.Validate, o.SourceRoot)
	case "import-selected-sources":
		return nil, ImportSelectedSourceRecords(o.Import)
	default:
		return nil, ErrRejected
	}
}

func Validate(opts ValidateOptions) ([]byte, error) {
	raw, e := safeRead(opts.PacketPath, MaxPacketBytes)
	if e != nil {
		return nil, e
	}
	p, e := decode(raw, MaxPacketBytes)
	if e != nil {
		return nil, e
	}
	receipt, e := ValidatePacket(p, opts.LandscapePath)
	if e != nil {
		return nil, e
	}
	return canonical(receipt, true)
}

func ValidatePacket(value any, landscapePath string) (map[string]any, error) {
	p, ok := value.(map[string]any)
	if !ok {
		return nil, ErrRejected
	}
	schema, _ := p["schema"].(string)
	if schema != "prufyx.io/upstream-evidence-packet/v1" && schema != "prufyx.io/upstream-evidence-packet/v2" {
		return nil, ErrRejected
	}
	want := []string{"schema", "submission", "project", "tagBindings", "sources", "declaration", "limitations", "review", "attribution"}
	if schema[len(schema)-2:] == "v1" {
		want = append(want, "transition")
	} else {
		want = append(want, "target")
	}
	if _, e := object(p, want...); e != nil {
		return nil, e
	}
	sub, e := object(p["submission"], "kind")
	if e != nil {
		return nil, e
	}
	kind, e := stringField(sub, "kind", 64)
	if e != nil {
		return nil, e
	}
	project, e := object(p["project"], "slug", "displayName", "canonicalRepositoryURL")
	if e != nil {
		return nil, e
	}
	slug, e := stringField(project, "slug", 80)
	if e != nil || !slugRE.MatchString(slug) {
		return nil, ErrRejected
	}
	repo, e := stringField(project, "canonicalRepositoryURL", 256)
	if e != nil || !githubRepo(repo) {
		return nil, ErrRejected
	}
	if _, e = stringField(project, "displayName", 120); e != nil {
		return nil, e
	}
	var versions = map[string]bool{}
	var landscapeDigest any = nil
	if schema == "prufyx.io/upstream-evidence-packet/v1" {
		if kind != "new_catalogue_identity_proposal" && kind != "existing_project_transition" {
			return nil, ErrRejected
		}
		if kind == "existing_project_transition" {
			tr, e := object(p["transition"], "currentVersion", "proposedVersion")
			if e != nil {
				return nil, e
			}
			for _, k := range []string{"currentVersion", "proposedVersion"} {
				s, e := stringField(tr, k, 24)
				if e != nil || !semverRE.MatchString(s) {
					return nil, ErrRejected
				}
				versions[s] = true
			}
			if len(versions) != 2 {
				return nil, ErrRejected
			}
			lr, e := safeRead(landscapePath, 4<<20)
			if e != nil {
				return nil, e
			}
			if _, e = decode(lr, 4<<20); e != nil {
				return nil, e
			}
			if !landscapeMatches(lr, slug, repo) {
				return nil, ErrRejected
			}
			landscapeDigest = digest(lr)
		} else if p["transition"] != nil {
			return nil, ErrRejected
		}
	} else {
		if kind != "existing_project_target_preflight" || slug != "tikv" || project["displayName"] != "TiKV" || repo != "https://github.com/tikv/tikv" {
			return nil, ErrRejected
		}
		target, e := object(p["target"], "targetVersion", "operation")
		if e != nil {
			return nil, e
		}
		v, _ := target["targetVersion"].(string)
		op, _ := target["operation"].(string)
		if v != "8.5.8" || op != "gcs-full-backup-wif" {
			return nil, ErrRejected
		}
		versions[v] = true
		lr, e := safeRead(landscapePath, 4<<20)
		if e != nil {
			return nil, ErrRejected
		}
		if _, e = decode(lr, 4<<20); e != nil || !landscapeMatches(lr, "tikv", repo) {
			return nil, ErrRejected
		}
		landscapeDigest = digest(lr)
	}
	bindings, ok := p["tagBindings"].([]any)
	if !ok || len(bindings) > 4 {
		return nil, ErrRejected
	}
	if kind == "existing_project_transition" && len(bindings) != 2 {
		return nil, ErrRejected
	}
	if kind == "new_catalogue_identity_proposal" && len(bindings) != 0 {
		return nil, ErrRejected
	}
	if kind == "existing_project_target_preflight" && len(bindings) != 1 {
		return nil, ErrRejected
	}
	commits := map[string]string{}
	tags := map[string]bool{}
	for _, x := range bindings {
		b, e := object(x, "version", "tag", "commit", "assertion")
		if e != nil {
			return nil, e
		}
		v, _ := b["version"].(string)
		c, _ := b["commit"].(string)
		a, _ := b["assertion"].(string)
		tag, _ := b["tag"].(string)
		if !versions[v] || !commitRE.MatchString(c) || a != "DECLARED_UNVERIFIED" || !validTag(tag) || tags[tag] {
			return nil, ErrRejected
		}
		if _, dup := commits[v]; dup {
			return nil, ErrRejected
		}
		commits[v] = c
		tags[tag] = true
	}
	if len(commits) != len(versions) {
		return nil, ErrRejected
	}
	if kind == "existing_project_target_preflight" && (commits["8.5.8"] != "3f446cfa9eb1d5c653031d261e185911495d0359" || !tags["v8.5.8"]) {
		return nil, ErrRejected
	}
	sources, ok := p["sources"].([]any)
	if !ok || len(sources) == 0 || len(sources) > 8 {
		return nil, ErrRejected
	}
	ids := map[string]bool{}
	ordinaryVersions := map[string]bool{}
	kubeflowGuides := 0
	roles := map[string]bool{}
	for _, x := range sources {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, ErrRejected
		}
		if schema == "prufyx.io/upstream-evidence-packet/v1" {
			if _, e := object(m, "id", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "spans"); e != nil {
				return nil, e
			}
		} else {
			if _, e := object(m, "id", "evidenceRole", "sourceKind", "targetVersion", "commit", "immutableURL", "fileDigest", "spans"); e != nil {
				return nil, e
			}
		}
		id, _ := m["id"].(string)
		fd, _ := m["fileDigest"].(string)
		c, _ := m["commit"].(string)
		u, _ := m["immutableURL"].(string)
		sp, ok := m["spans"].([]any)
		if !slugRE.MatchString(id) || ids[id] || !shaRE.MatchString(fd) || !commitRE.MatchString(c) || !ok || len(sp) == 0 || len(sp) > 8 || !immutableURL(u, c) {
			return nil, ErrRejected
		}
		ids[id] = true
		if schema == "prufyx.io/upstream-evidence-packet/v1" {
			sourceKind, _ := m["sourceKind"].(string)
			if !oneOf(sourceKind, "changelog", "release_note", "migration_guide", "source_code", "helm_chart", "repository_metadata") {
				return nil, ErrRejected
			}
			version, _ := m["version"].(string)
			if kind == "new_catalogue_identity_proposal" {
				if version != "identity" || !strings.HasPrefix(u, repo+"/blob/"+c+"/") {
					return nil, ErrRejected
				}
			} else if !versions[version] {
				return nil, ErrRejected
			}
			guide := slug == "kubeflow" && repo == "https://github.com/kubeflow/pipelines" && sourceKind == "migration_guide" && version == "2.0.0" && c == "debcbb9035e75869e9dc2ed6b9354376ac1a26e7" && u == "https://github.com/kubeflow/website/blob/debcbb9035e75869e9dc2ed6b9354376ac1a26e7/content/en/docs/components/pipelines/user-guides/migration.md"
			if guide {
				kubeflowGuides++
				if kubeflowGuides > 1 {
					return nil, ErrRejected
				}
			} else if kind == "existing_project_transition" {
				ordinaryVersions[version] = true
				if commits[version] != c {
					return nil, ErrRejected
				}
				if !strings.HasPrefix(u, repo+"/blob/"+c+"/") {
					return nil, ErrRejected
				}
			}
		} else {
			if len(sources) != 3 {
				return nil, ErrRejected
			}
			role, _ := m["evidenceRole"].(string)
			if roles[role] {
				return nil, ErrRejected
			}
			roles[role] = true
			targetVersion, _ := m["targetVersion"].(string)
			sourceKind, _ := m["sourceKind"].(string)
			expectedRepo, path, expectedCommit, expectedKind, ok := v2Source(role, c)
			if !ok || targetVersion != "8.5.8" || sourceKind != expectedKind || c != expectedCommit || !strings.HasPrefix(u, expectedRepo+"/blob/"+c+"/") || !strings.HasSuffix(u, "/"+path) {
				return nil, ErrRejected
			}
		}
		priorEnd := 0
		for _, sv := range sp {
			s, ok := sv.(map[string]any)
			if !ok {
				return nil, ErrRejected
			}
			if _, e := object(s, "startLine", "endLine", "excerpt"); e != nil {
				return nil, ErrRejected
			}
			start, ok1 := numberInt(s["startLine"])
			end, ok2 := numberInt(s["endLine"])
			excerpt, ok3 := s["excerpt"].(string)
			if !ok1 || !ok2 || !ok3 || start < 1 || end < start || end > 1_000_000 || start <= priorEnd || !validExcerpt(excerpt, start, end) {
				return nil, ErrRejected
			}
			priorEnd = end
		}
	}
	if kubeflowGuides > 0 && len(ordinaryVersions) != len(versions) {
		return nil, ErrRejected
	}
	if schema == "prufyx.io/upstream-evidence-packet/v2" && (!roles["target_setting_declaration"] || !roles["target_full_backup_caller"] || !roles["operator_action_guidance"]) {
		return nil, ErrRejected
	}
	decl, e := object(p["declaration"], "statement", "proofStatus")
	if e != nil {
		return nil, e
	}
	if _, e = stringField(decl, "statement", 1200); e != nil {
		return nil, e
	}
	if decl["proofStatus"] != "DECLARED_NOT_VERIFIED" {
		return nil, ErrRejected
	}
	limits, ok := p["limitations"].([]any)
	if !ok || len(limits) == 0 || len(limits) > 8 {
		return nil, ErrRejected
	}
	seenLimits := map[string]bool{}
	for _, v := range limits {
		s, ok := v.(string)
		if !ok || !validPlainText(s, 500) || seenLimits[s] {
			return nil, ErrRejected
		}
		seenLimits[s] = true
	}
	review, e := object(p["review"], "state", "claimedReviewer")
	if e != nil || review["state"] != "NOT_REVIEWED" {
		return nil, ErrRejected
	}
	reviewer, e := object(review["claimedReviewer"], "kind", "identity")
	if e != nil {
		return nil, e
	}
	rk, _ := reviewer["kind"].(string)
	ri, _ := reviewer["identity"].(string)
	if !oneOf(rk, "agent", "human") || !validIdentity(ri) {
		return nil, ErrRejected
	}
	attr, e := object(p["attribution"], "licenseAssertion", "attribution")
	if e != nil {
		return nil, e
	}
	if _, e = stringField(attr, "attribution", 500); e != nil {
		return nil, e
	}
	license, _ := attr["licenseAssertion"].(string)
	if !oneOf(license, "DECLARED_UNKNOWN", "DECLARED_PERMISSIVE", "DECLARED_RESTRICTED") {
		return nil, ErrRejected
	}
	canon, e := canonical(p, false)
	if e != nil {
		return nil, e
	}
	return map[string]any{"schema": "prufyx.io/upstream-evidence-receipt/v1", "packetDigest": digest(canon), "landscapeDigest": landscapeDigest, "submissionKind": kind, "consistency": "VALID", "workflowState": "CANDIDATE", "limitations": []any{"local consistency only; upstream identity, tag bindings, source bytes, hashes, and spans are unverified", "declared reviewer and attribution fields are not authentication, independent review, approval, publication, or evaluator authority"}}, nil
}

func validExcerpt(value string, start, end int) bool {
	if value == "" || utf8.RuneCountInString(value) > 1200 || strings.ContainsRune(value, '\r') {
		return false
	}
	lines := strings.Split(value, "\n")
	if len(lines) != end-start+1 {
		return false
	}
	for _, line := range lines {
		if utf8.RuneCountInString(line) > 1200 {
			return false
		}
		for _, r := range line {
			if r == 0x7f || r < 0x20 && r != '\t' || r >= 0xd800 && r <= 0xdfff {
				return false
			}
		}
	}
	return true
}

func Scaffold(o ScaffoldOptions) error {
	if !slugRE.MatchString(o.ProjectSlug) || !githubRepo(o.Repository) || o.Output == "" {
		return ErrRejected
	}
	var p map[string]any
	if o.Kind == "existing_project_target_preflight" {
		if o.ProjectSlug != "tikv" || o.DisplayName != "TiKV" || o.Repository != "https://github.com/tikv/tikv" || o.TargetVersion != "8.5.8" || o.Operation != "gcs-full-backup-wif" {
			return ErrRejected
		}
		p = map[string]any{"schema": "prufyx.io/upstream-evidence-packet/v2", "submission": map[string]any{"kind": o.Kind}, "project": map[string]any{"slug": o.ProjectSlug, "displayName": o.DisplayName, "canonicalRepositoryURL": o.Repository}, "target": map[string]any{"targetVersion": o.TargetVersion, "operation": o.Operation}, "tagBindings": []any{}, "sources": []any{}, "declaration": map[string]any{"statement": nil, "proofStatus": nil}, "limitations": []any{}, "review": map[string]any{"state": "NOT_REVIEWED", "claimedReviewer": map[string]any{"kind": nil, "identity": nil}}, "attribution": map[string]any{"licenseAssertion": nil, "attribution": nil}}
	} else if o.Kind == "existing_project_transition" || o.Kind == "new_catalogue_identity_proposal" {
		var transition any = nil
		if o.TargetVersion != "" || o.Operation != "" {
			return ErrRejected
		}
		if o.Kind == "existing_project_transition" {
			if !semverRE.MatchString(o.CurrentVersion) || !semverRE.MatchString(o.ProposedVersion) || o.CurrentVersion == o.ProposedVersion {
				return ErrRejected
			}
			transition = map[string]any{"currentVersion": o.CurrentVersion, "proposedVersion": o.ProposedVersion}
		} else if o.CurrentVersion != "" || o.ProposedVersion != "" {
			return ErrRejected
		}
		p = map[string]any{"schema": "prufyx.io/upstream-evidence-packet/v1", "submission": map[string]any{"kind": o.Kind}, "project": map[string]any{"slug": o.ProjectSlug, "displayName": o.DisplayName, "canonicalRepositoryURL": o.Repository}, "transition": transition, "tagBindings": []any{}, "sources": []any{}, "declaration": map[string]any{"statement": nil, "proofStatus": nil}, "limitations": []any{}, "review": map[string]any{"state": "NOT_REVIEWED", "claimedReviewer": map[string]any{"kind": nil, "identity": nil}}, "attribution": map[string]any{"licenseAssertion": nil, "attribution": nil}}
	} else {
		return ErrRejected
	}
	raw, e := canonical(p, true)
	if e != nil {
		return e
	}
	parent := filepath.Dir(o.Output)
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrRejected
	}
	absParent, e := filepath.Abs(parent)
	if e != nil {
		return ErrRejected
	}
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil {
		return ErrRejected
	}
	resolvedAbs, e := filepath.Abs(resolved)
	if e != nil || resolvedAbs != absParent {
		return ErrRejected
	}
	f, e := os.OpenFile(o.Output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrRejected
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		os.Remove(o.Output)
		return ErrRejected
	}
	return f.Close()
}
func numberInt(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	var i int
	_, e := fmt.Sscan(n.String(), &i)
	return i, e == nil
}
func githubRepo(s string) bool {
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Host != "github.com" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	p := strings.Split(strings.Trim(u.Path, "/"), "/")
	return len(p) == 2 && p[0] != "" && p[1] != "" && !strings.HasSuffix(strings.ToLower(p[1]), ".git")
}
func immutableURL(s, c string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.User == nil && u.Host == "github.com" && u.RawQuery == "" && u.Fragment == "" && strings.Contains(u.Path, "/blob/"+c+"/")
}
func oneOf(value string, allowed ...string) bool {
	for _, x := range allowed {
		if value == x {
			return true
		}
	}
	return false
}
func validTag(tag string) bool {
	if tag == "" || len(tag) > 128 || strings.HasPrefix(tag, "/") || strings.HasSuffix(tag, "/") || strings.HasSuffix(tag, ".") || strings.Contains(tag, "..") {
		return false
	}
	for _, p := range strings.Split(tag, "/") {
		if p == "" || strings.HasSuffix(p, ".lock") || !regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$`).MatchString(p) {
			return false
		}
	}
	return true
}
func validIdentity(s string) bool {
	return len(s) > 0 && len(s) <= 128 && regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:@/-]{0,127}$`).MatchString(s)
}
func v2Source(role, commit string) (string, string, string, string, bool) {
	switch role {
	case "target_setting_declaration":
		return "https://github.com/tikv/tikv", "src/config/mod.rs", "3f446cfa9eb1d5c653031d261e185911495d0359", "source_code", true
	case "target_full_backup_caller":
		return "https://github.com/tikv/tikv", "components/backup/src/endpoint.rs", "3f446cfa9eb1d5c653031d261e185911495d0359", "source_code", true
	case "operator_action_guidance":
		return "https://github.com/pingcap/docs", "tikv-configuration-file.md", commit, "repository_metadata", true
	}
	return "", "", "", "", false
}
func landscapeMatches(raw []byte, slug, repo string) bool {
	var data struct {
		Projects []struct {
			Slug          string  `json:"slug"`
			RepositoryURL *string `json:"repositoryURL"`
		} `json:"projects"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return false
	}
	for _, p := range data.Projects {
		if p.Slug == slug && p.RepositoryURL != nil {
			est := *p.RepositoryURL
			return repo == est || (slug == "buildpacks" && est == "https://github.com/buildpacks/pack" && repo == "https://github.com/buildpacks/lifecycle") || (slug == "kubeflow" && est == "https://github.com/kubeflow/kubeflow" && repo == "https://github.com/kubeflow/pipelines")
		}
	}
	return false
}
func sortedKeys(m map[string]any) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

var _ = bytes.Compare
