// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// The CNCF sub-project overlay: cited, hand-reviewed rows for repositories
// that are part of a CNCF project but are not items of the pinned landscape
// copy. This file is inert data plus a strict loader. Nothing here is wired
// into pack assembly, selection or any count: the landscape copy, its digest
// and the 255 check are untouched. The overlay file may be written only by a
// reviewed, owner-signed change; no generator, export or bot writes it.

// SubprojectsSchema is the schema of the overlay file.
const SubprojectsSchema = "prufyx.io/cncf-subprojects/v1"

// SubprojectsFile is the repository path of the overlay file.
const SubprojectsFile = "cli/internal/cncfcheck/data/cncf-subprojects.json"

// Source kinds: a governance file is the stronger source, a project README
// (the project's own literal listing) the weaker one, kept visible per row.
const (
	SourceKindGovernance = "governance"
	SourceKindReadme     = "readme"
)

// ErrSubprojectIntegrity is matched (errors.Is) by every refusal of the
// overlay. A refused overlay is refused as a whole.
var ErrSubprojectIntegrity = errors.New("cncf sub-project overlay integrity failure")

// SubprojectError is a typed refusal: Kind names the rule, Slug the row (empty
// for a file-level refusal).
type SubprojectError struct {
	Kind   string
	Slug   string
	Detail string
}

func (e *SubprojectError) Error() string {
	if e.Slug == "" {
		return fmt.Sprintf("cncf sub-project overlay: %s: %s", e.Kind, e.Detail)
	}
	return fmt.Sprintf("cncf sub-project overlay: row %q: %s: %s", e.Slug, e.Kind, e.Detail)
}

// Is makes every SubprojectError an ErrSubprojectIntegrity.
func (e *SubprojectError) Is(target error) bool { return target == ErrSubprojectIntegrity }

// Refusal kinds.
const (
	KindDecode      = "decode"
	KindSchema      = "schema"
	KindDigest      = "digest"
	KindOrder       = "order"
	KindField       = "field"
	KindParent      = "parent"
	KindRepoClash   = "repo-clash"
	KindSlugClash   = "slug-clash"
	KindCitation    = "citation"
	KindLicense     = "license"
	KindSourceKind  = "source-kind"
	KindUnsupported = "unsupported"
)

// SubprojectGovernance is the citation of one row: raw URL at the pinned
// commit, the file, the cited lines and the digest of those lines.
type SubprojectGovernance struct {
	URL        string `json:"url"`
	Commit     string `json:"commit"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	LineEnd    int    `json:"lineEnd"`
	LineSHA256 string `json:"lineSha256"`
	// EntryMarker is the literal entry line (trimmed) inside the cited
	// lines under which the repository is listed.
	EntryMarker string `json:"entryMarker"`
	// SourceKind is "governance" or "readme".
	SourceKind string `json:"sourceKind"`
}

// SubprojectLicense is the licence evidence: the raw URL of the LICENSE blob
// at LicenseCommit (on the row), the blob sha and the SPDX identifier.
type SubprojectLicense struct {
	SPDX    string `json:"spdx"`
	Source  string `json:"source"`
	BlobSHA string `json:"blobSha"`
}

// SubprojectRow is one overlay row. Every field is required except RepoPath.
type SubprojectRow struct {
	Slug          string               `json:"slug"`
	Name          string               `json:"name"`
	RepositoryURL string               `json:"repositoryURL"`
	RepoPath      string               `json:"repoPath,omitempty"`
	Parent        string               `json:"parent"`
	Governance    SubprojectGovernance `json:"governance"`
	License       SubprojectLicense    `json:"license"`
	LicenseCommit string               `json:"licenseCommit"`
}

// SubprojectOverlay is the overlay file.
type SubprojectOverlay struct {
	Schema     string          `json:"schema"`
	Rows       []SubprojectRow `json:"rows"`
	RowsDigest string          `json:"rowsDigest"`
}

// SubprojectNeighbours are the identities the overlay must not collide with:
// the landscape (slug to repository URL) and any other slug or repository the
// caller knows (table rows, existing targets).
type SubprojectNeighbours struct {
	Landscape  map[string]string
	OtherSlugs map[string]bool
	OtherRepos map[string]bool
}

var (
	subprojectRepoRE   = regexp.MustCompile(`^https://github\.com/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
	subprojectSHA1RE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	subprojectSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	subprojectSPDXRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*$`)
	subprojectPathRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)
)

// supportedSPDX is the closed set the loader and the verify tool can check.
var supportedSPDX = map[string]bool{"Apache-2.0": true}

func subprojectFail(kind, slug, format string, args ...any) error {
	return &SubprojectError{Kind: kind, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

// SubprojectsRowsDigest is the digest bound by the file: sha256 of the
// compact JSON of the rows array in struct field order.
func SubprojectsRowsDigest(rows []SubprojectRow) (string, error) {
	raw, err := json.Marshal(rows)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SubprojectsFileDigest is the digest of the file bytes (subprojectDigest);
// it is separate from the landscape catalogueDigest.
func SubprojectsFileDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// GitHubRawURL builds the raw URL of a file at a commit.
func GitHubRawURL(ownerRepo, commit, file string) string {
	return "https://raw.githubusercontent.com/" + ownerRepo + "/" + commit + "/" + file
}

// SubprojectRepoPath returns "owner/repo" of a row's repository URL.
func SubprojectRepoPath(row SubprojectRow) string {
	return strings.TrimPrefix(row.RepositoryURL, "https://github.com/")
}

// LoadSubprojects strictly decodes and checks the overlay. It is not wired
// into pack assembly; callers pass the neighbours they want to be disjoint
// from. Any failure is an ErrSubprojectIntegrity and refuses the whole file.
func LoadSubprojects(raw []byte, n SubprojectNeighbours) (*SubprojectOverlay, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var overlay SubprojectOverlay
	if err := dec.Decode(&overlay); err != nil {
		return nil, subprojectFail(KindDecode, "", "%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, subprojectFail(KindDecode, "", "trailing data after the document")
	}
	if overlay.Schema != SubprojectsSchema {
		return nil, subprojectFail(KindSchema, "", "schema %q", overlay.Schema)
	}
	if len(overlay.Rows) == 0 {
		return nil, subprojectFail(KindField, "", "no rows")
	}
	digest, err := SubprojectsRowsDigest(overlay.Rows)
	if err != nil || digest != overlay.RowsDigest {
		return nil, subprojectFail(KindDigest, "", "rowsDigest does not match the rows")
	}
	seenRepo := map[string]bool{}
	landscapeRepos := map[string]bool{}
	for _, repo := range n.Landscape {
		landscapeRepos[strings.ToLower(repo)] = true
	}
	for index := range overlay.Rows {
		row := overlay.Rows[index]
		if index > 0 && overlay.Rows[index-1].Slug >= row.Slug {
			return nil, subprojectFail(KindOrder, row.Slug, "slugs are not strictly sorted")
		}
		if err := checkSubprojectRow(row); err != nil {
			return nil, err
		}
		parentRepo, ok := n.Landscape[row.Parent]
		if !ok || parentRepo == "" {
			return nil, subprojectFail(KindParent, row.Slug, "parent %q is not in the landscape copy", row.Parent)
		}
		if _, ok := n.Landscape[row.Slug]; ok || n.OtherSlugs[row.Slug] {
			return nil, subprojectFail(KindSlugClash, row.Slug, "slug is already a landscape or table slug")
		}
		if landscapeRepos[row.RepositoryURL] || n.OtherRepos[row.RepositoryURL] || seenRepo[row.RepositoryURL+"|"+row.RepoPath] {
			return nil, subprojectFail(KindRepoClash, row.Slug, "repository %s is already known", row.RepositoryURL)
		}
		seenRepo[row.RepositoryURL+"|"+row.RepoPath] = true
	}
	return &overlay, nil
}

func checkSubprojectRow(row SubprojectRow) error {
	slug := row.Slug
	if !slugPattern.MatchString(slug) || row.Name == "" || strings.TrimSpace(row.Name) != row.Name || row.Parent == "" || !slugPattern.MatchString(row.Parent) {
		return subprojectFail(KindField, slug, "slug, name or parent is malformed")
	}
	if !subprojectRepoRE.MatchString(row.RepositoryURL) || strings.HasSuffix(row.RepositoryURL, ".git") {
		return subprojectFail(KindField, slug, "repositoryURL is not a lower-case https github.com owner/repo")
	}
	if row.RepoPath != "" && (!subprojectPathRE.MatchString(row.RepoPath) || strings.Contains(row.RepoPath, "..")) {
		return subprojectFail(KindField, slug, "repoPath is malformed")
	}
	g := row.Governance
	if !subprojectSHA1RE.MatchString(g.Commit) || !subprojectSHA256RE.MatchString(g.LineSHA256) {
		return subprojectFail(KindCitation, slug, "commit or lineSha256 is malformed")
	}
	if g.Line < 1 || g.LineEnd < g.Line || g.LineEnd-g.Line > 99 {
		return subprojectFail(KindCitation, slug, "line range %d-%d", g.Line, g.LineEnd)
	}
	if !subprojectPathRE.MatchString(g.File) || strings.Contains(g.File, "..") {
		return subprojectFail(KindCitation, slug, "file is malformed")
	}
	if g.EntryMarker == "" || strings.TrimSpace(g.EntryMarker) != g.EntryMarker || strings.ContainsAny(g.EntryMarker, "\r\n") {
		return subprojectFail(KindCitation, slug, "entryMarker is empty or not one trimmed line")
	}
	if g.SourceKind != SourceKindGovernance && g.SourceKind != SourceKindReadme {
		return subprojectFail(KindSourceKind, slug, "sourceKind %q", g.SourceKind)
	}
	if err := checkRawURL(g.URL, g.Commit, g.File); err != nil {
		return subprojectFail(KindCitation, slug, "governance url: %v", err)
	}
	if !subprojectSHA1RE.MatchString(row.LicenseCommit) || !subprojectSHA1RE.MatchString(row.License.BlobSHA) {
		return subprojectFail(KindLicense, slug, "licenseCommit or blobSha is malformed")
	}
	if !subprojectSPDXRE.MatchString(row.License.SPDX) || !supportedSPDX[row.License.SPDX] {
		return subprojectFail(KindLicense, slug, "spdx %q is not supported", row.License.SPDX)
	}
	licenseFile, err := rawURLFile(row.License.Source, SubprojectRepoPath(row), row.LicenseCommit)
	if err != nil {
		return subprojectFail(KindLicense, slug, "license source: %v", err)
	}
	if !strings.HasPrefix(strings.ToUpper(licenseFile), "LICENSE") && !strings.HasPrefix(strings.ToUpper(licenseFile), "COPYING") {
		return subprojectFail(KindLicense, slug, "license source is not a LICENSE file")
	}
	return nil
}

// checkRawURL requires the exact raw URL at a commit: https, the raw host,
// owner/repo, the commit and the file, nothing else. The owner/repo is the
// cited repository (kubernetes/community, argoproj/argoproj), not the row's.
func checkRawURL(raw, commit, file string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "raw.githubusercontent.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("not a plain https raw.githubusercontent.com URL")
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) < 4 || parts[2] != commit || strings.Join(parts[3:], "/") != file {
		return errors.New("URL does not name the commit and file")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(parts[0]) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(parts[1]) {
		return errors.New("owner or repository is malformed")
	}
	return nil
}

// rawURLFile checks a raw URL for the given owner/repo and commit and returns
// the file path.
func rawURLFile(raw, ownerRepo, commit string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "raw.githubusercontent.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("not a plain https raw.githubusercontent.com URL")
	}
	prefix := "/" + ownerRepo + "/" + commit + "/"
	if !strings.HasPrefix(parsed.Path, prefix) {
		return "", errors.New("URL does not name the row repository at licenseCommit")
	}
	file := strings.TrimPrefix(parsed.Path, prefix)
	if !subprojectPathRE.MatchString(file) {
		return "", errors.New("file is malformed")
	}
	return file, nil
}

// CitedLines returns the cited lines of a fetched file as the lines joined
// with "\n" and a trailing "\n" (what `sed -n L,Lp` prints), plus the lines.
func CitedLines(file []byte, line, lineEnd int) (string, []string, bool) {
	all := strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
	if line < 1 || lineEnd < line || lineEnd > len(all) {
		return "", nil, false
	}
	lines := all[line-1 : lineEnd]
	return strings.Join(lines, "\n") + "\n", lines, true
}

// CitedLinesDigest is the lineSha256 of the cited lines.
func CitedLinesDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// CheckCitedLines is the checkable part of a row's citation once the cited
// lines are known: the digest, the entry marker (exactly one whole line) and
// the repository listed literally on that line or after it. The offline test
// and the network tool both use it; the lines come from different places.
func CheckCitedLines(row SubprojectRow, text string, lines []string) error {
	g := row.Governance
	if CitedLinesDigest(text) != g.LineSHA256 {
		return subprojectFail(KindCitation, row.Slug, "lineSha256 does not match the cited lines")
	}
	marker := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == g.EntryMarker {
			if marker >= 0 {
				return subprojectFail(KindCitation, row.Slug, "entryMarker appears more than once in the cited lines")
			}
			marker = i
		}
	}
	if marker < 0 {
		return subprojectFail(KindCitation, row.Slug, "entryMarker is not a line of the cited range")
	}
	ownerRepo := regexp.QuoteMeta(SubprojectRepoPath(row))
	listing := regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9._-])(?:github\.com|raw\.githubusercontent\.com)/` + ownerRepo + `(?:[/)\s"'>]|$)`)
	for _, l := range lines[marker:] {
		if !listing.MatchString(l) {
			continue
		}
		if row.RepoPath != "" && !strings.Contains(l, "/"+row.RepoPath+"/") {
			continue
		}
		return nil
	}
	return subprojectFail(KindCitation, row.Slug, "repository %s is not listed literally under the entry", row.RepositoryURL)
}
