// SPDX-License-Identifier: AGPL-3.0-only

// Package providerexcerpt defines and validates the committed excerpt store
// for official provider lifecycle sources. An excerpt is a small anchored
// piece of a vendor page (table rows or one sentence) committed under
// cli/knowledge/provider-excerpts so that evidence rows cite it through the
// unchanged constraintengine.SourceEvidence shape: git revision, whole-file
// sha256, line span and an immutable github.com URL. Everything here is
// offline and fail-closed; nothing fetches.
package providerexcerpt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

const (
	ManifestSchema = "prufyx.io/provider-excerpt-manifest/v1alpha1"
	FileMagic      = "# prufyx-provider-excerpt/v1"
	// Dir is the repository-relative store directory.
	Dir = "cli/knowledge/provider-excerpts"
	// Repo is the public repository slug a citation must point at.
	Repo = "prufyx/prufyx"

	MaxExcerptBytes  = 8 * 1024
	MaxManifestBytes = 1 << 20
	MaxEntries       = 4096
	MaxBodyLines     = 64
	MaxParaphrase    = 1024

	LicencePermissive = "permissive-quote"
	LicenceUnknown    = "unknown-paraphrase"
	FormVerbatim      = "verbatim"
	FormParaphrase    = "paraphrase"
)

// ErrInvalid is wrapped by every rejection.
var ErrInvalid = errors.New("invalid provider excerpt")

func bad(format string, args ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), ErrInvalid)
}

// Entry is one manifest row.
type Entry struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Path      string `json:"path"` // relative to Dir
	SourceURL string `json:"sourceUrl"`
	FetchedAt string `json:"fetchedAt"`
	SHA256    string `json:"sha256"` // sha256:<hex> of the whole excerpt file
	Anchor    string `json:"anchor"`
	Licence   string `json:"licence"`
	Form      string `json:"form"`
}

// Manifest lists the excerpts, sorted by ID.
type Manifest struct {
	Schema  string  `json:"schema"`
	Entries []Entry `json:"entries"`
}

var (
	idRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	providerRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	anchorRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	pathRE     = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,31})/([a-z0-9][a-z0-9._-]{0,127})\.txt$`)

	// Official hosts only (design section 0). Adding a host is a code change.
	allowedHosts = map[string]bool{
		"docs.aws.amazon.com":       true,
		"cloud.google.com":          true,
		"learn.microsoft.com":       true,
		"github.com":                true,
		"raw.githubusercontent.com": true,
		"api.openshift.com":         true,
		"access.redhat.com":         true,
		"docs.openshift.com":        true,
		"docs.digitalocean.com":     true,
		"techdocs.akamai.com":       true,
		"docs.oracle.com":           true,
		"microk8s.io":               true,
		"api.snapcraft.io":          true,
		"docs.k0sproject.io":        true,
		"kubernetes.io":             true,
	}

	// Credential, cookie and tracking markers, matched case-insensitively
	// over the whole excerpt file.
	secretRE = regexp.MustCompile(`(?i)(set-cookie|\bcookie\s*[:=]|authorization\s*[:=]|\bbearer\s+[a-z0-9._~+/=-]{8,}|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password\s*[:=]|passwd|sessionid|session[_-]?id|\butm_[a-z]+|fbclid|gclid|\b_ga\b|-----BEGIN|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{20,}|\bgithub_pat_|\bxox[bap]-|[?&](token|key|sig|signature|sid)=|x-amz-signature)`)

	// Quotation and table markup is not a paraphrase.
	quoteRE = regexp.MustCompile("(?m)[\"“”‘’`|]|^\\s*>")
)

// ParseManifest strictly decodes and validates manifest bytes (no file
// access). Unknown or duplicate fields, aliases and trailing data fail.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return m, bad("manifest size")
	}
	if err := strictjson.Decode(raw, &m); err != nil {
		return Manifest{}, bad("manifest: %v", err)
	}
	if m.Schema != ManifestSchema {
		return Manifest{}, bad("manifest schema")
	}
	if len(m.Entries) > MaxEntries {
		return Manifest{}, bad("entry count")
	}
	paths := map[string]bool{}
	for i, e := range m.Entries {
		if i > 0 && m.Entries[i-1].ID >= e.ID {
			return Manifest{}, bad("entry order")
		}
		if err := validateEntry(e); err != nil {
			return Manifest{}, err
		}
		if paths[e.Path] {
			return Manifest{}, bad("duplicate path %s", e.Path)
		}
		paths[e.Path] = true
	}
	return m, nil
}

func validateEntry(e Entry) error {
	if !idRE.MatchString(e.ID) {
		return bad("entry id")
	}
	if !providerRE.MatchString(e.Provider) {
		return bad("entry %s provider", e.ID)
	}
	pm := pathRE.FindStringSubmatch(e.Path)
	if pm == nil || pm[1] != e.Provider || pm[2] != e.ID {
		return bad("entry %s path", e.ID)
	}
	if err := checkSourceURL(e.SourceURL); err != nil {
		return bad("entry %s: %v", e.ID, err)
	}
	t, err := time.Parse(time.RFC3339, e.FetchedAt)
	if err != nil || t.UTC().Format(time.RFC3339) != e.FetchedAt || t.Year() < 2020 {
		return bad("entry %s fetchedAt", e.ID)
	}
	if t.After(nowFn().Add(24 * time.Hour)) {
		return bad("entry %s: fetchedAt is in the future", e.ID)
	}
	if !digestRE.MatchString(e.SHA256) {
		return bad("entry %s sha256", e.ID)
	}
	if !anchorRE.MatchString(e.Anchor) {
		return bad("entry %s anchor", e.ID)
	}
	switch e.Licence {
	case LicencePermissive:
		if !permissiveSource(e.SourceURL) {
			return bad("entry %s: source is not on the permissive-quote list; use %s", e.ID, LicenceUnknown)
		}
		if e.Form != FormVerbatim && e.Form != FormParaphrase {
			return bad("entry %s form", e.ID)
		}
	case LicenceUnknown:
		// Unknown terms: no quotation, ever.
		if e.Form != FormParaphrase {
			return bad("entry %s: verbatim text under unknown licence", e.ID)
		}
	default:
		return bad("entry %s licence", e.ID)
	}
	return nil
}

// nowFn is the clock for the future-timestamp bound (replaced in tests).
var nowFn = time.Now

// permissiveRepos is the closed list of repositories whose content may be
// quoted verbatim (licence named in the provider design). Adding one is a code
// change. Every other source is paraphrase-only.
var permissiveRepos = map[string]bool{
	"kubernetes/website":    true,
	"kubernetes/kubernetes": true,
	"kubernetes-sigs/kind":  true,
	"k3s-io/k3s":            true,
	"rancher/rke2":          true,
}

// permissiveSource reports whether verbatim text may be stored for raw. The
// manifest licence label never decides this; the source does.
func permissiveSource(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Host {
	case "kubernetes.io":
		return true
	case "github.com", "raw.githubusercontent.com":
		parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		return len(parts) >= 3 && permissiveRepos[parts[0]+"/"+parts[1]]
	}
	return false
}

func checkSourceURL(raw string) error {
	if raw == "" || len(raw) > 2048 || strings.Contains(raw, "%") {
		return errors.New("source url")
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e {
			return errors.New("source url characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("source url shape")
	}
	if !allowedHosts[u.Host] {
		return fmt.Errorf("source host %q not allowlisted", u.Host)
	}
	if u.Path == "" || u.Path == "/" {
		return errors.New("source url path")
	}
	return nil
}

// ParseExcerpt validates one excerpt file against its entry and returns the
// 1-based first and last body line numbers (the cite-able span).
//
// File layout: FileMagic, then `key: value` header lines (source, fetchedAt,
// anchor, licence, form, pageSha256 and, for paraphrases, sentence), a line
// `---`, then the body. Every line ends in LF.
func ParseExcerpt(e Entry, data []byte) (bodyStart, bodyEnd int, err error) {
	if err := validateEntry(e); err != nil {
		return 0, 0, err
	}
	if len(data) == 0 || len(data) > MaxExcerptBytes {
		return 0, 0, bad("%s: excerpt size %d exceeds cap %d", e.ID, len(data), MaxExcerptBytes)
	}
	if !utf8.Valid(data) || data[len(data)-1] != '\n' {
		return 0, 0, bad("%s: excerpt must be UTF-8 ending in LF", e.ID)
	}
	for _, b := range data {
		if b == 0 || b == '\r' || (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f {
			return 0, 0, bad("%s: control byte in excerpt", e.ID)
		}
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != e.SHA256 {
		return 0, 0, bad("%s: excerpt does not hash to its manifest digest", e.ID)
	}
	if secretRE.Match(data) {
		return 0, 0, bad("%s: cookie, credential or tracking content", e.ID)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if lines[0] != FileMagic {
		return 0, 0, bad("%s: excerpt magic", e.ID)
	}
	hdr := map[string]string{}
	sep := -1
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			sep = i
			break
		}
		k, v, ok := strings.Cut(lines[i], ": ")
		if !ok || k == "" || v == "" || hdr[k] != "" {
			return 0, 0, bad("%s: header line %d", e.ID, i+1)
		}
		hdr[k] = v
	}
	if sep < 0 {
		return 0, 0, bad("%s: header terminator", e.ID)
	}
	allowed := map[string]bool{"source": true, "fetchedAt": true, "anchor": true, "licence": true, "form": true, "pageSha256": true, "sentence": true}
	for k := range hdr {
		if !allowed[k] {
			return 0, 0, bad("%s: header key %q", e.ID, k)
		}
	}
	if hdr["source"] != e.SourceURL || hdr["fetchedAt"] != e.FetchedAt || hdr["anchor"] != e.Anchor || hdr["licence"] != e.Licence || hdr["form"] != e.Form {
		return 0, 0, bad("%s: header disagrees with manifest", e.ID)
	}
	if !digestRE.MatchString(hdr["pageSha256"]) {
		return 0, 0, bad("%s: pageSha256", e.ID)
	}
	body := lines[sep+1:]
	if len(body) == 0 || len(body) > MaxBodyLines {
		return 0, 0, bad("%s: body must be 1..%d lines", e.ID, MaxBodyLines)
	}
	text := strings.Join(body, "\n")
	if strings.TrimSpace(text) == "" {
		return 0, 0, bad("%s: empty body", e.ID)
	}
	if e.Form == FormParaphrase {
		if !anchorRE.MatchString(hdr["sentence"]) {
			return 0, 0, bad("%s: paraphrase needs a sentence id", e.ID)
		}
		if len(text) > MaxParaphrase {
			return 0, 0, bad("%s: paraphrase too long", e.ID)
		}
		if quoteRE.MatchString(text) {
			return 0, 0, bad("%s: quotation or table markup in a paraphrase", e.ID)
		}
	} else if hdr["sentence"] != "" {
		return 0, 0, bad("%s: sentence id only for paraphrase", e.ID)
	}
	return sep + 2, len(lines), nil
}

// Reader returns the bytes of a repository-relative path at a revision.
type Reader func(revision, path string) ([]byte, error)

// GitReader reads blobs from the git object store of dir (git show). The
// revision must be a full 40-hex commit id; the content comes from the
// object database, never from the working tree.
func GitReader(dir string) Reader {
	return func(revision, path string) ([]byte, error) {
		if !revisionRE.MatchString(revision) || strings.HasPrefix(path, "-") {
			return nil, bad("revision or path")
		}
		cmd := exec.Command("git", "-C", dir, "show", revision+":"+path)
		var out, errb bytes.Buffer
		cmd.Stdout = &limitWriter{w: &out, n: MaxExcerptBytes + 1}
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			return nil, bad("git show %s:%s: %v", revision, path, err)
		}
		return out.Bytes(), nil
	}
}

type limitWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.w.Len()+len(p) > l.n {
		return 0, errors.New("excerpt over size cap")
	}
	return l.w.Write(p)
}

// VerifyAt checks every manifest entry at revision: the committed file
// exists, is within caps and re-hashes to the manifest digest.
func VerifyAt(m Manifest, revision string, read Reader) error {
	if !revisionRE.MatchString(revision) {
		return bad("revision")
	}
	for _, e := range m.Entries {
		data, err := read(revision, Dir+"/"+e.Path)
		if err != nil {
			return err
		}
		if _, _, err := ParseExcerpt(e, data); err != nil {
			return err
		}
	}
	return nil
}

// CheckSources verifies that sources cite excerpts of this store. It first
// runs the unchanged constraintengine.ValidateSources, then requires, per
// source: a github.com or raw.githubusercontent.com URL for this repository
// and Dir at the cited revision, a manifest entry for that path, the cited
// digest equal to the manifest digest, the file at the revision hashing to
// it, and the cited span inside the excerpt body.
func CheckSources(m Manifest, sources []constraintengine.SourceEvidence, read Reader) error {
	return CheckSourcesAt(m, sources, read, nil)
}

// CommitTimer returns the commit time of a revision.
type CommitTimer func(revision string) (time.Time, error)

// GitCommitTime reads commit times from the git object store of dir.
func GitCommitTime(dir string) CommitTimer {
	return func(revision string) (time.Time, error) {
		if !revisionRE.MatchString(revision) {
			return time.Time{}, bad("revision")
		}
		out, err := exec.Command("git", "-C", dir, "show", "-s", "--format=%ct", revision).Output()
		if err != nil {
			return time.Time{}, bad("commit time %s: %v", revision, err)
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return time.Time{}, bad("commit time %s", revision)
		}
		return time.Unix(n, 0).UTC(), nil
	}
}

// CheckSourcesAt is CheckSources plus, when commitTime is non-nil, a refusal
// of any entry fetched after the citing commit (fail-closed on lookup error).
func CheckSourcesAt(m Manifest, sources []constraintengine.SourceEvidence, read Reader, commitTime CommitTimer) error {
	if err := constraintengine.ValidateSources(sources); err != nil {
		return bad("sources: %v", err)
	}
	byPath := map[string]Entry{}
	for _, e := range m.Entries {
		byPath[e.Path] = e
	}
	for _, s := range sources {
		path, err := excerptPathFromURL(s.URL, s.Revision)
		if err != nil {
			return bad("source %s: %v", s.ID, err)
		}
		e, ok := byPath[path]
		if !ok {
			return bad("source %s: %s is not in the manifest", s.ID, path)
		}
		if s.ContentDigest != e.SHA256 {
			return bad("source %s: digest differs from the manifest", s.ID)
		}
		if commitTime != nil {
			ct, err := commitTime(s.Revision)
			if err != nil {
				return err
			}
			ft, perr := time.Parse(time.RFC3339, e.FetchedAt)
			if perr != nil || ft.After(ct) {
				return bad("source %s: fetchedAt is after the citing commit", s.ID)
			}
		}
		data, err := read(s.Revision, Dir+"/"+path)
		if err != nil {
			return err
		}
		start, end, err := ParseExcerpt(e, data)
		if err != nil {
			return err
		}
		if s.StartLine < start || s.EndLine > end {
			return bad("source %s: span %d-%d outside the excerpt body %d-%d", s.ID, s.StartLine, s.EndLine, start, end)
		}
	}
	return nil
}

func excerptPathFromURL(raw, revision string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("url")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	prefix := strings.Split(Repo, "/")
	if len(parts) < 3 || parts[0] != prefix[0] || parts[1] != prefix[1] {
		return "", errors.New("url is not this repository")
	}
	switch u.Host {
	case "github.com":
		if len(parts) < 4 || parts[2] != "blob" || parts[3] != revision {
			return "", errors.New("url revision")
		}
		parts = parts[4:]
	case "raw.githubusercontent.com":
		if parts[2] != revision {
			return "", errors.New("url revision")
		}
		parts = parts[3:]
	default:
		return "", errors.New("url host")
	}
	dir := strings.Split(Dir, "/")
	if len(parts) != len(dir)+2 {
		return "", errors.New("url is not an excerpt path")
	}
	for i, d := range dir {
		if parts[i] != d {
			return "", errors.New("url is not under the excerpt directory")
		}
	}
	rel := strings.Join(parts[len(dir):], "/")
	if !pathRE.MatchString(rel) {
		return "", errors.New("excerpt path")
	}
	return rel, nil
}

// VerifyTree checks a checked-out store directory (the one holding
// manifest.json): the manifest parses, every entry file is present and valid,
// and nothing else is stored (no unlisted file, symlink or directory other
// than provider directories).
// requireRegular Lstat-checks p: it must be a regular file (absent allowed
// only when required is false).
func requireRegular(p string, required bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		if !required && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	return nil
}

func VerifyTree(root string) (Manifest, error) {
	if err := requireRegular(filepath.Join(root, "manifest.json"), true); err != nil {
		return Manifest{}, bad("manifest: %v", err)
	}
	if err := requireRegular(filepath.Join(root, "README.md"), false); err != nil {
		return Manifest{}, bad("README.md: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return Manifest{}, bad("manifest: %v", err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return Manifest{}, err
	}
	listed := map[string]bool{}
	for _, e := range m.Entries {
		listed[e.Path] = true
		fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(e.Path)))
		if err != nil || !fi.Mode().IsRegular() {
			return Manifest{}, bad("%s: file missing or not regular", e.ID)
		}
		if fi.Size() > MaxExcerptBytes {
			return Manifest{}, bad("%s: excerpt over size cap", e.ID)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(e.Path)))
		if err != nil {
			return Manifest{}, bad("%s: %v", e.ID, err)
		}
		if _, _, err := ParseExcerpt(e, data); err != nil {
			return Manifest{}, err
		}
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == "manifest.json" || rel == "README.md" {
			return nil
		}
		if d.IsDir() {
			if !providerRE.MatchString(rel) {
				return bad("unexpected directory %s", rel)
			}
			return nil
		}
		if !listed[rel] {
			return bad("file %s is not in the manifest", rel)
		}
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	return m, nil
}
