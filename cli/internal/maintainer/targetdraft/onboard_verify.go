// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1; used only to bind tree bytes to the raw diff, never as a security hash
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/pathset"
)

// Onboarding verifier: the library entry that judges ONE onboarding change (a
// batch of new projects) from the authenticated raw diff and two read-only
// trees. It is the in-process source of the verify-pr result the onboarding
// admission consumes; there is no external result input anywhere.
//
// It is pure except for the injected upstream runner (binding.go): no file, no
// environment variable, no clock, no write. The network runs last, only after
// every local check of every project passed.
//
// What it owns (and what it leaves to the admission checker):
//   - the changed-path set: exactly the onboarding set, every path classified,
//     any refused, unknown or trust path is a failure;
//   - per project: absent from the base (recipe directory, real target, table
//     row, any casing), the recipe regenerates the real target, report, table
//     row and changelog byte for byte (the same check verify-pr runs), no
//     exclusions, and the upstream tags resolve to the recipe commits (B1);
//   - the digests of the full changed set and of the subset it judged.
//
// S2 requirements (the gate seam that calls this):
//   - the trees, the raw diff and both commit ids must come from the exact
//     SHAs in ONE gate step: this verifier binds only the diffed paths to the
//     diff (blob ids) and cannot prove the trees match the commit ids
//     elsewhere;
//   - the admission checker ignores JudgedPathsSHA256 and TagsCommitsSHA: the
//     table content is covered only by the signed batch table digest, so the
//     gate must compute that digest from the HEAD tree;
//   - the policy must carry a non-empty TrustPaths list (refused here when
//     empty).
//
// Left to the admission checker: the batch signature, keyset, principals, the
// table and registry digests and exclusion deltas, repository-level generated
// outputs, and the commit provenance.

const (
	// OnboardingVerifyMode is the constant provenance of this source.
	OnboardingVerifyMode = "inprocess"
	// MaxOnboardingSlugs bounds the projects of one batch.
	MaxOnboardingSlugs = 15

	onbBindingHeader     = "prufyx.io/onboarding-binding/v1\n"
	onbTagsCommitsHeader = "prufyx.io/onboarding-tags-commits/v1\n"
	maxTreeEntries       = 500000
)

// Typed reasons of the onboarding verifier (the codes of the shared recipe
// check, such as exclusion-present, bundle-digest or target-differs, and the
// binding codes, binding-*, are reported as they are).
const (
	OnbReasonInput          = "input-invalid"
	OnbReasonSlugList       = "slug-list-invalid"
	OnbReasonPolicy         = "policy-invalid"
	OnbReasonPathSet        = "path-set-invalid"
	OnbReasonOutside        = "path-outside-allowlist"
	OnbReasonTrust          = "trust-path-touched"
	OnbReasonForbidden      = "forbidden-path-touched"
	OnbReasonRequired       = "required-path-missing"
	OnbReasonSlugSet        = "slug-set-mismatch"
	OnbReasonTreeUnreadable = "tree-unreadable"
	OnbReasonTreeDiff       = "diff-tree-mismatch"
	OnbReasonBasePresent    = "slug-present-in-base"
	OnbReasonBaseUnknown    = "base-absence-unknown"
	OnbReasonHeadTable      = "head-table-row-missing"
	OnbReasonHeadExtra      = "head-recipe-file-not-in-diff"
	OnbReasonNoRunner       = "binding-unavailable"
	OnbReasonFactCollision  = "fact-project-collision"
	OnbReasonRepoCovered    = "repo-already-covered-in-base"
	OnbReasonRepoUnparsable = "repo-identity-unparsable"
	OnbReasonHeadTarget     = "head-target-undecodable"
)

var onbSlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// OnboardingPolicy names the exact non-project files of an onboarding change
// and the trust paths. It mirrors the admission checker's allowlist
// (static files, the batch file) but is stricter: the batch file, the table
// and every Required file MUST be in the change, and every path of a project
// is one of a fixed set of names.
type OnboardingPolicy struct {
	// BatchPath is the exact path of the onboarding batch file; it must be
	// ADDED by the change.
	BatchPath string
	// TablePath is the reviewed table file; it must be in the change.
	TablePath string
	// Required are further exact files that must be in the change
	// (regenerated outputs that always move). Optional are exact files that
	// may be. No entry may lie below the recipe or target directories.
	Required []string
	Optional []string
	// TrustPaths: an entry ending in "/" is a prefix, any other is one exact
	// file. A change to one is refused whatever else allows it.
	TrustPaths []string
}

// OnboardingVerifyInput is one check. Base and Head are read-only trees of the
// two commits; ChangedRaw is the output of
// `git diff --raw -z --no-abbrev --no-renames BASE HEAD`, captured ONCE by the
// caller and used for every digest here (and by the caller for its own).
type OnboardingVerifyInput struct {
	Base, Head Tree
	ChangedRaw []byte
	// Slugs are the expected projects (the batch's), at most
	// MaxOnboardingSlugs.
	Slugs  []string
	Policy OnboardingPolicy
	// BaseSHA and HeadSHA are the two commits the trees and the diff come
	// from (40 lowercase hex, different).
	BaseSHA, HeadSHA string
	// Upstream runs the B1 binding; nil means no binding and a failure.
	Upstream LsRemoteRunner
	Sleep    func(time.Duration)
	Ctx      context.Context
}

// OnboardingVerifyResult is the verify-pr style result. On any failure only
// Mode, Outcome "fail", Reasons, Details, Harness and the commit ids are set.
// Eligible is always false: a new onboarding is never the "unchanged" class,
// and nothing here is merge authority.
type OnboardingVerifyResult struct {
	Mode    string
	Outcome string // pass | fail
	Reasons []string
	Details []string
	// Harness is true when a failure was an I/O or no-verdict error rather
	// than an assertion.
	Harness bool

	BaseSHA string
	HeadSHA string

	BindingVerified    bool
	RecipeChange       string // "new" on pass
	Eligible           bool
	ChangedPathsSHA256 string // pathset.Digest of the FULL changed set
	JudgedPathsSHA256  string // pathset.Digest of the subset judged here
	Slugs              []string
	BindingDigest      string
	TagsCommitsSHA     map[string]string
}

// VerifyOnboarding judges one onboarding change. See the package comment above.
func VerifyOnboarding(in OnboardingVerifyInput) OnboardingVerifyResult {
	return verifyOnboarding(in, defaultVerifyEnv())
}

type onbRun struct {
	reasons map[string]bool
	details []string
	harness bool
}

func (r *onbRun) add(code string) { r.reasons[code] = true }

func (r *onbRun) addDetail(code, slug, detail string) {
	r.reasons[code] = true
	s := code
	if slug != "" {
		s = slug + ": " + code
	}
	if detail != "" {
		s += ": " + detail
	}
	r.details = append(r.details, clip(s))
}

func (r *onbRun) addFailure(slug string, f *VerifyFailure) {
	r.addDetail(f.Code, slug, f.Detail)
	if f.Harness {
		r.harness = true
	}
}

func (r *onbRun) addHarness(code, slug, detail string) {
	r.addDetail(code, slug, detail)
	r.harness = true
}

func (r *onbRun) failed() bool { return len(r.reasons) != 0 }

func (r *onbRun) fail(in OnboardingVerifyInput) OnboardingVerifyResult {
	out := OnboardingVerifyResult{Mode: OnboardingVerifyMode, Outcome: "fail", Harness: r.harness}
	if sha1HexRE.MatchString(in.BaseSHA) {
		out.BaseSHA = in.BaseSHA
	}
	if sha1HexRE.MatchString(in.HeadSHA) {
		out.HeadSHA = in.HeadSHA
	}
	out.Reasons = make([]string, 0, len(r.reasons))
	for c := range r.reasons {
		out.Reasons = append(out.Reasons, c)
	}
	sort.Strings(out.Reasons)
	out.Details = append([]string(nil), r.details...)
	sort.Strings(out.Details)
	if len(out.Reasons) == 0 {
		// Unreachable: a failure always has a reason. Never an empty one.
		out.Reasons = []string{OnbReasonInput}
	}
	return out
}

// onbCleanPath is the admission checker's plain-path rule.
func onbCleanPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.Contains(p, "\\") || strings.ContainsAny(p, "\x00\n\r") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func onbForbiddenPath(p string) bool {
	lower := strings.ToLower(p)
	base := lower[strings.LastIndex(lower, "/")+1:]
	return strings.HasPrefix(lower, ".github/") || base == "codeowners"
}

func onbTrustPath(p string, trust []string) bool {
	for _, t := range trust {
		if strings.HasSuffix(t, "/") && strings.HasPrefix(p, t) || p == t {
			return true
		}
	}
	name := strings.ToLower(path.Base(p))
	return strings.HasPrefix(name, "trust-root") || strings.Contains(name, "approval-keys")
}

func gitBlobSHA(b []byte) string {
	h := sha1.New() //nolint:gosec // see the import
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Prefixed(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// recipeRequired are the project files that must be in every onboarding change
// (rules.json is the optional one; the recipe decides).
var recipeRequired = []string{"recipe.json", "facts.bundle", "report.json", "table-row.json", "changelog.md"}

// treeView is the read-only, cached view of a Tree as recipeFiles.
type treeView struct {
	t     Tree
	files map[string]bool // path -> is a link
	cache map[string][]byte
}

func newTreeView(t Tree) (*treeView, *VerifyFailure) {
	ents, err := t.Entries()
	if err != nil {
		return nil, harness(OnbReasonTreeUnreadable, "entries: %v", err)
	}
	if len(ents) > maxTreeEntries {
		return nil, harness(OnbReasonTreeUnreadable, "tree has over %d entries", maxTreeEntries)
	}
	v := &treeView{t: t, files: make(map[string]bool, len(ents)), cache: map[string][]byte{}}
	for _, e := range ents {
		if _, dup := v.files[e.Path]; dup {
			return nil, harness(OnbReasonTreeUnreadable, "entry %q listed twice", e.Path)
		}
		v.files[e.Path] = e.IsLink
	}
	return v, nil
}

func (v *treeView) has(rel string) bool {
	link, ok := v.files[rel]
	return ok && !link
}

func (v *treeView) read(rel string, limit int64) ([]byte, *VerifyFailure) {
	link, ok := v.files[rel]
	if !ok {
		return nil, fail("file-missing", "%s", rel)
	}
	if link {
		return nil, fail("file-unreadable", "%s is a symbolic link", rel)
	}
	b, cached := v.cache[rel]
	if !cached {
		var err error
		if b, err = v.t.Read(rel); err != nil {
			return nil, harness("file-unreadable", "%s: %v", rel, err)
		}
		v.cache[rel] = b
	}
	if int64(len(b)) > limit {
		return nil, fail("file-unreadable", "%s is over %d bytes", rel, limit)
	}
	return b, nil
}

func (v *treeView) under(prefix string) []string {
	var out []string
	for p := range v.files {
		if strings.HasPrefix(p, prefix) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// optStr is an optional JSON string: absent is fine, but a present value that
// is not a string (null, number, array, object) is a decode error, never a
// skipped field.
type optStr string

func (o *optStr) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || string(bytes.TrimSpace(b)) == "null" {
		return errors.New("field is not a string")
	}
	*o = optStr(s)
	return nil
}

// onbRow is the part of a table row the verifier reads.
type onbRow struct {
	Slug        string `json:"slug"`
	FactProject optStr `json:"factProject"`
	Component   optStr `json:"component"`
	Upstream    *struct {
		Repository optStr `json:"repository"`
	} `json:"upstream"`
}

type onbTableFile struct {
	Projects []onbRow `json:"projects"`
	Reserved []*struct {
		Repository *optStr `json:"repository"`
	} `json:"reserved"`
}

// onbTableDoc reads a table file; any decode problem is an error (no guess).
func onbTableDoc(raw []byte) (*onbTableFile, error) {
	var doc onbTableFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func onbTableSlugs(raw []byte) ([]string, error) {
	doc, err := onbTableDoc(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Projects))
	for _, r := range doc.Projects {
		out = append(out, r.Slug)
	}
	return out, nil
}

// baseFacts are the identity values the base already uses: project ids (slug,
// project, factProject) lower-cased, and upstream repository KEYS (host/path)
// of every repo, component, upstream repository and reserved repository.
type baseFacts struct {
	ids   map[string]bool
	repos map[string]bool
	bad   []string // values that could not be reduced to a key
}

func (b *baseFacts) addID(v string) {
	if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
		b.ids[v] = true
	}
}

// addRepo records a repository spelling; bare allows owner/name (reserved
// repositories). A value that cannot be reduced is remembered, never skipped.
func (b *baseFacts) addRepo(v string, bare bool) {
	k, ok := repoKey(v, bare)
	switch {
	case !ok:
		b.bad = append(b.bad, v)
	case k != "":
		b.repos[k] = true
	}
}

var repoHosts = map[string]string{"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}

// repoKey reduces every spelling of an upstream repository to the canonical
// key host/owner/name (lower case): schemes git+https, https, http, ssh, git,
// git+ssh, scp-like user@host:path, bare host/path, a www. prefix, a trailing
// dot in the host, ssh.github.com, a numeric port, trailing slash and .git,
// @ref, ?query and #fragment suffixes, and package urls
// pkg:github|gitlab|bitbucket/owner/name[@version][?q][#subpath]. Empty input
// is ("", true) (field absent). Everything else is ("", false): non-ASCII or
// control bytes, percent-encoding, API/raw/gist/download alias hosts, a
// non-numeric port after a scheme, an extra path segment on github.com or
// bitbucket.org (tree/main, sub), more than 10 segments, unknown purl types.
// bare allows a two-segment owner/name on github.com.
func repoKey(v string, bare bool) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "", true
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c <= 0x20 || c >= 0x7f || c == '\\' || c == '%' {
			return "", false
		}
	}
	if strings.Contains(v, "..") {
		return "", false
	}
	var host, rest string
	hadScheme := false
	if after, ok := strings.CutPrefix(v, "pkg:"); ok {
		typ, r, found := strings.Cut(after, "/")
		h, known := repoHosts[typ]
		if !found || !known {
			return "", false
		}
		host, rest = h, r
		rest, _, _ = strings.Cut(rest, "#")
		rest, _, _ = strings.Cut(rest, "?")
	} else {
		for changed := true; changed; {
			changed = false
			for _, p := range []string{"git+", "https://", "http://", "ssh://", "git://"} {
				if t, ok := strings.CutPrefix(v, p); ok {
					v, changed, hadScheme = t, true, true
				}
			}
		}
		v, _, _ = strings.Cut(v, "#")
		v, _, _ = strings.Cut(v, "?")
		// userinfo (git@, user:pass@): only before the first slash.
		if i := strings.IndexByte(v, '@'); i >= 0 && !strings.Contains(v[:i], "/") {
			v = v[i+1:]
		}
		// scp-like host:path and host:port/path.
		if i := strings.IndexByte(v, ':'); i >= 0 && !strings.Contains(v[:i], "/") {
			tail := v[i+1:]
			port, after, hasSlash := strings.Cut(tail, "/")
			numeric := port != "" && strings.Trim(port, "0123456789") == ""
			switch {
			case hasSlash && numeric:
				tail = after
			case hadScheme:
				// A scheme url has a numeric port or none.
				return "", false
			}
			v = v[:i] + "/" + strings.TrimPrefix(tail, "/")
		}
		segs := strings.Split(v, "/")
		if bare && len(segs) == 2 {
			host, rest = "github.com", v
		} else {
			host = segs[0]
			rest = strings.Join(segs[1:], "/")
		}
	}
	host = strings.TrimPrefix(strings.TrimRight(host, "."), "www.")
	if host == "ssh.github.com" {
		host = "github.com"
	}
	if !repoHostOK(host) {
		return "", false
	}
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segs) < 2 || len(segs) > 10 || (len(segs) != 2 && (host == "github.com" || host == "bitbucket.org")) {
		return "", false
	}
	// @ref / @version on the last segment, then .git, repeatedly.
	last := segs[len(segs)-1]
	last, _, _ = strings.Cut(last, "@")
	for strings.HasSuffix(last, ".git") {
		last = strings.TrimSuffix(last, ".git")
	}
	segs[len(segs)-1] = last
	for _, sg := range segs {
		if sg == "" || sg == "." || strings.Trim(sg, "abcdefghijklmnopqrstuvwxyz0123456789._-") != "" {
			return "", false
		}
	}
	return host + "/" + strings.Join(segs, "/"), true
}

// repoHostOK accepts a plain dotted host name, and for the three known forges
// only the forge's own host (no api., raw., gist., codeload., objects. or
// *.githubusercontent.com alias, no punycode label).
func repoHostOK(host string) bool {
	if host == "" || !strings.Contains(host, ".") || strings.Trim(host, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "xn--") || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	for _, forge := range []string{"github.com", "gitlab.com", "bitbucket.org", "githubusercontent.com"} {
		if host != forge && strings.HasSuffix(host, "."+forge) {
			return false
		}
	}
	return host != "githubusercontent.com"
}

type onbTargetDoc struct {
	Target struct {
		Project     optStr `json:"project"`
		FactProject optStr `json:"factProject"`
		Component   optStr `json:"component"`
		Repo        optStr `json:"repo"`
	} `json:"target"`
}

// checkCollisions refuses a project whose identity is already used by the
// base: its slug, fact project or the head target's project equal to any base
// id, or its repo, component or the head target's repo or component reducing
// to the same repository key as any base repository, under any spelling. A
// head target that does not decode, or a repo that cannot be reduced, is a
// refusal.
func checkCollisions(run *onbRun, bf *baseFacts, head *treeView, slug string, rc *Recipe) {
	raw, f := head.read(realTargetPath(slug), maxOutputBytes)
	var doc onbTargetDoc
	if f != nil || json.Unmarshal(raw, &doc) != nil {
		run.addDetail(OnbReasonHeadTarget, slug, "the head target does not decode")
		return
	}
	ids := []string{slug, rc.FactProject, string(doc.Target.Project), string(doc.Target.FactProject)}
	repos := []string{rc.Repo, rc.Component, string(doc.Target.Repo), string(doc.Target.Component)}
	for _, v := range ids {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" && bf.ids[v] {
			run.addDetail(OnbReasonFactCollision, slug, "an id is already used in the base")
			break
		}
	}
	for _, v := range repos {
		k, ok := repoKey(v, false)
		switch {
		case !ok:
			run.addDetail(OnbReasonRepoUnparsable, slug, "a head repository value cannot be reduced to a key")
		case k != "" && bf.repos[k]:
			run.addDetail(OnbReasonRepoCovered, slug, "an upstream repository is already covered in the base")
		}
	}
}

func onbPolicyOK(p OnboardingPolicy) bool {
	seen := map[string]bool{}
	list := append([]string{p.BatchPath, p.TablePath}, append(append([]string(nil), p.Required...), p.Optional...)...)
	for _, e := range list {
		if !onbCleanPath(e) || seen[e] || onbTrustPath(e, p.TrustPaths) || onbForbiddenPath(e) ||
			strings.HasPrefix(e, RecipesRoot) || strings.HasPrefix(e, CrdVersionsDir+"/") {
			return false
		}
		seen[e] = true
	}
	// A policy without trust paths is refused: the checker would still refuse
	// them, but this verifier does not run with the list silently empty.
	if len(p.TrustPaths) == 0 {
		return false
	}
	for _, t := range p.TrustPaths {
		if t == "" {
			return false
		}
	}
	return true
}

func verifyOnboarding(in OnboardingVerifyInput, env verifyEnv) OnboardingVerifyResult {
	run := &onbRun{reasons: map[string]bool{}}
	env, ef := normalizeEnv(env)
	if ef != nil {
		run.addFailure("", ef)
		return run.fail(in)
	}

	// Stage 0: the input itself.
	if in.Base == nil || in.Head == nil {
		run.addDetail(OnbReasonInput, "", "base or head tree missing")
	}
	if !sha1HexRE.MatchString(in.BaseSHA) || !sha1HexRE.MatchString(in.HeadSHA) || in.BaseSHA == in.HeadSHA {
		run.addDetail(OnbReasonInput, "", "base and head must be two different 40 lowercase hex commit ids")
	}
	slugs := append([]string(nil), in.Slugs...)
	sort.Strings(slugs)
	slugOK := len(slugs) > 0 && len(slugs) <= MaxOnboardingSlugs
	for i, s := range slugs {
		if !onbSlugRE.MatchString(s) || !slugRE.MatchString(s) || i > 0 && slugs[i-1] == s {
			slugOK = false
		}
	}
	if !slugOK {
		run.addDetail(OnbReasonSlugList, "", fmt.Sprintf("%d slugs; need 1..%d valid, unique", len(slugs), MaxOnboardingSlugs))
	}
	if !onbPolicyOK(in.Policy) {
		run.addDetail(OnbReasonPolicy, "", "the path policy is incomplete or unsafe")
	}
	if run.failed() {
		return run.fail(in)
	}

	// Stage 1: the raw diff, parsed once, and every path classified.
	recs, f := parseChangedRecords(in.ChangedRaw)
	if f != nil {
		run.addFailure("", f)
		return run.fail(in)
	}
	paths := make([]string, 0, len(recs))
	byPath := map[string]changedRecord{}
	for _, r := range recs {
		paths = append(paths, r.Path)
		byPath[r.Path] = r
	}
	if err := pathset.Valid(paths); err != nil {
		run.addDetail(OnbReasonPathSet, "", err.Error())
		return run.fail(in)
	}
	fullDigest, err := pathset.Digest(paths)
	if err != nil {
		run.addDetail(OnbReasonPathSet, "", err.Error())
		return run.fail(in)
	}

	static := map[string]bool{in.Policy.BatchPath: true, in.Policy.TablePath: true}
	for _, p := range in.Policy.Required {
		static[p] = true
	}
	for _, p := range in.Policy.Optional {
		static[p] = true
	}
	judged := map[string]string{} // path -> slug
	for _, s := range slugs {
		judged[realTargetPath(s)] = s
		for name := range allowedFiles(s) {
			judged[RecipesRoot+s+"/"+name] = s
		}
	}
	for _, p := range paths {
		_, isJudged := judged[p]
		switch {
		case !onbCleanPath(p):
			run.addDetail(OnbReasonPathSet, "", fmt.Sprintf("unclean path %q", p))
		case onbTrustPath(p, in.Policy.TrustPaths):
			run.addDetail(OnbReasonTrust, "", fmt.Sprintf("%q", p))
		case onbForbiddenPath(p):
			run.addDetail(OnbReasonForbidden, "", fmt.Sprintf("%q", p))
		case static[p] || isJudged:
		case onbOtherSlugPath(p):
			run.addDetail(OnbReasonSlugSet, "", fmt.Sprintf("%q belongs to a project outside the expected list", p))
		default:
			run.addDetail(OnbReasonOutside, "", fmt.Sprintf("%q", p))
		}
	}
	need := []string{in.Policy.BatchPath, in.Policy.TablePath}
	need = append(need, in.Policy.Required...)
	for _, s := range slugs {
		need = append(need, realTargetPath(s))
		for _, n := range recipeRequired {
			need = append(need, RecipesRoot+s+"/"+n)
		}
	}
	for _, p := range need {
		if _, ok := byPath[p]; !ok {
			run.addDetail(OnbReasonRequired, "", fmt.Sprintf("%q is not in the change", p))
		}
	}
	if r, ok := byPath[in.Policy.BatchPath]; ok && r.Status != "A" {
		run.addDetail("path-status", "", "the batch file must be added, not modified")
	}
	if run.failed() {
		return run.fail(in)
	}

	// Stage 2: the trees must be the ones the diff describes, and the base
	// must not know any project.
	head, hf := newTreeView(in.Head)
	if hf != nil {
		run.addFailure("", hf)
		return run.fail(in)
	}
	base, bf := newTreeView(in.Base)
	if bf != nil {
		run.addFailure("", bf)
		return run.fail(in)
	}
	for _, p := range paths {
		r := byPath[p]
		hb, f := head.read(p, MaxFileBytes)
		if f != nil {
			if f.Harness {
				run.addFailure("", f)
			} else {
				run.addDetail(OnbReasonTreeDiff, "", fmt.Sprintf("%q is not a readable regular file in head", p))
			}
			continue
		}
		if gitBlobSHA(hb) != r.NewSHA {
			run.addDetail(OnbReasonTreeDiff, "", fmt.Sprintf("%q: head bytes are not the diff's new blob", p))
		}
		_, inBase := base.files[p]
		switch r.Status {
		case "A":
			if inBase {
				run.addDetail(OnbReasonTreeDiff, "", fmt.Sprintf("%q is listed as added but exists in base", p))
			}
		case "M":
			bb, f := base.read(p, MaxFileBytes)
			switch {
			case f != nil && f.Harness:
				run.addFailure("", f)
			case f != nil:
				run.addDetail(OnbReasonTreeDiff, "", fmt.Sprintf("%q is listed as modified but is not a regular file in base", p))
			case gitBlobSHA(bb) != r.OldSHA:
				run.addDetail(OnbReasonTreeDiff, "", fmt.Sprintf("%q: base bytes are not the diff's old blob", p))
			}
		}
	}
	for _, s := range slugs {
		for _, p := range head.under(RecipesRoot + s + "/") {
			if _, ok := byPath[p]; !ok {
				run.addDetail(OnbReasonHeadExtra, s, fmt.Sprintf("%q", p))
			}
		}
	}
	facts := checkBaseAbsence(run, base, head, in.Policy.TablePath, slugs)
	if run.failed() {
		return run.fail(in)
	}

	// Stage 3: every project's recipe regenerates what the change carries.
	type verified struct {
		slug string
		cc   *contentChecked
	}
	var done []verified
	for _, s := range slugs {
		dirRel := strings.TrimSuffix(RecipesRoot, "/") + "/" + s
		cc, f := checkRecipeContent(head, s, dirRel, realTargetPath(s), env)
		if f != nil {
			run.addFailure(s, f)
			continue
		}
		checkCollisions(run, facts, head, s, cc.rc)
		done = append(done, verified{s, cc})
	}
	if run.failed() {
		return run.fail(in)
	}

	// Stage 4: the network, last, only when everything local held.
	if in.Upstream == nil {
		run.addHarness(OnbReasonNoRunner, "", "no upstream runner")
		return run.fail(in)
	}
	binder := Binder{Runner: in.Upstream, Sleep: in.Sleep, Ctx: in.Ctx}
	var bindDigest strings.Builder
	bindDigest.WriteString(onbBindingHeader)
	tagsCommits := map[string]string{}
	for _, d := range done {
		br, bf := binder.Bind(d.cc.rc, d.cc.bundle.Commit, in.HeadSHA)
		if bf != nil {
			// The first failure ends the run: the wait is bounded by one
			// project's attempts, not by the batch.
			run.addFailure(d.slug, bf)
			return run.fail(in)
		}
		bindDigest.WriteString(d.slug + "\t" + br.Digest + "\n")
		tags := append([]BindingTag(nil), br.Tags...)
		sort.Slice(tags, func(i, j int) bool { return tags[i].Tag < tags[j].Tag })
		var tc strings.Builder
		tc.WriteString(onbTagsCommitsHeader)
		for _, t := range tags {
			tc.WriteString(t.Tag + "\t" + t.Commit + "\n")
		}
		tagsCommits[d.slug] = sha256Prefixed([]byte(tc.String()))
	}

	// Stage 5: the digests. The judged subset is the per-project paths.
	var judgedPaths []string
	for _, p := range paths {
		if _, ok := judged[p]; ok {
			judgedPaths = append(judgedPaths, p)
		}
	}
	judgedDigest, err := pathset.Digest(judgedPaths)
	if err != nil {
		run.addDetail(OnbReasonPathSet, "", err.Error())
		return run.fail(in)
	}
	return OnboardingVerifyResult{
		Mode: OnboardingVerifyMode, Outcome: "pass", Reasons: []string{},
		BaseSHA: in.BaseSHA, HeadSHA: in.HeadSHA,
		BindingVerified: true, RecipeChange: "new", Eligible: false,
		ChangedPathsSHA256: fullDigest, JudgedPathsSHA256: judgedDigest,
		Slugs: slugs, BindingDigest: sha256Prefixed([]byte(bindDigest.String())), TagsCommitsSHA: tagsCommits,
	}
}

// onbOtherSlugPath reports a path shaped exactly like a project's own file (a
// real target or a known recipe file) of some slug.
func onbOtherSlugPath(p string) bool {
	if rest, ok := strings.CutPrefix(p, CrdVersionsDir+"/target-"); ok {
		name, ok := strings.CutSuffix(rest, ".json")
		return ok && slugRE.MatchString(name)
	}
	if rest, ok := strings.CutPrefix(p, RecipesRoot); ok {
		parts := strings.Split(rest, "/")
		return len(parts) == 2 && slugRE.MatchString(parts[0]) && allowedFiles(parts[0])[parts[1]]
	}
	return false
}

// checkBaseAbsence records, per project and under any casing, whether the base
// already has a recipe directory or file, a real target (by file name or by
// the project it names) or a table row; and that the head table has exactly
// the project's own row. A table or target that cannot be read is "unknown",
// never absent.
func checkBaseAbsence(run *onbRun, base, head *treeView, tablePath string, slugs []string) *baseFacts {
	bf := &baseFacts{ids: map[string]bool{}, repos: map[string]bool{}}
	baseTable, tf := base.read(tablePath, MaxFileBytes)
	var baseRows []string
	if tf != nil {
		run.addHarness(OnbReasonBaseUnknown, "", "base table unreadable: "+tf.Code)
	} else if doc, err := onbTableDoc(baseTable); err != nil {
		run.addHarness(OnbReasonBaseUnknown, "", "base table does not decode")
	} else {
		for _, r := range doc.Projects {
			baseRows = append(baseRows, r.Slug)
			bf.addID(r.Slug)
			bf.addID(string(r.FactProject))
			bf.addRepo(string(r.Component), false)
			if r.Upstream != nil {
				bf.addRepo(string(r.Upstream.Repository), false)
			}
		}
		for _, r := range doc.Reserved {
			// A reserved entry without a repository (or null) is never skipped.
			if r == nil || r.Repository == nil || strings.TrimSpace(string(*r.Repository)) == "" {
				bf.bad = append(bf.bad, "reserved entry without a repository")
				continue
			}
			bf.addRepo(string(*r.Repository), true)
		}
	}
	var baseTargetProjects []string
	targetPrefix := CrdVersionsDir + "/"
	for _, p := range base.under(targetPrefix) {
		name := strings.TrimPrefix(p, targetPrefix)
		if strings.Contains(name, "/") || !strings.HasPrefix(name, "target-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, f := base.read(p, maxOutputBytes)
		var doc onbTargetDoc
		if f != nil || json.Unmarshal(raw, &doc) != nil {
			run.addHarness(OnbReasonBaseUnknown, "", fmt.Sprintf("base target %q does not decode", name))
			continue
		}
		baseTargetProjects = append(baseTargetProjects, string(doc.Target.Project))
		bf.addID(string(doc.Target.Project))
		bf.addID(string(doc.Target.FactProject))
		bf.addRepo(string(doc.Target.Repo), false)
		bf.addRepo(string(doc.Target.Component), false)
	}
	headTable, hf := head.read(tablePath, MaxFileBytes)
	if len(bf.bad) != 0 {
		run.addHarness(OnbReasonRepoUnparsable, "", fmt.Sprintf("%d base repository value(s) cannot be reduced to a key", len(bf.bad)))
	}
	var headRows []string
	headOK := false
	if hf != nil {
		run.addDetail(OnbReasonHeadTable, "", "head table unreadable: "+hf.Code)
	} else if rows, err := onbTableSlugs(headTable); err != nil {
		run.addDetail(OnbReasonHeadTable, "", "head table does not decode")
	} else {
		headRows, headOK = rows, true
	}
	for _, s := range slugs {
		present := false
		for _, r := range baseRows {
			present = present || strings.EqualFold(r, s)
		}
		for _, r := range baseTargetProjects {
			present = present || strings.EqualFold(r, s)
		}
		for p := range base.files {
			if rest, ok := strings.CutPrefix(p, RecipesRoot); ok {
				first, _, _ := strings.Cut(rest, "/")
				present = present || strings.EqualFold(first, s)
			}
			if rest, ok := strings.CutPrefix(p, targetPrefix); ok {
				present = present || strings.EqualFold(rest, "target-"+s+".json")
			}
		}
		if present {
			run.addDetail(OnbReasonBasePresent, s, "")
		}
		exact, fold := 0, 0
		for _, r := range headRows {
			if r == s {
				exact++
			}
			if strings.EqualFold(r, s) {
				fold++
			}
		}
		if headOK && (exact != 1 || fold != 1) {
			run.addDetail(OnbReasonHeadTable, s, fmt.Sprintf("%d exact and %d case-folded rows in the head table", exact, fold))
		}
	}
	return bf
}
