// SPDX-License-Identifier: AGPL-3.0-only

package projectonboarding

// The exact-tag route intentionally has no Release-shaped fields.  It is a
// separate closed schema so old snapshots and their canonical bytes remain
// wholly unchanged.

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const (
	ExactTagRequestSchema  = "prufyx.io/public-project-onboarding-request/v2"
	ExactTagSnapshotSchema = "prufyx.io/public-project-onboarding-snapshot/v2"
	ExactTagReceiptSchema  = "prufyx.io/public-project-onboarding-sync-receipt/v2"
)

var exactTagSnapshotLimitations = []string{
	"explicit Git tag observations are mutable locators captured at observation time",
	"no ownership, signature authority, review, admission, support, compatibility, runtime, or publication claim follows",
}

var exactTagReceiptLimitations = []string{
	"only fixed public GitHub repository, tag-reference, annotated-tag, and commit-pinned raw-content endpoints were queried",
	"this is source observation only and is not admission or executable support",
}

type exactTagRequest struct {
	repo, owner, name, slug, license, anchor, digest string
	tags, paths                                      []string
	document                                         map[string]any
}

type exactTagList []string

func (s *exactTagList) String() string { return strings.Join(*s, ",") }
func (s *exactTagList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func runExactTagInit(args []string, stderr io.Writer) int {
	f := flag.NewFlagSet("project init", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var repo, out, slug, anchor, pathsCSV, license, prefix string
	var tags exactTagList
	var limit int
	f.StringVar(&repo, "repository", "", "canonical public GitHub repository")
	f.StringVar(&out, "output", "", "new request file")
	f.StringVar(&slug, "slug", "", "project slug")
	f.Var(&tags, "exact-tag", "exact selected Git tag (repeatable)")
	f.StringVar(&anchor, "license-anchor-tag", "", "selected tag for license probe")
	f.StringVar(&pathsCSV, "changelog-paths", "", "comma-separated paths")
	f.StringVar(&license, "license-disposition", "NOT_REVIEWED", "")
	f.StringVar(&prefix, "tag-prefix", "", "")
	f.IntVar(&limit, "release-limit", 0, "")
	if f.Parse(args) != nil {
		return reject(stderr)
	}
	visited := map[string]bool{}
	f.Visit(func(value *flag.Flag) { visited[value.Name] = true })
	if f.NArg() != 0 || out == "" || len(tags) < 1 || len(tags) > 10 || anchor == "" || visited["tag-prefix"] || visited["release-limit"] || prefix != "" || limit != 0 || (license != "NOT_REVIEWED" && license != "DECLARED_UNKNOWN") {
		return reject(stderr)
	}
	canonical, owner, name, err := repositoryParts(repo)
	if err != nil {
		return reject(stderr)
	}
	if slug == "" {
		slug = deriveSlug(owner, name)
	}
	if _, err = sourcecorpus.ValidateSlug(slug); err != nil {
		return reject(stderr)
	}
	seen := map[string]bool{}
	anchorOK := false
	for _, tag := range tags {
		if !tagRE.MatchString(tag) || seen[tag] {
			return reject(stderr)
		}
		seen[tag] = true
		anchorOK = anchorOK || tag == anchor
	}
	if !anchorOK {
		return reject(stderr)
	}
	paths := append([]string(nil), defaultChangelogPaths...)
	if pathsCSV != "" {
		paths = strings.Split(pathsCSV, ",")
	}
	if len(paths) < 1 || len(paths) > 8 {
		return reject(stderr)
	}
	seen = map[string]bool{}
	for _, p := range paths {
		if !validChangelogPath(canonical, p) || seen[p] {
			return reject(stderr)
		}
		seen[p] = true
	}
	v := map[string]any{"schema": ExactTagRequestSchema, "authority": Authority, "project": map[string]any{"slug": slug, "canonicalRepositoryURL": canonical, "owner": owner, "repository": name}, "discovery": map[string]any{"mode": "EXPLICIT_GIT_TAGS", "exactTags": toAny(tags), "licenseAnchorTag": anchor, "changelogPaths": toAny(paths), "licenseDisposition": license}, "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}}
	raw, e := sourcecorpus.Canonical(v)
	if e != nil || writeNewPrivate(out, raw) != nil {
		return reject(stderr)
	}
	return 0
}

func parseExactTagRequest(raw []byte) (exactTagRequest, error) {
	v, e := sourcecorpus.DecodeBounded(raw, maxRequest)
	if e != nil {
		return exactTagRequest{}, ErrRejected
	}
	m, ok := v.(map[string]any)
	if !ok || !exact(m, "schema", "authority", "project", "discovery", "review") || m["schema"] != ExactTagRequestSchema || m["authority"] != Authority {
		return exactTagRequest{}, ErrRejected
	}
	p, ok := m["project"].(map[string]any)
	if !ok || !exact(p, "slug", "canonicalRepositoryURL", "owner", "repository") {
		return exactTagRequest{}, ErrRejected
	}
	repo, owner, name, e := repositoryParts(stringOf(p["canonicalRepositoryURL"]))
	if e != nil || p["owner"] != owner || p["repository"] != name {
		return exactTagRequest{}, ErrRejected
	}
	slug, e := sourcecorpus.ValidateSlug(p["slug"])
	if e != nil {
		return exactTagRequest{}, ErrRejected
	}
	d, ok := m["discovery"].(map[string]any)
	if !ok || !exact(d, "mode", "exactTags", "licenseAnchorTag", "changelogPaths", "licenseDisposition") || d["mode"] != "EXPLICIT_GIT_TAGS" {
		return exactTagRequest{}, ErrRejected
	}
	rawtags, ok := d["exactTags"].([]any)
	if !ok || len(rawtags) < 1 || len(rawtags) > 10 {
		return exactTagRequest{}, ErrRejected
	}
	tags := make([]string, 0, len(rawtags))
	seen := map[string]bool{}
	for _, x := range rawtags {
		s := stringOf(x)
		if !tagRE.MatchString(s) || seen[s] {
			return exactTagRequest{}, ErrRejected
		}
		seen[s] = true
		tags = append(tags, s)
	}
	anchor := stringOf(d["licenseAnchorTag"])
	if !seen[anchor] {
		return exactTagRequest{}, ErrRejected
	}
	rawpaths, ok := d["changelogPaths"].([]any)
	if !ok || len(rawpaths) < 1 || len(rawpaths) > 8 {
		return exactTagRequest{}, ErrRejected
	}
	paths := make([]string, 0, len(rawpaths))
	seen = map[string]bool{}
	for _, x := range rawpaths {
		s := stringOf(x)
		if !validChangelogPath(repo, s) || seen[s] {
			return exactTagRequest{}, ErrRejected
		}
		seen[s] = true
		paths = append(paths, s)
	}
	license := stringOf(d["licenseDisposition"])
	if license != "NOT_REVIEWED" && license != "DECLARED_UNKNOWN" {
		return exactTagRequest{}, ErrRejected
	}
	review, ok := m["review"].(map[string]any)
	if !ok || !exact(review, "state", "admissionState") || review["state"] != "NOT_REVIEWED" || review["admissionState"] != "NOT_ADMITTED" {
		return exactTagRequest{}, ErrRejected
	}
	canon, e := sourcecorpus.Canonical(v)
	if e != nil {
		return exactTagRequest{}, ErrRejected
	}
	return exactTagRequest{repo, owner, name, slug, license, anchor, sourcecorpus.SHA(canon), tags, paths, m}, nil
}

func runExactTagSync(ctx context.Context, r exactTagRequest, parent, previous string, stdout, stderr io.Writer, opt Options) int {
	if sourcecorpus.ValidatePrivateDirectoryPath(parent) != nil {
		return reject(stderr)
	}
	if opt.Fetcher == nil {
		opt.Fetcher = FixedHTTPSFetcher{}
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	var prior map[string]any
	var priorObjects map[string][]byte
	var e error
	if previous != "" {
		prior, priorObjects, e = VerifySnapshot(previous)
		if e != nil || prior["schema"] != ExactTagSnapshotSchema {
			return reject(stderr)
		}
	}
	snap, receipt, objects, e := syncExactTags(ctx, r, prior, priorObjects, opt.Fetcher, opt.Now)
	if e != nil {
		return reject(stderr)
	}
	var corpusRaw []byte
	if len(snap["sources"].([]any)) > 0 {
		corpus := map[string]any{"schema": sourcecorpus.Schema, "revision": onboardingRevision(request{repo: r.repo}), "authority": sourcecorpus.DeclaredAuthority, "records": snap["corpusRecords"]}
		corpusRaw, _ = sourcecorpus.Canonical(corpus)
		receipt["sourceCorpusManifestDigest"] = sourcecorpus.SHA(corpusRaw)
	} else {
		receipt["sourceCorpusManifestDigest"] = nil
	}
	delete(snap, "corpusRecords")
	raw, _ := sourcecorpus.Canonical(snap)
	digest := sourcecorpus.SHA(raw)
	name := "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	receipt["snapshotDigest"] = digest
	receipt["outputName"] = name
	receiptRaw, e := sourcecorpus.Canonical(receipt)
	if e != nil || sourcecorpus.WriteProjectSnapshotTree(parent, name, objects, raw, corpusRaw, receiptRaw) != nil {
		return reject(stderr)
	}
	if emitJSON(stdout, receipt) != nil {
		return rejectReason(stderr, "OUTPUT_WRITE_FAILURE")
	}
	return 0
}

func syncExactTags(ctx context.Context, r exactTagRequest, prior map[string]any, _ map[string][]byte, fetcher Fetcher, now func() time.Time) (map[string]any, map[string]any, map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	objs := map[string][]byte{}
	count, aggregate := 0, 0
	add := func(b []byte) string {
		d := sourcecorpus.SHA(b)
		if _, ok := objs[d]; !ok {
			aggregate += len(b)
			objs[d] = append([]byte(nil), b...)
		}
		return d
	}
	api := func(path string) ([]byte, string, error) {
		count++
		if count > maxRequests {
			return nil, "", ErrRejected
		}
		b, status, e := fetcher.Fetch(ctx, "api.github.com", path)
		if e != nil {
			return nil, "", ErrNetwork
		}
		if status == 403 || status == 429 {
			return nil, "", ErrRateLimited
		}
		if status == 404 {
			return nil, "", ErrUnavailable
		}
		if status != 200 || len(b) == 0 || len(b) > maxAPI {
			return nil, "", ErrRejected
		}
		d := add(b)
		if aggregate > maxAggregate {
			return nil, "", ErrRejected
		}
		return b, d, nil
	}
	repoRaw, repoDigest, e := api("/repos/" + r.owner + "/" + r.name)
	if e != nil {
		return nil, nil, nil, e
	}
	var wire struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	}
	if decodeAPI(repoRaw, &wire) != nil || wire.ID < 1 || wire.FullName != r.owner+"/"+r.name || wire.HTMLURL != r.repo {
		return nil, nil, nil, ErrRejected
	}
	obs := make([]any, 0, len(r.tags))
	for _, tag := range r.tags {
		refRaw, refDigest, e := api("/repos/" + r.owner + "/" + r.name + "/git/ref/tags/" + url.PathEscape(tag))
		if e != nil {
			return nil, nil, nil, e
		}
		var ref struct {
			Ref    string `json:"ref"`
			Object struct {
				Type string `json:"type"`
				SHA  string `json:"sha"`
			} `json:"object"`
		}
		if decodeAPI(refRaw, &ref) != nil || ref.Ref != "refs/tags/"+tag || (ref.Object.Type != "commit" && ref.Object.Type != "tag") || !commit(ref.Object.SHA) {
			return nil, nil, nil, ErrRejected
		}
		entry := map[string]any{"tag": tag, "refTargetKind": ref.Object.Type, "refTargetSHA": ref.Object.SHA, "tagReferenceObject": "sha256/" + strings.TrimPrefix(refDigest, "sha256:"), "annotatedTagObject": any(nil), "annotatedTagSHA": any(nil), "peeledCommit": ref.Object.SHA}
		if ref.Object.Type == "tag" {
			outer := ref.Object.SHA
			tagRaw, tagDigest, e := api("/repos/" + r.owner + "/" + r.name + "/git/tags/" + outer)
			if e != nil {
				return nil, nil, nil, e
			}
			var tw struct {
				SHA    string `json:"sha"`
				Tag    string `json:"tag"`
				Object struct {
					Type string `json:"type"`
					SHA  string `json:"sha"`
				} `json:"object"`
			}
			if decodeAPI(tagRaw, &tw) != nil || tw.SHA != outer || tw.Tag != tag || tw.Object.Type != "commit" || !commit(tw.Object.SHA) {
				return nil, nil, nil, ErrRejected
			}
			entry["annotatedTagObject"] = "sha256/" + strings.TrimPrefix(tagDigest, "sha256:")
			entry["annotatedTagSHA"] = outer
			entry["peeledCommit"] = tw.Object.SHA
		}
		obs = append(obs, entry)
	}
	// Probe bounded candidate changelog paths at every selected peeled commit,
	// then bind the declared anchor to the bounded license probe.
	sources, records := []any{}, []any{}
	seenImmutable := map[string]bool{}
	captured := now().UTC().Truncate(time.Second).Format(time.RFC3339)
	if !validTimestamp(captured) {
		return nil, nil, nil, ErrRejected
	}
	sourceAggregate := 0
	for _, value := range obs {
		o := value.(map[string]any)
		peeled := stringOf(o["peeledCommit"])
		for _, p := range r.paths {
			immutable := r.repo + "/blob/" + peeled + "/" + p
			if seenImmutable[immutable] {
				break
			}
			count++
			if count > maxRequests {
				return nil, nil, nil, ErrRejected
			}
			body, status, fetchErr := fetcher.Fetch(ctx, "raw.githubusercontent.com", "/"+r.owner+"/"+r.name+"/"+peeled+"/"+p)
			if fetchErr != nil {
				return nil, nil, nil, ErrNetwork
			}
			if status == 404 {
				continue
			}
			if status == 403 || status == 429 {
				return nil, nil, nil, ErrRateLimited
			}
			if status != 200 || len(body) < 1 || len(body) > maxObject {
				return nil, nil, nil, ErrRejected
			}
			span, e := fullSpan(body)
			if e != nil {
				return nil, nil, nil, e
			}
			if !seenImmutable[immutable] {
				sourceAggregate += len(body)
			}
			if sourceAggregate > maxCorpusBytes {
				return nil, nil, nil, ErrRejected
			}
			d := add(body)
			if aggregate > maxAggregate {
				return nil, nil, nil, ErrRejected
			}
			sourceID := onboardingSourceID(request{repo: r.repo}, peeled, p)
			s := map[string]any{"id": sourceID, "kind": "changelog", "version": "reference_only", "commit": peeled, "immutableURL": immutable, "fileDigest": d, "object": "sha256/" + strings.TrimPrefix(d, "sha256:"), "byteLength": int64(len(body)), "spans": []any{span}, "captureState": "FETCHED"}
			sources = append(sources, s)
			records = append(records, corpusRecord(request{repo: r.repo, slug: r.slug}, sourceID, "reference_only", peeled, immutable, d, len(body), span, captured))
			seenImmutable[immutable] = true
			break
		}
	}
	anchorCommit := ""
	for _, value := range obs {
		o := value.(map[string]any)
		if o["tag"] == r.anchor {
			anchorCommit = stringOf(o["peeledCommit"])
		}
	}
	license := any(nil)
	for _, p := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "COPYING"} {
		count++
		if count > maxRequests {
			return nil, nil, nil, ErrRejected
		}
		body, status, fetchErr := fetcher.Fetch(ctx, "raw.githubusercontent.com", "/"+r.owner+"/"+r.name+"/"+anchorCommit+"/"+p)
		if fetchErr != nil {
			return nil, nil, nil, ErrNetwork
		}
		if status == 404 {
			continue
		}
		if status == 403 || status == 429 {
			return nil, nil, nil, ErrRateLimited
		}
		if status != 200 || len(body) < 1 || len(body) > maxObject {
			return nil, nil, nil, ErrRejected
		}
		d := add(body)
		if aggregate > maxAggregate {
			return nil, nil, nil, ErrRejected
		}
		license = map[string]any{"kind": "license", "commit": anchorCommit, "immutableURL": r.repo + "/blob/" + anchorCommit + "/" + p, "fileDigest": d, "object": "sha256/" + strings.TrimPrefix(d, "sha256:"), "byteLength": int64(len(body)), "disposition": r.license}
		break
	}
	sort.Slice(sources, func(i, j int) bool {
		return stringOf(sources[i].(map[string]any)["id"]) < stringOf(sources[j].(map[string]any)["id"])
	})
	sort.Slice(records, func(i, j int) bool {
		return stringOf(records[i].(map[string]any)["id"]) < stringOf(records[j].(map[string]any)["id"])
	})
	adapter := "PRESENT"
	if len(sources) == 0 {
		adapter = "OMITTED_NO_CHANGELOG_BYTES"
	}
	lineage := any(nil)
	if prior != nil {
		priorRepository, ok := prior["repository"].(map[string]any)
		if !ok || priorRepository["repositoryID"] != wire.ID {
			return nil, nil, nil, ErrRejected
		}
		l, e := exactTagLineage(prior, r, obs)
		if e != nil {
			return nil, nil, nil, e
		}
		lineage = l
	}
	snap := map[string]any{"schema": ExactTagSnapshotSchema, "authority": Authority, "request": r.document, "requestDigest": r.digest, "observedAt": captured, "repository": map[string]any{"canonicalRepositoryURL": r.repo, "repositoryID": wire.ID, "fullName": wire.FullName, "repositoryObject": "sha256/" + strings.TrimPrefix(repoDigest, "sha256:")}, "tagObservations": obs, "sources": sources, "corpusRecords": records, "corpusAdapterState": adapter, "license": license, "lineage": lineage, "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}, "limitations": toAny(exactTagSnapshotLimitations)}
	receipt := map[string]any{"schema": ExactTagReceiptSchema, "result": "SYNCED", "authority": Authority, "requestDigest": r.digest, "repositoryID": wire.ID, "tagCount": int64(len(obs)), "sourceCount": int64(len(sources)), "corpusAdapterState": adapter, "sourceCorpusManifestDigest": nil, "reviewState": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED", "lineage": lineage, "limitations": toAny(exactTagReceiptLimitations)}
	return snap, receipt, objs, nil
}

func exactTagLineage(prior map[string]any, r exactTagRequest, obs []any) (map[string]any, error) {
	pr, ok := prior["request"].(map[string]any)
	if !ok {
		return nil, ErrRejected
	}
	raw, _ := sourcecorpus.Canonical(pr)
	old, e := parseExactTagRequest(raw)
	if e != nil {
		return nil, e
	}
	oldRepo := prior["repository"].(map[string]any)
	if old.repo != r.repo || old.slug != r.slug || oldRepo["repositoryID"] == nil || !sameNonSelection(old, r) {
		return nil, ErrRejected
	}
	oldObs := prior["tagObservations"].([]any)
	by := map[string]map[string]any{}
	for _, v := range oldObs {
		x, ok := v.(map[string]any)
		if !ok {
			return nil, ErrRejected
		}
		by[stringOf(x["tag"])] = x
	}
	current := map[string]map[string]any{}
	for _, v := range obs {
		x := v.(map[string]any)
		current[stringOf(x["tag"])] = x
	}
	shared, newer, omitted := []string{}, []string{}, []string{}
	for _, t := range r.tags {
		if o := by[t]; o != nil {
			if !sameTagBinding(o, current[t]) {
				return nil, ErrRejected
			}
			shared = append(shared, t)
		} else {
			newer = append(newer, t)
		}
	}
	for _, t := range old.tags {
		if current[t] == nil {
			omitted = append(omitted, t)
		}
	}
	sort.Strings(shared)
	sort.Strings(newer)
	sort.Strings(omitted)
	return map[string]any{"previousSnapshotDigest": digestMust(prior), "sharedTags": toAny(shared), "newlySelectedTags": toAny(newer), "omittedPriorTags": toAny(omitted), "sharedBindingState": "REOBSERVED_UNCHANGED", "omittedState": "NOT_REOBSERVED_NOT_REVALIDATED", "scope": "IMMEDIATE_PREVIOUS_SELECTION_SHARED_TAG_BINDINGS_ONLY"}, nil
}
func sameNonSelection(a, b exactTagRequest) bool {
	return a.repo == b.repo && a.owner == b.owner && a.name == b.name && a.slug == b.slug && a.license == b.license && strings.Join(a.paths, "\x00") == strings.Join(b.paths, "\x00")
}
func sameTagBinding(a, b map[string]any) bool {
	return a["refTargetKind"] == b["refTargetKind"] && a["refTargetSHA"] == b["refTargetSHA"] && a["annotatedTagSHA"] == b["annotatedTagSHA"] && a["peeledCommit"] == b["peeledCommit"]
}

func verifyExactTagSnapshot(dir string, s map[string]any) (map[string]any, map[string][]byte, error) {
	if !exact(s, "schema", "authority", "request", "requestDigest", "observedAt", "repository", "tagObservations", "sources", "corpusAdapterState", "license", "lineage", "review", "limitations") || s["schema"] != ExactTagSnapshotSchema || s["authority"] != Authority || !validTimestamp(stringOf(s["observedAt"])) || !exactStrings(s["limitations"], exactTagSnapshotLimitations) {
		return nil, nil, ErrRejected
	}
	raw, _ := sourcecorpus.Canonical(s["request"])
	r, e := parseExactTagRequest(raw)
	if e != nil || s["requestDigest"] != r.digest {
		return nil, nil, ErrRejected
	}
	review, ok := s["review"].(map[string]any)
	if !ok || !exact(review, "state", "admissionState") || review["state"] != "NOT_REVIEWED" || review["admissionState"] != "NOT_ADMITTED" {
		return nil, nil, ErrRejected
	}
	repo, ok := s["repository"].(map[string]any)
	repositoryID, idOK := repo["repositoryID"].(int64)
	if !ok || !idOK || repositoryID < 1 || !exact(repo, "canonicalRepositoryURL", "repositoryID", "fullName", "repositoryObject") || repo["canonicalRepositoryURL"] != r.repo || repo["fullName"] != r.owner+"/"+r.name {
		return nil, nil, ErrRejected
	}
	objects := map[string][]byte{}
	aggregate := 0
	read := func(n string, maximum int64) ([]byte, error) {
		if !objectRE.MatchString(n) {
			return nil, ErrRejected
		}
		digest := "sha256:" + strings.TrimPrefix(n, "sha256/")
		if cached, found := objects[digest]; found {
			if int64(len(cached)) > maximum {
				return nil, ErrRejected
			}
			return cached, nil
		}
		if len(objects) >= maxRequests {
			return nil, ErrRejected
		}
		data, err := sourcecorpus.ReadPrivateTreeFile(dir, "objects/"+n, maximum)
		if err != nil || sourcecorpus.SHA(data) != digest || aggregate+len(data) > maxAggregate {
			return nil, ErrRejected
		}
		aggregate += len(data)
		objects[digest] = data
		return data, nil
	}
	readAPI := func(name string) ([]byte, error) { return read(name, maxAPI) }
	readRaw := func(name string) ([]byte, error) { return read(name, maxObject) }
	b, e := readAPI(stringOf(repo["repositoryObject"]))
	if e != nil {
		return nil, nil, ErrRejected
	}
	var w struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	}
	if decodeAPI(b, &w) != nil || w.ID != repositoryID || w.FullName != repo["fullName"] || w.HTMLURL != repo["canonicalRepositoryURL"] {
		return nil, nil, ErrRejected
	}
	obs, ok := s["tagObservations"].([]any)
	sources, sourcesOK := s["sources"].([]any)
	if !ok || !sourcesOK || len(obs) != len(r.tags) || len(sources) > len(obs) || (len(sources) == 0 && s["corpusAdapterState"] != "OMITTED_NO_CHANGELOG_BYTES") || (len(sources) > 0 && s["corpusAdapterState"] != "PRESENT") {
		return nil, nil, ErrRejected
	}
	var corpusRaw []byte
	if len(sources) > 0 {
		if _, e := sourcecorpus.VerifyPath(filepath.Join(dir, "SOURCE-CORPUS-MANIFEST.json"), filepath.Join(dir, "objects")); e != nil {
			return nil, nil, ErrRejected
		}
		corpusRaw, e = sourcecorpus.ReadPrivateTreeFile(dir, "SOURCE-CORPUS-MANIFEST.json", 256<<10)
		if e != nil {
			return nil, nil, ErrRejected
		}
	}
	for i, v := range obs {
		x, ok := v.(map[string]any)
		if !ok || !exact(x, "tag", "refTargetKind", "refTargetSHA", "tagReferenceObject", "annotatedTagObject", "annotatedTagSHA", "peeledCommit") || x["tag"] != r.tags[i] || !commit(stringOf(x["refTargetSHA"])) || !commit(stringOf(x["peeledCommit"])) {
			return nil, nil, ErrRejected
		}
		rb, e := readAPI(stringOf(x["tagReferenceObject"]))
		if e != nil {
			return nil, nil, ErrRejected
		}
		var ref struct {
			Ref    string `json:"ref"`
			Object struct {
				Type string `json:"type"`
				SHA  string `json:"sha"`
			} `json:"object"`
		}
		if decodeAPI(rb, &ref) != nil || ref.Ref != "refs/tags/"+r.tags[i] || ref.Object.Type != x["refTargetKind"] || ref.Object.SHA != x["refTargetSHA"] {
			return nil, nil, ErrRejected
		}
		if ref.Object.Type == "commit" {
			if x["annotatedTagObject"] != nil || x["annotatedTagSHA"] != nil || x["peeledCommit"] != ref.Object.SHA {
				return nil, nil, ErrRejected
			}
		} else if ref.Object.Type == "tag" {
			tb, e := readAPI(stringOf(x["annotatedTagObject"]))
			if e != nil {
				return nil, nil, ErrRejected
			}
			var tw struct {
				SHA    string `json:"sha"`
				Tag    string `json:"tag"`
				Object struct {
					Type string `json:"type"`
					SHA  string `json:"sha"`
				} `json:"object"`
			}
			if decodeAPI(tb, &tw) != nil || tw.SHA != x["annotatedTagSHA"] || tw.SHA != ref.Object.SHA || tw.Tag != x["tag"] || tw.Object.Type != "commit" || tw.Object.SHA != x["peeledCommit"] {
				return nil, nil, ErrRejected
			}
		} else {
			return nil, nil, ErrRejected
		}
	}
	if !validExactTagLineage(s["lineage"], r.tags, obs) {
		return nil, nil, ErrRejected
	}
	if verifyExactTagSources(s, r, readRaw) != nil || (len(sources) > 0 && !adapterMatchesExactTagSnapshot(dir, s, r)) || verifyExactTagLicense(s, r, obs, readRaw) != nil {
		return nil, nil, ErrRejected
	}
	rawReceipt, e := sourcecorpus.ReadPrivateTreeFile(dir, "SYNC-RECEIPT.json", maxRequest)
	if e != nil {
		return nil, nil, ErrRejected
	}
	rv, e := sourcecorpus.DecodeBounded(bytes.TrimSpace(rawReceipt), maxRequest)
	receipt, ok := rv.(map[string]any)
	digest := digestMust(s)
	outputName := "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	if e != nil || !ok || !exact(receipt, "schema", "result", "authority", "requestDigest", "repositoryID", "tagCount", "sourceCount", "corpusAdapterState", "sourceCorpusManifestDigest", "reviewState", "admissionState", "lineage", "limitations", "snapshotDigest", "outputName") || receipt["schema"] != ExactTagReceiptSchema || receipt["result"] != "SYNCED" || receipt["authority"] != Authority || receipt["requestDigest"] != s["requestDigest"] || receipt["repositoryID"] != repositoryID || receipt["tagCount"] != int64(len(obs)) || receipt["sourceCount"] != int64(len(sources)) || receipt["corpusAdapterState"] != s["corpusAdapterState"] || receipt["reviewState"] != "NOT_REVIEWED" || receipt["admissionState"] != "NOT_ADMITTED" || !sameCanonical(receipt["lineage"], s["lineage"]) || !exactStrings(receipt["limitations"], exactTagReceiptLimitations) || receipt["snapshotDigest"] != digest || receipt["outputName"] != outputName || filepath.Base(filepath.Clean(dir)) != outputName {
		return nil, nil, ErrRejected
	}
	if len(sources) == 0 {
		if receipt["sourceCorpusManifestDigest"] != nil {
			return nil, nil, ErrRejected
		}
	} else if receipt["sourceCorpusManifestDigest"] != sourcecorpus.SHA(bytes.TrimSpace(corpusRaw)) {
		return nil, nil, ErrRejected
	}
	return s, objects, nil
}

func sameCanonical(a, b any) bool {
	left, leftErr := sourcecorpus.Canonical(a)
	right, rightErr := sourcecorpus.Canonical(b)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func verifyExactTagSources(snapshot map[string]any, r exactTagRequest, read func(string) ([]byte, error)) error {
	selectedCommits := map[string]bool{}
	for _, value := range snapshot["tagObservations"].([]any) {
		selectedCommits[stringOf(value.(map[string]any)["peeledCommit"])] = true
	}
	sources := snapshot["sources"].([]any)
	seenIDs, seenURLs, seenCommits := map[string]bool{}, map[string]bool{}, map[string]bool{}
	lastID := ""
	for _, value := range sources {
		source, ok := value.(map[string]any)
		if !ok || !exact(source, "id", "kind", "version", "commit", "immutableURL", "fileDigest", "object", "byteLength", "spans", "captureState") || source["kind"] != "changelog" || source["version"] != "reference_only" || source["captureState"] != "FETCHED" {
			return ErrRejected
		}
		id, immutable := stringOf(source["id"]), stringOf(source["immutableURL"])
		commitValue, digest := stringOf(source["commit"]), stringOf(source["fileDigest"])
		if !selectedCommits[commitValue] || !commit(commitValue) {
			return ErrRejected
		}
		selectedPath := ""
		for _, candidate := range r.paths {
			if immutable == r.repo+"/blob/"+commitValue+"/"+candidate {
				selectedPath = candidate
				break
			}
		}
		if selectedPath == "" || id != onboardingSourceID(request{repo: r.repo}, commitValue, selectedPath) || seenIDs[id] || seenURLs[immutable] || seenCommits[commitValue] || lastID != "" && id <= lastID {
			return ErrRejected
		}
		seenIDs[id], seenURLs[immutable], seenCommits[commitValue], lastID = true, true, true, id
		if _, err := sourcecorpus.ValidateImmutableURL(source["immutableURL"], r.repo, commitValue); err != nil || !validDigest(source["fileDigest"]) || stringOf(source["object"]) != "sha256/"+strings.TrimPrefix(digest, "sha256:") {
			return ErrRejected
		}
		data, err := read(stringOf(source["object"]))
		if err != nil || sourcecorpus.SHA(data) != digest || source["byteLength"] != int64(len(data)) {
			return ErrRejected
		}
	}
	return nil
}

func adapterMatchesExactTagSnapshot(directory string, snapshot map[string]any, r exactTagRequest) bool {
	raw, err := sourcecorpus.ReadPrivateTreeFile(directory, "SOURCE-CORPUS-MANIFEST.json", 256<<10)
	if err != nil {
		return false
	}
	value, err := sourcecorpus.DecodeBounded(bytes.TrimSpace(raw), 256<<10)
	manifest, ok := value.(map[string]any)
	if err != nil || !ok || manifest["revision"] != onboardingRevision(request{repo: r.repo}) {
		return false
	}
	records, ok := manifest["records"].([]any)
	if !ok || len(records) != len(snapshot["sources"].([]any)) {
		return false
	}
	byID := map[string]map[string]any{}
	for _, item := range records {
		record, ok := item.(map[string]any)
		if !ok || stringOf(record["id"]) == "" || byID[stringOf(record["id"])] != nil {
			return false
		}
		byID[stringOf(record["id"])] = record
	}
	for _, item := range snapshot["sources"].([]any) {
		source := item.(map[string]any)
		record := byID[stringOf(source["id"])]
		if record == nil {
			return false
		}
		recordSource, sourceOK := record["source"].(map[string]any)
		project, projectOK := record["project"].(map[string]any)
		capture, captureOK := record["capture"].(map[string]any)
		declarations, declarationsOK := record["declarations"].(map[string]any)
		ruleIDs, ruleIDsOK := declarations["ruleIDs"].([]any)
		if !sourceOK || !projectOK || !captureOK || !declarationsOK || !ruleIDsOK || !exact(declarations, "packetDigest", "ruleIDs") || declarations["packetDigest"] != nil || len(ruleIDs) != 0 || project["slug"] != r.slug || project["canonicalRepositoryURL"] != r.repo || recordSource["repositoryURL"] != r.repo || recordSource["sourceKind"] != "changelog" || recordSource["version"] != source["version"] || recordSource["commit"] != source["commit"] || recordSource["immutableURL"] != source["immutableURL"] || recordSource["fileDigest"] != source["fileDigest"] || recordSource["byteLength"] != source["byteLength"] || capture["object"] != source["object"] || capture["capturedAt"] != snapshot["observedAt"] {
			return false
		}
		left, _ := sourcecorpus.Canonical(recordSource["spans"])
		right, _ := sourcecorpus.Canonical(source["spans"])
		if !bytes.Equal(left, right) {
			return false
		}
	}
	return true
}

func verifyExactTagLicense(snapshot map[string]any, r exactTagRequest, observations []any, read func(string) ([]byte, error)) error {
	if snapshot["license"] == nil {
		return nil
	}
	license, ok := snapshot["license"].(map[string]any)
	if !ok || !exact(license, "kind", "commit", "immutableURL", "fileDigest", "object", "byteLength", "disposition") || license["kind"] != "license" || license["disposition"] != r.license {
		return ErrRejected
	}
	anchorCommit := ""
	for _, value := range observations {
		observation := value.(map[string]any)
		if observation["tag"] == r.anchor {
			anchorCommit = stringOf(observation["peeledCommit"])
			break
		}
	}
	commitValue, digest := stringOf(license["commit"]), stringOf(license["fileDigest"])
	immutable, err := sourcecorpus.ValidateImmutableURL(license["immutableURL"], r.repo, commitValue)
	if err != nil || anchorCommit == "" || commitValue != anchorCommit || !hasFixedLicensePath(immutable, r.repo, commitValue) || !validDigest(license["fileDigest"]) || stringOf(license["object"]) != "sha256/"+strings.TrimPrefix(digest, "sha256:") {
		return ErrRejected
	}
	data, err := read(stringOf(license["object"]))
	if err != nil || sourcecorpus.SHA(data) != digest || license["byteLength"] != int64(len(data)) {
		return ErrRejected
	}
	return nil
}

// validExactTagLineage checks the current snapshot's self-contained closed
// statement. It deliberately does not treat it as proof of prior evidence;
// that requires runExactTagVerify with --previous.
func validExactTagLineage(value any, tags []string, observations []any) bool {
	if value == nil {
		return true
	}
	l, ok := value.(map[string]any)
	if !ok || !exact(l, "previousSnapshotDigest", "sharedTags", "newlySelectedTags", "omittedPriorTags", "sharedBindingState", "omittedState", "scope") || !validDigest(l["previousSnapshotDigest"]) || l["sharedBindingState"] != "REOBSERVED_UNCHANGED" || l["omittedState"] != "NOT_REOBSERVED_NOT_REVALIDATED" || l["scope"] != "IMMEDIATE_PREVIOUS_SELECTION_SHARED_TAG_BINDINGS_ONLY" {
		return false
	}
	decode := func(v any) ([]string, bool) {
		raw, ok := v.([]any)
		if !ok {
			return nil, false
		}
		out := make([]string, len(raw))
		last := ""
		for i, x := range raw {
			s := stringOf(x)
			if !tagRE.MatchString(s) || (i > 0 && s <= last) {
				return nil, false
			}
			out[i] = s
			last = s
		}
		return out, true
	}
	shared, ok := decode(l["sharedTags"])
	if !ok {
		return false
	}
	newer, ok := decode(l["newlySelectedTags"])
	if !ok {
		return false
	}
	omitted, ok := decode(l["omittedPriorTags"])
	if !ok {
		return false
	}
	if priorCount := len(shared) + len(omitted); priorCount < 1 || priorCount > 10 {
		return false
	}
	selected := map[string]bool{}
	for _, t := range tags {
		selected[t] = true
	}
	seen := map[string]bool{}
	for _, t := range shared {
		if !selected[t] || seen[t] {
			return false
		}
		seen[t] = true
	}
	for _, t := range newer {
		if !selected[t] || seen[t] {
			return false
		}
		seen[t] = true
	}
	if len(seen) != len(selected) {
		return false
	}
	for _, t := range omitted {
		if selected[t] || seen[t] {
			return false
		}
		seen[t] = true
	}
	observed := map[string]bool{}
	for _, v := range observations {
		x, ok := v.(map[string]any)
		if !ok {
			return false
		}
		observed[stringOf(x["tag"])] = true
	}
	for t := range selected {
		if !observed[t] {
			return false
		}
	}
	return true
}

func runExactTagVerify(args []string, stdout, stderr io.Writer) int {
	s, _, e := VerifySnapshot(args[1])
	if e != nil {
		return reject(stderr)
	}
	lineage := "CONTINUITY_NOT_REPLAYED_PREVIOUS_NOT_SUPPLIED"
	if s["lineage"] == nil {
		lineage = "NO_PREVIOUS_SNAPSHOT"
	}
	if len(args) == 4 {
		prior, _, err := VerifySnapshot(args[3])
		if err != nil || prior["schema"] != ExactTagSnapshotSchema {
			return reject(stderr)
		}
		currentRepository, currentOK := s["repository"].(map[string]any)
		priorRepository, priorOK := prior["repository"].(map[string]any)
		if !currentOK || !priorOK || currentRepository["repositoryID"] != priorRepository["repositoryID"] {
			return reject(stderr)
		}
		requestRaw, _ := sourcecorpus.Canonical(s["request"])
		r, err := parseExactTagRequest(requestRaw)
		if err != nil {
			return reject(stderr)
		}
		observations, ok := s["tagObservations"].([]any)
		if !ok {
			return reject(stderr)
		}
		computed, err := exactTagLineage(prior, r, observations)
		if err != nil || s["lineage"] == nil {
			return reject(stderr)
		}
		if digestMust(prior) != stringOf(s["lineage"].(map[string]any)["previousSnapshotDigest"]) {
			return reject(stderr)
		}
		want, _ := sourcecorpus.Canonical(computed)
		got, _ := sourcecorpus.Canonical(s["lineage"])
		if !bytes.Equal(want, got) {
			return reject(stderr)
		}
		lineage = "CONTINUITY_REPLAYED_VERIFIED"
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-onboarding-verification/v2", "snapshotDigest": digestMust(s), "verification": "VERIFIED_RETAINED_EXACT_TAG_OBSERVATIONS", "continuity": lineage, "reviewState": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}) != nil {
		return reject(stderr)
	}
	return 0
}
func runExactTagStatus(args []string, stdout, stderr io.Writer) int {
	s, _, e := VerifySnapshot(args[1])
	if e != nil {
		return reject(stderr)
	}
	continuity := "NO_PREVIOUS_SNAPSHOT"
	if s["lineage"] != nil {
		continuity = "CONTINUITY_NOT_REPLAYED_PREVIOUS_NOT_SUPPLIED"
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-onboarding-status/v2", "snapshotDigest": digestMust(s), "repository": publicRepository(s), "tagCount": int64(len(s["tagObservations"].([]any))), "sourceCount": int64(len(s["sources"].([]any))), "freshness": "NOT_CHECKED_OFFLINE", "upstreamContinuity": continuity, "lineage": s["lineage"], "review": s["review"]}) != nil {
		return reject(stderr)
	}
	return 0
}
func runExactTagInspect(path, tag string, notes bool, stdout, stderr io.Writer) int {
	if notes {
		return reject(stderr)
	}
	s, _, e := VerifySnapshot(path)
	if e != nil {
		return reject(stderr)
	}
	out := []any{}
	for _, v := range s["tagObservations"].([]any) {
		if tag == "" || v.(map[string]any)["tag"] == tag {
			out = append(out, v)
		}
	}
	if tag != "" && len(out) == 0 {
		return reject(stderr)
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-onboarding-inspection/v2", "repository": s["repository"], "tagObservations": out, "sources": s["sources"], "license": s["license"], "lineage": s["lineage"], "review": s["review"]}) != nil {
		return reject(stderr)
	}
	return 0
}
func runExactTagProposal(args []string, stdout, stderr io.Writer) int {
	s, _, e := VerifySnapshot(args[1])
	if e != nil {
		return reject(stderr)
	}
	tags := []any{}
	for _, v := range s["tagObservations"].([]any) {
		x := v.(map[string]any)
		tags = append(tags, map[string]any{"tag": x["tag"], "refTargetKind": x["refTargetKind"], "refTargetSHA": x["refTargetSHA"], "annotatedTagSHA": x["annotatedTagSHA"], "peeledCommit": x["peeledCommit"]})
	}
	sources := make([]any, 0, len(s["sources"].([]any)))
	for _, value := range s["sources"].([]any) {
		source := value.(map[string]any)
		sources = append(sources, map[string]any{"id": source["id"], "kind": source["kind"], "version": source["version"], "commit": source["commit"], "immutableURL": source["immutableURL"], "fileDigest": source["fileDigest"], "byteLength": source["byteLength"], "spans": source["spans"], "captureState": source["captureState"]})
	}
	var license any
	if retained, ok := s["license"].(map[string]any); ok {
		license = map[string]any{"kind": retained["kind"], "commit": retained["commit"], "immutableURL": retained["immutableURL"], "fileDigest": retained["fileDigest"], "byteLength": retained["byteLength"], "disposition": retained["disposition"]}
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-source-only-proposal/v2", "snapshotDigest": digestMust(s), "observedAt": s["observedAt"], "repository": publicRepository(s), "tagObservations": tags, "sources": sources, "license": license, "lineage": s["lineage"], "request": "INDEPENDENT_REVIEW_REQUIRED", "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}, "limitations": []any{"references and digests only; raw objects are deliberately excluded", "this proposal does not approve support, ownership, a rule, compatibility, signing, or publication"}}) != nil {
		return reject(stderr)
	}
	return 0
}
