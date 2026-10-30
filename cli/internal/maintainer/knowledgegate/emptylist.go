// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// Admission of an empty-list mechanical line attestation. A mechanical
// attestation is admitted by re-derivation (rederive). One that lists no
// rule claims that a whole line removes nothing, which makes a missing
// removal look like a verified absence, so on top of re-derivation it must
// meet five conditions, each with a stable refusal code. The detail of a
// refused change starts "empty-list/<code>: ".
//
// Order: the checks that need no upstream run before the change is handed
// to re-derivation (a refused change is never re-derived, so it never gets
// Proof=rederived); the checks that need the tags or the extractor's own
// output run after it and may only refuse; the citation contents are
// checked by the citations check, whose findings are attached last.
//
// The scheduled re-derivation of unchanged records (RederiveAll) does not
// pass through these checks: an unchanged record is not a loosening.
// Refusal codes, in the detail of a refused change as "empty-list/<code>".
const (
	emptyListTargetNotAttesting = "target-not-attesting"
	emptyListExtractorDigest    = "extractor-digest"
	emptyListCitation           = "citation"
	emptyListFreshness          = "freshness"
	emptyListReleasesIncomplete = "releases-incomplete"
	emptyListNewestPairNotEmpty = "newest-pair-not-empty"

	// emptyListMinRemainingLease is how long an empty-list attestation must
	// still be valid at the gate's clock.
	emptyListMinRemainingLease = 14 * 24 * time.Hour
	emptyListCheckName         = "empty-list"
)

var (
	commitHexRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	k8sFinalTagRE = regexp.MustCompile(`^v1\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
)

func emptyListErr(code, format string, args ...any) error {
	return fmt.Errorf("empty-list/%s: %s", code, fmt.Sprintf(format, args...))
}

// isEmptyListChange reports whether c is in the scope of this file: a new or
// loosened mechanical line attestation that lists no rule.
func isEmptyListChange(c *Change) bool {
	return c.Class == ClassLoosening && c.rhead != nil && c.rhead.attestation != nil && c.rhead.mechanical() && len(c.rhead.attestation.RuleIDs) == 0
}

// attestsScope reports whether ex is an extractor that attests family for
// component: it declares the family and, when it names the component it
// attests, that is component; one that does not is accepted only for a
// family with exactly that one component.
func attestsScope(ex extract.Extractor, family, component string, f lineattest.Family) bool {
	attester, ok := ex.(extract.LineAttester)
	if !ok || !slices.Contains(attester.AttestedFamilies(), family) {
		return false
	}
	if ca, named := ex.(extract.ComponentAttester); named {
		return ca.AttestedComponent() == component
	}
	return slices.Equal(f.Components(), []string{component})
}

// emptyListPre runs the checks of an empty-list change that need no upstream:
// target-not-attesting, extractor-digest, citation structure and freshness.
// It returns nil for any change outside the scope.
func emptyListPre(c *Change, opts Options) error {
	if !isEmptyListChange(c) {
		return nil
	}
	rec, a := c.rhead, c.rhead.attestation
	x := rec.Extractor
	if x == nil {
		return emptyListErr(emptyListTargetNotAttesting, "re-derivation failed: the record names no extractor")
	}
	spec, ok := opts.Catalog[x.ID]
	if !ok {
		return emptyListErr(emptyListTargetNotAttesting, "re-derivation failed: unknown extractor %q", logSafe(x.ID))
	}
	f, ok := lineattest.LookupFamily(a.FactFamily)
	if !ok || !f.Admits(a.Component) {
		return emptyListErr(emptyListTargetNotAttesting, "re-derivation failed: fact family %s does not cover %s", logSafe(a.FactFamily), logSafe(a.Component))
	}
	ex := spec.New(1)
	if !attestsScope(ex, a.FactFamily, a.Component, f) {
		return emptyListErr(emptyListTargetNotAttesting, "re-derivation failed: extractor %s does not attest %s for %s", logSafe(x.ID), logSafe(a.FactFamily), logSafe(a.Component))
	}

	// C2: the identity the record names is the identity this binary ships.
	src, ok := ex.(extract.CodeSource)
	if !ok {
		return emptyListErr(emptyListExtractorDigest, "extractor %s does not expose its source for the code digest", logSafe(x.ID))
	}
	dir, own := src.SourceFiles()
	files, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: dir, Files: own})
	if err != nil {
		return emptyListErr(emptyListExtractorDigest, "the code digest of extractor %s cannot be computed: %v", logSafe(x.ID), err)
	}
	shipped := constraintengine.Extractor{ID: ex.ID(), Version: ex.Version(), CodeDigest: extract.CodeDigest(files)}
	if *x != shipped {
		return emptyListErr(emptyListExtractorDigest, "re-derivation failed: the record names extractor %s %s %s, this gate runs %s %s %s",
			logSafe(x.ID), logSafe(x.Version), logSafe(x.CodeDigest), shipped.ID, shipped.Version, shipped.CodeDigest)
	}

	// C3: the citations are immutable blob URLs of the extractor's repository.
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		return emptyListErr(emptyListCitation, "%v", err)
	}
	if err := emptyListCitationShape(repo, *a); err != nil {
		return err
	}

	// C4: derived recently, and valid for long enough to be reviewed.
	if err := freshRecordDerivation(rec, opts.Now); err != nil {
		return emptyListErr(emptyListFreshness, "%v", err)
	}
	until, err := time.Parse(time.RFC3339, rec.ValidUntil)
	if err != nil {
		return emptyListErr(emptyListFreshness, "validUntil %q is not a time", logSafe(rec.ValidUntil))
	}
	if !until.After(opts.Now.Add(emptyListMinRemainingLease)) {
		return emptyListErr(emptyListFreshness, "validUntil %s is not more than %d days after the gate's clock %s", until.UTC().Format(time.RFC3339), int(emptyListMinRemainingLease/(24*time.Hour)), opts.Now.UTC().Format(time.RFC3339))
	}
	return nil
}

// emptyListCitationShape checks the form of every cited source and release
// commit. The content digests and line spans are read upstream by the
// citations check.
func emptyListCitationShape(repo extract.RepoRef, a lineattest.LineAttestation) error {
	if len(a.Evidence.Sources) == 0 {
		return emptyListErr(emptyListCitation, "the record cites no source")
	}
	for _, s := range a.Evidence.Sources {
		if !commitHexRE.MatchString(s.Revision) {
			return emptyListErr(emptyListCitation, "source %s: revision %q is not a full 40-hex commit", logSafe(s.ID), logSafe(s.Revision))
		}
		prefix := repo.BlobURL(s.Revision, "")
		if !strings.HasPrefix(s.URL, prefix) {
			return emptyListErr(emptyListCitation, "source %s: url %q is not an immutable blob URL of %s at its revision", logSafe(s.ID), logSafe(s.URL), repo.Key)
		}
		p := strings.TrimPrefix(s.URL, prefix)
		if p == "" || strings.ContainsAny(p, "?#\\") || strings.HasPrefix(p, "/") || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
			return emptyListErr(emptyListCitation, "source %s: url %q has no clean file path, or carries a query or fragment", logSafe(s.ID), logSafe(s.URL))
		}
		if s.StartLine < 1 || s.EndLine < s.StartLine {
			return emptyListErr(emptyListCitation, "source %s: lines %d-%d are not a span", logSafe(s.ID), s.StartLine, s.EndLine)
		}
	}
	if a.Releases != nil {
		for _, list := range [][]lineattest.Release{a.Releases.From, a.Releases.To} {
			for _, r := range list {
				if !commitHexRE.MatchString(r.Commit) {
					return emptyListErr(emptyListCitation, "release %s: commit %q is not a full 40-hex commit", logSafe(r.Version), logSafe(r.Commit))
				}
			}
		}
	}
	return nil
}

// emptyListPost runs, after re-derivation, C5 (the newest pair of every
// component and family is empty in the gate's own derivation) and C1 (the
// releases are exactly the final releases the tags list). changes are all
// the changes of the run; it only ever refuses.
func emptyListPost(changes []*Change, opts Options) {
	var all []*Change
	for _, c := range changes {
		if isEmptyListChange(c) {
			all = append(all, c)
		}
	}
	if len(all) == 0 {
		return
	}

	// C5: any group whose newest line is not derived empty by this run
	// refuses the whole batch.
	type group struct{ component, family string }
	newest := map[group]*Change{}
	for _, c := range all {
		a := c.rhead.attestation
		g := group{a.Component, a.FactFamily}
		if n := newest[g]; n == nil || lineattest.LineLess(n.rhead.attestation.Line, a.Line) {
			newest[g] = c
		}
	}
	var bad []string
	for g, n := range newest {
		if !derivedEmpty(n) {
			bad = append(bad, fmt.Sprintf("%s %s line %s", logSafe(g.component), logSafe(g.family), logSafe(n.rhead.attestation.Line)))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		for _, c := range all {
			c.failFirst(emptyListErr(emptyListNewestPairNotEmpty, "the newest line of a group in this change is not derived empty by the gate's own run: %s", strings.Join(bad, "; ")).Error())
		}
	}

	// C1: only for a change re-derivation admitted.
	tags := map[string][]extract.Tag{}
	for _, c := range all {
		if !c.OK {
			continue
		}
		if err := releasesComplete(c, opts, tags); err != nil {
			c.fail(err.Error())
		}
	}
}

// failFirst records detail unless the change is already refused: the first
// reason stays.
func (c *Change) failFirst(detail string) {
	if !c.OK && c.Detail != "" {
		return
	}
	c.fail(detail)
}

// derivedEmpty reports whether the extractor's own record for c's scope was
// derived by this run and lists no rule.
func derivedEmpty(c *Change) bool {
	raw, ok := c.derivedGroup[c.RuleID]
	if !ok || !c.OK {
		return false
	}
	var derived struct {
		RuleIDs []string `json:"ruleIds"`
	}
	return json.Unmarshal(raw, &derived) == nil && len(derived.RuleIDs) == 0
}

// releasesComplete is C1: the final releases the repository's tags show for
// the line and its predecessor are exactly the ones the record names (CRD
// family), or the two minor-release anchors the record cites exist at the
// commits it cites (Kubernetes). It reads nothing but the tag list, and does
// not ask the extractor.
func releasesComplete(c *Change, opts Options, tagCache map[string][]extract.Tag) error {
	a := c.rhead.attestation
	spec := opts.Catalog[c.rhead.Extractor.ID]
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		return emptyListErr(emptyListReleasesIncomplete, "%v", err)
	}
	if opts.Source == nil {
		return emptyListErr(emptyListReleasesIncomplete, "no upstream source is configured to list the tags")
	}
	list, ok := tagCache[repo.Key]
	if !ok {
		list, err = opts.Source.Tags(repo)
		if err != nil {
			return emptyListErr(emptyListReleasesIncomplete, "the tags of %s cannot be listed: %v", repo.Key, err)
		}
		tagCache[repo.Key] = list
	}
	f, _ := lineattest.LookupFamily(a.FactFamily)
	switch {
	case f.ReleaseScoped():
		return crdReleasesComplete(c, list)
	case a.FactFamily == lineattest.FamilyKubernetesRemovedServedGVK:
		return kubernetesAnchorsComplete(*a, list)
	}
	return emptyListErr(emptyListReleasesIncomplete, "no release rule is defined for fact family %s", logSafe(a.FactFamily))
}

// finalReleases lists the final release tags of line under the prefixes,
// ascending by version. A version tagged twice at one commit counts once; at
// two commits, or a matching tag with no full commit, is an error. A target
// with a release scheme reads its tags with the scheme's grammar
// (crdversions.CalverEdgeRelease) instead of the prefixes.
func finalReleases(tags []extract.Tag, prefixes []string, scheme, line string) ([]lineattest.Release, error) {
	byVersion := map[string]string{}
	// A line with a tag of a zero-padded minor (v26.02.0) and one of the
	// canonical minor (v26.2.0) has ambiguous releases.
	var sawPadded, sawCanonical bool
	for _, t := range tags {
		var versions []string
		if scheme == crdversions.SchemeCalverEdge {
			if v, _, ok := crdversions.CalverEdgeRelease(t.Name); ok {
				versions = append(versions, v)
			} else if l, bad := crdversions.CalverEdgeUnread(t.Name); bad && l == line {
				// Shaped like a release of this line but not read: the
				// line's releases are not known.
				return nil, fmt.Errorf("tag %s has the shape of a release of line %s that the release grammar does not read", logSafe(t.Name), line)
			}
		}
		paddedOf := map[string]bool{}
		for _, p := range prefixes {
			if v, padded, ok := crdversions.ReadFinalTag(p, 9, t.Name); ok {
				versions = append(versions, v)
				paddedOf[v] = padded
			}
		}
		for _, version := range versions {
			if l, ok := lineattest.LineOf(version); !ok || l != line {
				continue
			}
			if paddedOf[version] {
				sawPadded = true
			} else {
				sawCanonical = true
			}
			if sawPadded && sawCanonical {
				return nil, fmt.Errorf("line %s has release tags with a zero-padded minor and with a canonical minor, so its releases are ambiguous", line)
			}
			if !commitHexRE.MatchString(t.Commit) {
				return nil, fmt.Errorf("tag %s has no full commit", logSafe(t.Name))
			}
			if prev, dup := byVersion[version]; dup && prev != t.Commit {
				return nil, fmt.Errorf("version %s is tagged at two commits", version)
			}
			byVersion[version] = t.Commit
		}
	}
	out := make([]lineattest.Release, 0, len(byVersion))
	for v, commit := range byVersion {
		out = append(out, lineattest.Release{Version: v, Commit: commit})
	}
	sort.Slice(out, func(i, j int) bool { return constraintengine.VersionLess(out[i].Version, out[j].Version) })
	return out, nil
}

func crdReleasesComplete(c *Change, tags []extract.Tag) error {
	a := c.rhead.attestation
	id := c.rhead.Extractor.ID
	target, ok := crdversions.TargetFor(strings.TrimPrefix(id, crdversions.IDPrefix))
	if !strings.HasPrefix(id, crdversions.IDPrefix) || !ok {
		return emptyListErr(emptyListReleasesIncomplete, "extractor %s names no custom-resource target", logSafe(id))
	}
	return crdReleasesMatch(target, a, tags)
}

// crdReleasesMatch compares the releases an attestation names with the final
// release tags of its line and of its previous line (lineattest.PreviousLine).
func crdReleasesMatch(target crdversions.Target, a *lineattest.LineAttestation, tags []extract.Tag) error {
	previous, ok := lineattest.PreviousLine(a.Component, a.Line)
	if !ok || a.Releases == nil {
		return emptyListErr(emptyListReleasesIncomplete, "line %s has no previous minor line or the record names no releases", logSafe(a.Line))
	}
	for _, side := range []struct {
		name string
		line string
		have []lineattest.Release
	}{{"releases.from", previous, a.Releases.From}, {"releases.to", a.Line, a.Releases.To}} {
		want, err := finalReleases(tags, target.TagPrefixes, target.ReleaseScheme, side.line)
		if err != nil {
			return emptyListErr(emptyListReleasesIncomplete, "line %s: %v", side.line, err)
		}
		if len(want) == 0 || len(want) > lineattest.MaxReleases {
			return emptyListErr(emptyListReleasesIncomplete, "line %s has %d final releases in the tags, want 1-%d", side.line, len(want), lineattest.MaxReleases)
		}
		if !slices.Equal(want, side.have) {
			return emptyListErr(emptyListReleasesIncomplete, "%s is not exactly the %d final releases of line %s the tags show", side.name, len(want), side.line)
		}
	}
	return nil
}

// kubernetesAnchorsComplete is C1 for the Kubernetes family, which names no
// releases: Kubernetes removes a served API version only at the .0 release of
// a minor line, so what the attestation reads are the two anchors v1.(L-1).0
// and v1.L.0. The patch releases are not required.
func kubernetesAnchorsComplete(a lineattest.LineAttestation, tags []extract.Tag) error {
	major, minor, _ := strings.Cut(a.Line, ".")
	l, err := strconv.Atoi(minor)
	if major != "1" || err != nil || l-1 < k8sservedapis.MinFromMinor {
		return emptyListErr(emptyListReleasesIncomplete, "line %s is not a line v1.%d and later have an anchor pair for", logSafe(a.Line), k8sservedapis.MinFromMinor+1)
	}
	anchors := map[int]string{}
	for _, t := range tags {
		m := k8sFinalTagRE.FindStringSubmatch(t.Name)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		if n != l-1 && n != l {
			continue
		}
		if !commitHexRE.MatchString(t.Commit) {
			return emptyListErr(emptyListReleasesIncomplete, "tag %s has no full commit", logSafe(t.Name))
		}
		if m[2] != "0" {
			continue
		}
		if prev, dup := anchors[n]; dup && prev != t.Commit {
			return emptyListErr(emptyListReleasesIncomplete, "tag %s names two commits", logSafe(t.Name))
		}
		anchors[n] = t.Commit
	}
	for i, n := range []int{l - 1, l} {
		commit, ok := anchors[n]
		if !ok {
			return emptyListErr(emptyListReleasesIncomplete, "no final tag v1.%d.0 in the tags", n)
		}
		want := fmt.Sprintf("openapi-1-%d-0", n)
		found := false
		for _, s := range a.Evidence.Sources {
			if s.ID == want {
				found = s.Revision == commit
			}
		}
		if !found {
			return emptyListErr(emptyListReleasesIncomplete, "source %s (anchor %d of 2) is not cited at the commit of tag v1.%d.0", want, i+1, n)
		}
	}
	return nil
}

// emptyListCitations attaches the citations check's findings to the
// empty-list changes they name, and reports the empty-list check when the
// change set holds any such change.
func (r *Report) emptyListCitations(cls *Classification) {
	var all []*Change
	for _, c := range cls.Changes {
		if isEmptyListChange(c) {
			all = append(all, c)
		}
	}
	if len(all) == 0 {
		return
	}
	// The upstream half of condition 3 (digest, span) lives in the citations
	// check: when it did not run or did not pass, no empty list is admitted.
	citationsOK, citationsDetail := false, "the citations check did not run"
	for _, ck := range r.Checks {
		if ck.Name == CheckCitations {
			citationsOK, citationsDetail = ck.OK, ck.Detail
		}
	}
	for _, c := range all {
		id := rulecheck.AttestationCitationItem(*c.rhead.attestation).ID
		named := false
		for _, f := range r.citationFindings {
			if f.RuleID == id {
				c.failFirst(emptyListErr(emptyListCitation, "source %s [%s]: %s", logSafe(f.SourceID), f.Check, logSafe(f.Message)).Error())
				named = true
				break
			}
		}
		if !named && !citationsOK {
			c.failFirst(emptyListErr(emptyListCitation, "the citations check did not pass: %s", logSafe(citationsDetail)).Error())
		}
	}
	var failed []string
	for _, c := range all {
		if !c.OK {
			failed = append(failed, c.RuleID+": "+c.Detail)
		}
	}
	r.add(emptyListCheckName, len(failed) == 0, "%d empty-list line attestations, %d refused%s", len(all), len(failed), listDetail(failed))
}
