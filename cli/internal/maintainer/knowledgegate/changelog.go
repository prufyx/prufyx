// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogattest"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// Admission of a changelog-attested line attestation (fact family
// lineattest.FamilyChangelogAttestedEntries). The family is admitted ONLY
// through this file: the generic extractor framework (extract.Run) cannot
// state such an attestation, because it requires an attestation to list
// exactly the extractor's own rules and the rules of this family are
// reviewed. So the gate does not ask the catalog and never trusts a stated
// record. It re-derives the record on its own, with changelogattest and
// changelogentries, from the pinned sources, the reviewed target row, the
// reviewed dispositions of the head tree and the head pack's rules, and
// admits the record only when the re-derived record is byte-equal.
//
// The detail of a refused change starts "changelog/<code>: ". Order, as in
// the empty-list admission: the checks that need no upstream run first and
// hand the change to re-derivation only when they pass; the release list
// and the extractor's own output are read after; the citation contents are
// checked by the citations check, whose findings are attached last.
//
// An unchanged record (RederiveAll) is re-derived the same way but is not
// held to the lease and freshness conditions: those are conditions of an
// admission, not of a record in force.
const (
	// The record names no extractor, no reviewed target row or no
	// dispositions file, is not mechanical, or names a component that is not
	// a member of the family's table.
	changelogTargetNotAttesting = "target-not-attesting"
	// The identity the record names is not the identity this binary ships.
	changelogExtractorDigest = "extractor-digest"
	// The record's citations are not one immutable blob URL per window tag at
	// the tag's commit with a content digest and a line span; or the
	// citations check found a source that does not match upstream.
	changelogCitation = "citation"
	// The derivation is not recent, or the lease is shorter than the
	// minimum.
	changelogFreshness = "freshness"
	// The releases the record names are not exactly the final releases the
	// tags show.
	changelogReleasesIncomplete = "releases-incomplete"
	// The dispositions file is not strict reviewed data: a mark is not in the
	// reviewed state, is future-dated, has an unknown proposer or kind, ...
	changelogMarkProvenance = "mark-provenance"
	// An entry at the newest final tag holds an item its own tag's read lacks.
	changelogEntryAmended = "entry-amended"
	// The re-derivation withholds the pair (the typed reason is in the
	// detail), cannot run, or differs byte for byte from the record.
	changelogRederivation = "rederivation"

	// changelogMinRemainingLease is how long an admitted attestation must
	// still be valid at the gate's clock.
	changelogMinRemainingLease = 14 * 24 * time.Hour
	changelogCheckName         = "changelog"
)

// ChangelogConfig is the reviewed data the changelog admission reads
// besides the pack. The zero value admits nothing: no target row, no
// dispositions.
type ChangelogConfig struct {
	// Targets is the reviewed table of changelog sources by component.
	Targets map[string]ce.Target
	// DispositionsDir is the directory of the head tree that holds one
	// reviewed dispositions file per component, named <slug>.json after the
	// extractor id changelog.entries.<slug>.
	DispositionsDir string
}

func changelogErr(code, format string, args ...any) error {
	return fmt.Errorf("changelog/%s: %s", code, fmt.Sprintf(format, args...))
}

// isChangelogRecord reports whether c is a record of the changelog family,
// whatever its basis.
func isChangelogRecord(c *Change) bool {
	return c != nil && c.rhead != nil && c.rhead.attestation != nil && c.rhead.attestation.FactFamily == lineattest.FamilyChangelogAttestedEntries
}

// changelogPrep is what a re-derivation reads, established by changelogPre.
type changelogPrep struct {
	slug     string
	identity constraintengine.Extractor
	cfg      changelogattest.Config
}

var dispositionsSlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (o Options) changelogMember(component string) bool {
	if o.changelogAdmits != nil {
		return o.changelogAdmits(component)
	}
	f, ok := lineattest.LookupFamily(lineattest.FamilyChangelogAttestedEntries)
	return ok && f.Admits(component)
}

// changelogPre runs the checks of a changelog record that need no upstream.
// admission is true for a change (lease and freshness apply), false for a
// record already in force.
func changelogPre(c *Change, head *loadedPack, opts Options, admission bool) (*changelogPrep, error) {
	rec, a := c.rhead, c.rhead.attestation
	if !rec.mechanical() {
		return nil, changelogErr(changelogTargetNotAttesting, "a changelog-attested record is admitted only as a mechanical re-derivation, never by a statement or an approval")
	}
	x := rec.Extractor
	if x == nil {
		return nil, changelogErr(changelogTargetNotAttesting, "re-derivation failed: the record names no extractor")
	}
	if !opts.changelogMember(a.Component) {
		return nil, changelogErr(changelogTargetNotAttesting, "re-derivation failed: %s is not a member of the changelog family table", logSafe(a.Component))
	}
	tgt, ok := opts.Changelog.Targets[a.Component]
	if !ok || tgt.Component != a.Component {
		return nil, changelogErr(changelogTargetNotAttesting, "re-derivation failed: no reviewed changelog target for %s", logSafe(a.Component))
	}
	slug, ok := strings.CutPrefix(x.ID, changelogattest.IDPrefix)
	if !ok || !dispositionsSlugRE.MatchString(slug) {
		return nil, changelogErr(changelogTargetNotAttesting, "re-derivation failed: %q is not a changelog extractor", logSafe(x.ID))
	}

	// The identity the record names is the identity this binary ships.
	files, err := extract.CodeFiles(extract.FrameworkSource(), changelogattest.SourceSet())
	if err != nil {
		return nil, changelogErr(changelogExtractorDigest, "the code digest of extractor %s cannot be computed: %v", logSafe(x.ID), err)
	}
	shipped := constraintengine.Extractor{ID: changelogattest.IDPrefix + slug, Version: changelogattest.Version, CodeDigest: extract.CodeDigest(files)}
	if *x != shipped {
		return nil, changelogErr(changelogExtractorDigest, "re-derivation failed: the record names extractor %s %s %s, this gate runs %s %s %s",
			logSafe(x.ID), logSafe(x.Version), logSafe(x.CodeDigest), shipped.ID, shipped.Version, shipped.CodeDigest)
	}

	// The reviewed dispositions of the head tree: strict reviewed data.
	if opts.Changelog.DispositionsDir == "" {
		return nil, changelogErr(changelogTargetNotAttesting, "no dispositions directory is configured")
	}
	raw, err := opts.Head.Read(path.Join(opts.Changelog.DispositionsDir, slug+".json"), changelogattest.MaxFileBytes)
	if errors.Is(err, ErrMissing) {
		return nil, changelogErr(changelogTargetNotAttesting, "re-derivation failed: no dispositions file for %s", logSafe(slug))
	}
	if err != nil {
		return nil, changelogErr(changelogMarkProvenance, "the dispositions file of %s cannot be read: %v", logSafe(slug), err)
	}
	disp, err := changelogattest.LoadDispositions(raw, a.Component)
	if err != nil {
		return nil, changelogErr(changelogMarkProvenance, "%v", err)
	}
	if err := checkMarkProvenance(disp, opts.Now); err != nil {
		return nil, err
	}

	// The pack's rules, as the attestation reads them.
	if head == nil {
		return nil, changelogErr(changelogTargetNotAttesting, "the head pack is not loaded")
	}
	var rules []json.RawMessage
	for _, id := range head.Order {
		var shape struct {
			Rule json.RawMessage `json:"rule"`
		}
		if err := json.Unmarshal(head.Entries[id].Raw, &shape); err != nil || len(shape.Rule) == 0 {
			return nil, changelogErr(changelogTargetNotAttesting, "rule %s of the head pack cannot be read", logSafe(id))
		}
		rules = append(rules, shape.Rule)
	}
	prep := &changelogPrep{slug: slug, identity: shipped, cfg: changelogattest.Config{Target: tgt, Dispositions: disp, PackRules: rules}}

	if err := changelogCitationShape(tgt, *a); err != nil {
		return nil, err
	}
	if !admission {
		return prep, nil
	}
	if err := freshRecordDerivation(rec, opts.Now); err != nil {
		return nil, changelogErr(changelogFreshness, "%v", err)
	}
	until, err := time.Parse(time.RFC3339, rec.ValidUntil)
	if err != nil {
		return nil, changelogErr(changelogFreshness, "validUntil %q is not a time", logSafe(rec.ValidUntil))
	}
	if !until.After(opts.Now.Add(changelogMinRemainingLease)) {
		return nil, changelogErr(changelogFreshness, "validUntil %s is not more than %d days after the gate's clock %s", until.UTC().Format(time.RFC3339), int(changelogMinRemainingLease/(24*time.Hour)), opts.Now.UTC().Format(time.RFC3339))
	}
	return prep, nil
}

// checkMarkProvenance is the gate's own reading of who reviewed each mark,
// on top of LoadDispositions: every mark is in the reviewed state (a model's
// proposal that no person reviewed is refused, whatever it says), names a
// known proposer, and is not dated after the gate's clock.
func checkMarkProvenance(d *changelogattest.Dispositions, now time.Time) error {
	for i, m := range d.Marks {
		if m.State != changelogattest.StateReviewed {
			return changelogErr(changelogMarkProvenance, "mark %d (%s) is %q, not reviewed", i, logSafe(m.ProposedBy), logSafe(m.State))
		}
		if m.ProposedBy != changelogattest.ProposedByModel && m.ProposedBy != changelogattest.ProposedByPerson {
			return changelogErr(changelogMarkProvenance, "mark %d has proposer %q", i, logSafe(m.ProposedBy))
		}
		at, err := time.Parse(time.RFC3339, m.ReviewedAt)
		if err != nil {
			return changelogErr(changelogMarkProvenance, "mark %d has no review time", i)
		}
		if at.After(now) {
			return changelogErr(changelogMarkProvenance, "mark %d is dated %s, after the gate's clock", i, m.ReviewedAt)
		}
	}
	return nil
}

// windowReleases is the window of a record, by its releases: the patch
// releases of the from line and every release of the to line. The first
// release of the from line describes the hop into it and is never read.
func windowReleases(a lineattest.LineAttestation) []lineattest.Release {
	var out []lineattest.Release
	if a.Releases == nil {
		return nil
	}
	for _, r := range a.Releases.From {
		if parts := strings.Split(r.Version, "."); len(parts) == 3 && parts[2] != "0" {
			out = append(out, r)
		}
	}
	return append(out, a.Releases.To...)
}

// changelogCitationShape checks the form of the citations: exactly one
// source per window tag, id changelog-<version>, at the tag's commit, the
// blob URL of the reviewed target's path, a sha256 content digest and a
// line span. The contents are read upstream by the citations check.
func changelogCitationShape(t ce.Target, a lineattest.LineAttestation) error {
	if a.Releases == nil {
		return changelogErr(changelogCitation, "the record names no releases")
	}
	window := windowReleases(a)
	if len(window) == 0 || len(a.Evidence.Sources) != len(window) {
		return changelogErr(changelogCitation, "the record cites %d sources, the window has %d tags", len(a.Evidence.Sources), len(window))
	}
	byID := map[string]constraintengine.SourceEvidence{}
	for _, s := range a.Evidence.Sources {
		if _, dup := byID[s.ID]; dup {
			return changelogErr(changelogCitation, "source %s is cited twice", logSafe(s.ID))
		}
		byID[s.ID] = s
	}
	for _, r := range window {
		id := "changelog-" + r.Version
		s, ok := byID[id]
		if !ok {
			return changelogErr(changelogCitation, "no source %s for the tag %s", id, r.Version)
		}
		if !commitHexRE.MatchString(s.Revision) || s.Revision != r.Commit {
			return changelogErr(changelogCitation, "source %s: revision %q is not the commit of tag %s", id, logSafe(s.Revision), r.Version)
		}
		if want := t.Repo.BlobURL(s.Revision, t.Path); s.URL != want {
			return changelogErr(changelogCitation, "source %s: url %q is not the immutable blob URL %q", id, logSafe(s.URL), want)
		}
		if d, ok := strings.CutPrefix(s.ContentDigest, "sha256:"); !ok || len(d) != 64 || strings.Trim(d, "0123456789abcdef") != "" {
			return changelogErr(changelogCitation, "source %s: contentDigest %q is not a sha256 digest", id, logSafe(s.ContentDigest))
		}
		if s.StartLine < 1 || s.EndLine < s.StartLine {
			return changelogErr(changelogCitation, "source %s: lines %d-%d are not a span", id, s.StartLine, s.EndLine)
		}
	}
	return nil
}

// changelogReleasesComplete is the release condition: the releases the
// record names are exactly the final releases the tags show for its line and
// the line before it.
func changelogReleasesComplete(a lineattest.LineAttestation, tags []extract.Tag) error {
	from, ok := a.FromLine()
	if !ok || a.Releases == nil {
		return changelogErr(changelogReleasesIncomplete, "line %s has no previous minor line or the record names no releases", logSafe(a.Line))
	}
	for _, side := range []struct {
		name, line string
		have       []lineattest.Release
	}{{"releases.from", from, a.Releases.From}, {"releases.to", a.Line, a.Releases.To}} {
		want, err := finalReleases(tags, []string{"v", ""}, "", side.line)
		if err != nil {
			return changelogErr(changelogReleasesIncomplete, "line %s: %v", side.line, err)
		}
		if len(want) == 0 || len(want) > lineattest.MaxReleases {
			return changelogErr(changelogReleasesIncomplete, "line %s has %d final releases in the tags, want 1-%d", side.line, len(want), lineattest.MaxReleases)
		}
		if !slices.Equal(want, side.have) {
			return changelogErr(changelogReleasesIncomplete, "%s is not exactly the %d final releases of line %s the tags show", side.name, len(want), side.line)
		}
	}
	return nil
}

// changelogRederive re-derives one record and sets OK and Proof, or the
// refusal. prep comes from changelogPre.
func changelogRederive(ctx context.Context, c *Change, prep *changelogPrep, opts Options) {
	if err := changelogRederiveErr(ctx, c, prep, opts); err != nil {
		c.fail(err.Error())
		return
	}
	c.OK, c.Proof = true, ProofRederived
}

func changelogRederiveErr(ctx context.Context, c *Change, prep *changelogPrep, opts Options) error {
	rec, a := c.rhead, c.rhead.attestation
	if opts.Source == nil {
		return changelogErr(changelogRederivation, "no upstream source is configured")
	}
	t := prep.cfg.Target
	repo, err := extract.ParseRepo(t.Repo.Key)
	if err != nil || repo != t.Repo {
		return changelogErr(changelogRederivation, "the target repository %q is not canonical", logSafe(t.Repo.Key))
	}
	derived, err := time.Parse(time.RFC3339, rec.DerivedAt)
	if err != nil {
		return changelogErr(changelogRederivation, "derivedAt %q", logSafe(rec.DerivedAt))
	}
	if until, err := time.Parse(time.RFC3339, rec.ValidUntil); err != nil || !until.After(derived) {
		return changelogErr(changelogRederivation, "validUntil %q", logSafe(rec.ValidUntil))
	}
	tags, err := opts.Source.Tags(repo)
	if err != nil {
		return changelogErr(changelogReleasesIncomplete, "the tags of %s cannot be listed: %v", repo.Key, err)
	}
	if err := changelogReleasesComplete(*a, tags); err != nil {
		return err
	}
	ex, err := changelogattest.New(prep.slug, prep.cfg)
	if err != nil {
		return changelogErr(changelogTargetNotAttesting, "%v", err)
	}
	var pair *extract.VersionPair
	for _, p := range ex.Pairs(extract.ReleaseIndex{Repo: repo, Tags: tags}) {
		if line, ok := lineattest.LineOf(p.To); ok && line == a.Line {
			p := p
			pair = &p
		}
	}
	if pair == nil {
		return changelogErr(changelogRederivation, "the extractor derives no pair into line %s from the tags", logSafe(a.Line))
	}
	reader := extract.NewRecorder(opts.Source)
	res, err := ex.Extract(ctx, reader, *pair)
	if w, withheld := extract.IsWithheld(err); withheld {
		code := ""
		if m, ok := w.Proof.(map[string]string); ok {
			code = m["code"]
		}
		if code == string(ce.EntryAmended) {
			return changelogErr(changelogEntryAmended, "%s", logSafe(w.Reason))
		}
		return changelogErr(changelogRederivation, "the extractor withholds line %s (%s): %s", logSafe(a.Line), logSafe(code), logSafe(w.Reason))
	}
	if err != nil {
		return changelogErr(changelogRederivation, "the extractor cannot derive line %s: %v", logSafe(a.Line), err)
	}
	if len(res.Attestations) != 1 {
		return changelogErr(changelogRederivation, "the extractor states %d attestations for line %s, want 1", len(res.Attestations), logSafe(a.Line))
	}
	cand := res.Attestations[0]
	if cand.Component != a.Component || cand.Line != a.Line || cand.FactFamily != a.FactFamily {
		return changelogErr(changelogRederivation, "the extractor attests %s %s %s, not this record's scope", logSafe(cand.Component), logSafe(cand.FactFamily), logSafe(cand.Line))
	}
	stamped, err := stampChangelog(cand, reader, repo, tags, prep.identity, rec.DerivedAt, rec.ValidUntil)
	if err != nil {
		return changelogErr(changelogRederivation, "%v", err)
	}
	raw, err := extract.Canonical(stamped)
	if err != nil {
		return changelogErr(changelogRederivation, "%v", err)
	}
	if !bytes.Equal(raw, rec.Canonical) {
		return changelogErr(changelogRederivation, "line attestation differs from what extractor %s %s derives from the pinned upstream bytes", logSafe(prep.identity.ID), logSafe(prep.identity.Version))
	}
	return nil
}

// stampChangelog turns the extractor's candidate into the record the gate
// compares with: mechanical provenance, reviewedAt equal to derivedAt,
// sources resolved only from bytes this re-derivation read. It is the stamp
// of extract.Run for a line attestation, minus the member-table and
// own-rules checks the changelog family does not use (the record is held
// byte-equal to a record the pack loader has validated).
func stampChangelog(c extract.AttestationCandidate, rec *extract.Recorder, repo extract.RepoRef, tags []extract.Tag, id constraintengine.Extractor, derivedAt, validUntil string) (lineattest.LineAttestation, error) {
	if c.Basis != extract.BasisMechanical {
		return lineattest.LineAttestation{}, fmt.Errorf("attestation of %s: only an explicit mechanical attestation is stamped", c.Component)
	}
	extractor := id
	ids := append([]string{}, c.RuleIDs...)
	sort.Strings(ids)
	a := lineattest.LineAttestation{Component: c.Component, Line: c.Line, FactFamily: c.FactFamily, Completeness: lineattest.Completeness, RuleIDs: ids,
		InstallProfiles: lineattest.CopyInstallProfiles(c.InstallProfiles),
		Evidence:        lineattest.Evidence{Basis: constraintengine.BasisMechanical, Extractor: &extractor, DerivedAt: derivedAt, ReviewedAt: derivedAt, ValidUntil: validUntil}}
	if c.Releases == nil {
		return lineattest.LineAttestation{}, fmt.Errorf("attestation %s names no releases", a.Key())
	}
	r := lineattest.Releases{From: append([]lineattest.Release{}, c.Releases.From...), To: append([]lineattest.Release{}, c.Releases.To...)}
	// Every release the record names must be a release tag of the tag list
	// at that commit. The first release of the from line is named but its
	// entry is not read, so being read is not a condition.
	for _, side := range [][]lineattest.Release{r.From, r.To} {
		for _, rel := range side {
			if !tagAt(tags, rel) {
				return lineattest.LineAttestation{}, fmt.Errorf("attestation %s names release %s at %s, which is not a release tag", a.Key(), rel.Version, rel.Commit)
			}
		}
	}
	a.Releases = &r
	if len(c.Sources) == 0 {
		return lineattest.LineAttestation{}, fmt.Errorf("attestation %s cites no source", a.Key())
	}
	for _, s := range c.Sources {
		got, ok := rec.Lookup(s.Repo, s.Commit, s.Path)
		if !ok {
			return lineattest.LineAttestation{}, fmt.Errorf("attestation %s cites %s@%s:%s, which the re-derivation did not read", a.Key(), s.Repo.Key, s.Commit, s.Path)
		}
		start, end := s.StartLine, s.EndLine
		if start < 1 || end < start || end > got.Lines {
			return lineattest.LineAttestation{}, fmt.Errorf("attestation %s cites lines %d-%d of %s, which has %d lines", a.Key(), start, end, s.Path, got.Lines)
		}
		a.Evidence.Sources = append(a.Evidence.Sources, constraintengine.SourceEvidence{ID: s.ID, URL: s.Repo.BlobURL(s.Commit, s.Path), Revision: s.Commit, ContentDigest: "sha256:" + got.SHA256, StartLine: start, EndLine: end})
	}
	sort.Slice(a.Evidence.Sources, func(i, j int) bool { return a.Evidence.Sources[i].ID < a.Evidence.Sources[j].ID })
	return a, nil
}

// tagAt reports whether a tag "v<version>" or "<version>" names the release
// at its commit.
func tagAt(tags []extract.Tag, rel lineattest.Release) bool {
	for _, t := range tags {
		if t.Commit == rel.Commit && (t.Name == rel.Version || t.Name == "v"+rel.Version) {
			return true
		}
	}
	return false
}

// rederiveChangelog admits, by re-derivation only, the changelog records
// changelogPre passed.
func rederiveChangelog(ctx context.Context, changes []*Change, preps map[*Change]*changelogPrep, opts Options) {
	for _, c := range changes {
		if c.OK || c.Detail != "" {
			continue
		}
		changelogRederive(ctx, c, preps[c], opts)
	}
}

// changelogCitations attaches the citations check's findings to the
// changelog changes they name, and reports the changelog check when the
// change set holds any such change. It only ever refuses.
func (r *Report) changelogCitations(cls *Classification) {
	var all []*Change
	for _, c := range cls.Changes {
		if c.Class == ClassLoosening && isChangelogRecord(c) {
			all = append(all, c)
		}
	}
	if len(all) == 0 {
		return
	}
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
				c.failFirst(changelogErr(changelogCitation, "source %s [%s]: %s", logSafe(f.SourceID), f.Check, logSafe(f.Message)).Error())
				named = true
				break
			}
		}
		if !named && !citationsOK {
			c.failFirst(changelogErr(changelogCitation, "the citations check did not pass: %s", logSafe(citationsDetail)).Error())
		}
	}
	var failed []string
	for _, c := range all {
		if !c.OK {
			failed = append(failed, c.RuleID+": "+c.Detail)
		}
	}
	r.add(changelogCheckName, len(failed) == 0, "%d changelog line attestations, %d refused%s", len(all), len(failed), listDetail(failed))
}
