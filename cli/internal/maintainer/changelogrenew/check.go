// SPDX-License-Identifier: AGPL-3.0-only

// Package changelogrenew renews changelog.listed_entries line attestations.
//
// A renewal is only taken from a new derivation: two byte-identical run
// directories of one extractor. It moves the three times of a record
// (evidence.derivedAt, reviewedAt and validUntil) and, when the runs are of a
// newer build of the record's own extractor, that build's version and code
// digest. Nothing else may differ. A changed release list, source or line
// range, another extractor, or any other difference is not a renewal and
// belongs to the ordinary intake.
//
// There is one predicate for each of the two cases, TimeOnly (the same build)
// and NewBuild (a newer one). The package admits nothing: the knowledge gate
// re-derives every change on its own and uses TimeOnly as a further refusal.
package changelogrenew

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// MaxLease bounds validUntil minus derivedAt of a renewed record.
const MaxLease = 90 * 24 * time.Hour

// kubernetesComponent is never renewed across extractor builds.
const kubernetesComponent = "pkg:github/kubernetes/kubernetes"

// Refusal codes.
const (
	CodeInput          = "input"
	CodeRun            = "run"
	CodeRunMismatch    = "run-mismatch"
	CodeUnpinned       = "unpinned-file"
	CodeOtherExtractor = "other-extractor"
	CodeBuild          = "extractor-build"
	CodeComponent      = "component"
	CodeNotInForce     = "not-in-force"
	CodeDerivationTime = "derivation-time"
	CodeLease          = "lease"
	CodeChanged        = "content-changed"
	CodeNothing        = "nothing-renewed"
)

// Error is a refusal with a stable code.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return "changelog-renewal/" + e.Code + ": " + e.Detail }

func refuse(code, format string, a ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// dateFields are the evidence members every renewal moves.
var dateFields = []string{"derivedAt", "reviewedAt", "validUntil"}

// buildFields are the extractor members a renewal across builds also moves.
var buildFields = []string{"version", "codeDigest"}

type side struct {
	generic            map[string]any
	evidence           map[string]any
	extractorMembers   map[string]any
	extractor          []byte
	build              constraintengine.Extractor
	component          string
	derived, until     time.Time
	reviewedAt, atText string
}

func readSide(name string, raw []byte) (side, error) {
	var s side
	if err := strictjson.Check(raw); err != nil {
		return s, refuse(CodeInput, "the %s record: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&s.generic); err != nil || s.generic == nil {
		return s, refuse(CodeInput, "the %s record is not a JSON object", name)
	}
	s.evidence, _ = s.generic["evidence"].(map[string]any)
	if family, _ := s.generic["factFamily"].(string); family != lineattest.FamilyChangelogListedEntries || s.evidence == nil {
		return s, refuse(CodeInput, "the %s record is not a %s record with evidence", name, lineattest.FamilyChangelogListedEntries)
	}
	s.component, _ = s.generic["component"].(string)
	text := func(k string) string { v, _ := s.evidence[k].(string); return v }
	if text("basis") != constraintengine.BasisMechanical {
		return s, refuse(CodeInput, "the %s record is not mechanical", name)
	}
	s.extractorMembers, _ = s.evidence["extractor"].(map[string]any)
	member := func(k string) string { v, _ := s.extractorMembers[k].(string); return v }
	s.build = constraintengine.Extractor{ID: member("id"), Version: member("version"), CodeDigest: member("codeDigest")}
	if s.build.ID == "" || s.build.Version == "" || s.build.CodeDigest == "" {
		return s, refuse(CodeOtherExtractor, "the %s record does not name an extractor id, version and codeDigest", name)
	}
	var err error
	if s.extractor, err = extract.Canonical(s.extractorMembers); err != nil {
		return s, refuse(CodeInput, "the %s record: %v", name, err)
	}
	var err1, err2 error
	s.derived, err1 = constraintengine.ParseUTC(text("derivedAt"))
	s.until, err2 = constraintengine.ParseUTC(text("validUntil"))
	if err1 != nil || err2 != nil {
		return s, refuse(CodeInput, "the %s record's times cannot be read", name)
	}
	s.reviewedAt, s.atText = text("reviewedAt"), text("derivedAt")
	return s, nil
}

// checkTimes requires the times of next to be those of a later derivation that
// extends the record.
func checkTimes(old, next side) error {
	if !next.derived.After(old.derived) || next.reviewedAt != next.atText {
		return refuse(CodeDerivationTime, "derivedAt must be a new derivation later than the base one and equal reviewedAt")
	}
	if life := next.until.Sub(next.derived); life <= 0 || life > MaxLease {
		return refuse(CodeLease, "validUntil must be more than 0 and at most 90 days after derivedAt")
	}
	if !next.until.After(old.until) {
		return refuse(CodeLease, "validUntil is not later than the base one")
	}
	return nil
}

// sameRest requires the canonical JSON of both records to be equal once the
// three times and the named extractor members are taken out.
func sameRest(old, next side, extractorFields []string, moved string) error {
	var rest [2][]byte
	for i, s := range []side{old, next} {
		for _, k := range dateFields {
			delete(s.evidence, k)
		}
		for _, k := range extractorFields {
			delete(s.extractorMembers, k)
		}
		var err error
		if rest[i], err = extract.Canonical(s.generic); err != nil {
			return refuse(CodeInput, "a record cannot be compared: %v", err)
		}
	}
	if !bytes.Equal(rest[0], rest[1]) {
		return refuse(CodeChanged, "the record differs in more than %s", moved)
	}
	return nil
}

// TimeOnly reports whether the record next is a renewal of the record old (both
// as JSON) by the same extractor build: both are mechanical
// changelog.listed_entries records of the same extractor id, version and code
// digest; next's derivedAt is later than old's and is its reviewedAt; next's
// validUntil is later than old's and more than 0 and at most MaxLease after its
// derivedAt; and everything else, every other member of the record and of its
// evidence (a lease member, the releases, the sources and their line ranges
// included), is equal. It judges no clock.
func TimeOnly(old, next []byte) error {
	o, err := readSide("base", old)
	if err != nil {
		return err
	}
	n, err := readSide("new", next)
	if err != nil {
		return err
	}
	if !bytes.Equal(o.extractor, n.extractor) {
		return refuse(CodeOtherExtractor, "the new record names another extractor or build than the base record")
	}
	if err := checkTimes(o, n); err != nil {
		return err
	}
	return sameRest(o, n, nil, "evidence.derivedAt, reviewedAt and validUntil")
}

var (
	extractorVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	codeDigestRE       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// parseVersion reads an extractor version, numeric x.y.z.
func parseVersion(v string) ([]uint64, bool) {
	m := extractorVersionRE.FindStringSubmatch(v)
	if m == nil {
		return nil, false
	}
	out := make([]uint64, 0, 3)
	for _, part := range m[1:] {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// newerBuild requires next to be another build of the listed extractor old
// names: the same id, another code digest and a version that is not lower.
func newerBuild(old, next constraintengine.Extractor) error {
	if old.ID != next.ID || !strings.HasPrefix(old.ID, ListedIDPrefix) || len(old.ID) == len(ListedIDPrefix) {
		return refuse(CodeOtherExtractor, "both records must name one %s<project> extractor", ListedIDPrefix)
	}
	if !codeDigestRE.MatchString(old.CodeDigest) || !codeDigestRE.MatchString(next.CodeDigest) {
		return refuse(CodeBuild, "a code digest cannot be read")
	}
	if old.CodeDigest == next.CodeDigest {
		return refuse(CodeBuild, "the code digest is the base one: this is not a new build")
	}
	a, ok1 := parseVersion(old.Version)
	b, ok2 := parseVersion(next.Version)
	if !ok1 || !ok2 {
		return refuse(CodeBuild, "an extractor version is not numeric x.y.z")
	}
	if slices.Compare(b, a) < 0 {
		return refuse(CodeBuild, "the extractor version %s is lower than the base %s", next.Version, old.Version)
	}
	return nil
}

// NewBuild reports whether the record next is a renewal of the record old (both
// as JSON) by a newer build of the same extractor, judged at now. Both are
// mechanical changelog.listed_entries records of one changelog.listed
// extractor, of a component other than Kubernetes, and both are in force at
// now; the code digest differs and the version is not lower; next's derivedAt
// is later than old's, not ahead of now by more than ClockSkew, and is its
// reviewedAt; next's validUntil is later than old's and more than 0 and at most
// MaxLease after its derivedAt; and only evidence.extractor.version,
// evidence.extractor.codeDigest and those three times differ.
//
// It shows that the newer build's output on the pinned bytes equals the stored
// claim. It does not show that the two builds are equivalent.
func NewBuild(old, next []byte, now time.Time) error {
	if now.IsZero() {
		return refuse(CodeDerivationTime, "there is no clock to judge a new build by")
	}
	o, err := readSide("base", old)
	if err != nil {
		return err
	}
	n, err := readSide("new", next)
	if err != nil {
		return err
	}
	if o.component == kubernetesComponent || n.component == kubernetesComponent {
		return refuse(CodeComponent, "a Kubernetes record is not renewed across extractor builds")
	}
	if err := newerBuild(o.build, n.build); err != nil {
		return err
	}
	if n.derived.After(now.Add(ClockSkew)) {
		return refuse(CodeDerivationTime, "derivedAt is ahead of the clock")
	}
	if !o.until.After(now) || !n.until.After(now) {
		return refuse(CodeNotInForce, "both records must be in force")
	}
	if err := checkTimes(o, n); err != nil {
		return err
	}
	return sameRest(o, n, buildFields, "evidence.extractor.version and codeDigest, derivedAt, reviewedAt and validUntil")
}

// Current is the build of ex that this binary holds: the identity a run of it
// records.
func Current(ex extract.Extractor) (constraintengine.Extractor, error) {
	var none constraintengine.Extractor
	src, ok := ex.(extract.CodeSource)
	if !ok {
		return none, refuse(CodeBuild, "extractor %s does not expose its source for the code digest", ex.ID())
	}
	dir, own := src.SourceFiles()
	files, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: dir, Files: own})
	if err != nil {
		return none, refuse(CodeBuild, "the code digest of %s: %v", ex.ID(), err)
	}
	return constraintengine.Extractor{ID: ex.ID(), Version: ex.Version(), CodeDigest: extract.CodeDigest(files)}, nil
}

// Pinned requires every file a listed record cites to be pinned to a release
// the record names: exactly one source per release of the line, named
// "changelog-<version>", at that release's commit, with a blob URL of repo at
// that commit and a clean path.
func Pinned(a lineattest.LineAttestation, repo extract.RepoRef) error {
	if a.Releases == nil || len(a.Releases.To) == 0 || len(a.Evidence.Sources) != len(a.Releases.To) {
		return refuse(CodeUnpinned, "%s: there is not exactly one source per release of the line", a.Key())
	}
	byID := map[string]constraintengine.SourceEvidence{}
	for _, s := range a.Evidence.Sources {
		byID[s.ID] = s
	}
	for _, r := range a.Releases.To {
		s, ok := byID["changelog-"+r.Version]
		if !ok || !extract.IsCommitSHA(r.Commit) || s.Revision != r.Commit {
			return refuse(CodeUnpinned, "%s: release %s has no source at its own commit", a.Key(), r.Version)
		}
		delete(byID, s.ID)
		if _, ok := sourcePath(s, repo); !ok {
			return refuse(CodeUnpinned, "%s: source %s is not a file of %s at its revision", a.Key(), s.ID, repo.Key)
		}
	}
	return nil
}

// sourcePath is the repository path of a source's blob URL.
func sourcePath(s constraintengine.SourceEvidence, repo extract.RepoRef) (string, bool) {
	p, ok := strings.CutPrefix(s.URL, repo.BlobURL(s.Revision, ""))
	if !ok || p == "" || p == "." || p == ".." || strings.ContainsAny(p, "?#%\\\t\n") ||
		strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") || path.Clean(p) != p {
		return "", false
	}
	return p, true
}
