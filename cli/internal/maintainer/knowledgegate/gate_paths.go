// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Gate paths. The files that define the required checks (workflows, the
// merge-policy scripts, the code owners file, the gate code) are trust
// paths for the change itself: a queued run executes the workflow file of
// the proposed commit, so a change to them could rewrite its own checks.
// The gate that judges the change is built from the base, so it is the one
// place such a change can be stopped. A change of any of them is admitted
// only with an owner approval of subject gatePaths that binds the pull
// request ("pr-<number>") and the exact bytes of every gate file the change
// touches. The approval is signed with the same pinned owner key flow as a
// rule approval; the pinned key file is read from the base, so a change
// cannot bring its own key and a GitHub review is never a substitute.
const (
	// ApprovalSubjectGatePaths is the subject of the approval of a change to
	// gate files.
	ApprovalSubjectGatePaths = "gatePaths"
	// GatePathsPack is the pack name such an approval names; the approval
	// file is <approvals>/gate-paths/<candidate id>.json.
	GatePathsPack = "gate-paths"
	// GatePathsScope is the scope such an approval names.
	GatePathsScope = "gate-paths"
	// GatePathsSchema is the schema of the statement such an approval binds.
	GatePathsSchema = "prufyx.io/gate-paths-change/v1"
	checkGatePaths  = "gate-paths"
)

var gateCandidateRE = regexp.MustCompile(`^pr-[1-9][0-9]{0,8}$`)

// defaultGatePaths is the default list: an entry ending in "/" is a prefix,
// any other an exact file.
func defaultGatePaths() []string {
	return []string{
		".github/workflows/",
		".github/CODEOWNERS",
		".github/actions/",
		"action.yml",
		"action.yaml",
		// Every script a workflow calls, and any added later.
		"scripts/",
		// The queue builds the head tree: a dependency, toolchain or vendored
		// source edit changes what runs.
		"cli/go.mod",
		"cli/go.sum",
		"cli/vendor/",
		"go.mod",
		"go.sum",
		"go.work",
		"go.work.sum",
		"cli/internal/maintainer/knowledgegate/",
		"cli/internal/maintainer/mergepolicy/",
		"cli/internal/maintainer/releasedocs/",
		// The renderers behind the blocks and counts the gates compare.
		"cli/internal/maintainer/releasenotes/",
		"cli/internal/maintainer/coveragereport/",
		"cli/internal/maintainer/verifyprworkflow/",
		"cli/internal/maintainer/targetdraft/classify.go",
		"cli/cmd/prufyx-maintainer/gate.go",
		"cli/cmd/prufyx-maintainer/release_docs.go",
		// The CNCF sub-project overlay: its data, its loader, the network
		// tool that re-checks its citations, and the classifier rule that
		// keeps a factory export from writing it. Every change is signed.
		"cli/internal/cncfcheck/data/cncf-subprojects.json",
		"cli/internal/cncfcheck/subprojects.go",
		"cli/internal/cncfcheck/subprojects_test.go",
		"cli/cmd/prufyx-maintainer/subprojects_test.go",
		"cli/cmd/prufyx-maintainer/subprojects.go",
		"cli/internal/maintainer/knowledgepacket/classify.go",
		"cli/internal/maintainer/knowledgepacket/classify_overlay_test.go",
	}
}

// gatePath reports whether rel is a gate file.
func (l Layout) gatePath(rel string) bool {
	// Module and action files of any directory (the repository holds more
	// than one module), whatever the list says.
	switch path.Base(rel) {
	case "go.mod", "go.sum", "go.work", "go.work.sum", "action.yml", "action.yaml":
		return true
	}
	for _, p := range l.GatePaths {
		if strings.HasSuffix(p, "/") && strings.HasPrefix(rel, p) || rel == p {
			return true
		}
	}
	return false
}

// GatePathsChange is the statement an approval of subject gatePaths binds
// (its canonical JSON is the candidate).
type GatePathsChange struct {
	Schema      string          `json:"schema"`
	CandidateID string          `json:"candidateId"`
	Files       []GatePathsFile `json:"files"`
}

// GatePathsFile is one gate file the change touches, with the digest of its
// bytes in the head ("absent" when the change deletes it).
type GatePathsFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

func gatePathsStatement(layout Layout, base, head Tree, candidateID string) (GatePathsChange, []byte, error) {
	if !gateCandidateRE.MatchString(candidateID) {
		return GatePathsChange{}, nil, errors.New("the candidate id is not pr-<number>")
	}
	changed, err := ChangedPaths(base, head)
	if err != nil {
		return GatePathsChange{}, nil, err
	}
	return gatePathsStatementOf(layout, head, candidateID, changed)
}

func gatePathsStatementOf(layout Layout, head Tree, candidateID string, changed []string) (GatePathsChange, []byte, error) {
	st := GatePathsChange{Schema: GatePathsSchema, CandidateID: candidateID, Files: []GatePathsFile{}}
	for _, p := range changed {
		if !layout.gatePath(p) {
			continue
		}
		raw, err := head.ReadOptional(p, MaxFileBytes)
		if err != nil {
			return GatePathsChange{}, nil, fmt.Errorf("%s: %v", logSafe(p), err)
		}
		d := "absent"
		if raw != nil {
			d = CandidateDigest(raw)
		}
		st.Files = append(st.Files, GatePathsFile{Path: p, Digest: d})
	}
	if len(st.Files) == 0 {
		return GatePathsChange{}, nil, errors.New("the change touches no gate file")
	}
	sort.Slice(st.Files, func(i, j int) bool { return st.Files[i].Path < st.Files[j].Path })
	canonical, err := extract.Canonical(st)
	if err != nil {
		return GatePathsChange{}, nil, err
	}
	return st, canonical, nil
}

// GatePathsApprovalSubject reads the gate-file change between a base and a
// head checkout exactly as the gate reads it, for the owner to sign or check.
func GatePathsApprovalSubject(layout Layout, base, head Tree, candidateID string) (ApprovalSubject, GatePathsChange, error) {
	st, canonical, err := gatePathsStatement(layout, base, head, candidateID)
	if err != nil {
		return ApprovalSubject{}, GatePathsChange{}, err
	}
	return ApprovalSubject{Kind: ApprovalSubjectGatePaths, Pack: GatePathsPack, RuleID: candidateID, Scope: GatePathsScope, Candidate: canonical}, st, nil
}

func (s *subjectFlags) loadGatePaths(layout Layout) (ApprovalSubject, ApprovalKeys, error) {
	if s.baseRoot == "" || s.headRoot == "" || s.keys == "" || s.keysDigest == "" || s.candidateID == "" {
		return ApprovalSubject{}, ApprovalKeys{}, usageError{"--subject gatePaths takes --candidate-id, --base-root, --head-root, --keys and --keys-digest"}
	}
	if s.pack != "" || s.rule != "" || s.record != "" || s.basePack != "" || s.headPack != "" || s.repository != "" || s.baseBaselines != "" || s.headBaselines != "" {
		return ApprovalSubject{}, ApprovalKeys{}, usageError{"--subject gatePaths takes --candidate-id, --base-root and --head-root only"}
	}
	keysRaw, err := readBoundedFile(s.keys, maxApprovalBytes*4)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	keys, err := LoadApprovalKeys(keysRaw, s.keysDigest)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	subject, _, err := GatePathsApprovalSubject(layout, Tree{Root: s.baseRoot}, Tree{Root: s.headRoot}, s.candidateID)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	return subject, keys, nil
}

// gatePathsApprovalPath is where a change carries its gate-path approval.
func gatePathsApprovalPath(layout Layout, candidateID string) string {
	return layout.ApprovalDir + "/" + GatePathsPack + "/" + candidateID + ".json"
}

// gatePathsApprovalReason is the records check of one file under the
// gate-paths approval directory: only this change's own approval, and only
// next to a gate file change, belongs there.
func gatePathsApprovalReason(name string, opts Options, changed []string) string {
	if !gateCandidateRE.MatchString(opts.CandidateID) || name != opts.CandidateID+".json" {
		return "not the approval of this change (" + GatePathsPack + "/pr-<number>.json)"
	}
	for _, p := range changed {
		if opts.Layout.gatePath(p) {
			return ""
		}
	}
	return "a gate-paths approval without a change to a gate file"
}

// gatePathCheck refuses a change to a gate file unless an owner approval of
// subject gatePaths for this change arrives with it, verifies under the
// base's pinned owner keys and binds the exact bytes of every gate file the
// change touches. It always runs and says what it saw.
func (r *Report) gatePathCheck(opts Options, loadKeys func() (*ApprovalKeys, error)) {
	var touched []string
	for _, p := range r.ChangedPaths {
		if opts.Layout.gatePath(p) {
			touched = append(touched, p)
		}
	}
	if len(touched) == 0 {
		r.add(checkGatePaths, true, "0 gate files changed")
		return
	}
	fail := func(why string) {
		r.add(checkGatePaths, false, "%d gate files changed%s; they need an owner approval of subject gatePaths bound to this change: %s", len(touched), listDetail(touched), why)
	}
	if !gateCandidateRE.MatchString(opts.CandidateID) {
		fail("the change has no reference (pr-<number>)")
		return
	}
	_, statement, err := gatePathsStatementOf(opts.Layout, opts.Head, opts.CandidateID, r.ChangedPaths)
	if err != nil {
		fail(logSafe(err.Error()))
		return
	}
	raw, err := opts.Head.ReadOptional(gatePathsApprovalPath(opts.Layout, opts.CandidateID), maxApprovalBytes+1)
	switch {
	case err != nil:
		fail("approval: " + logSafe(err.Error()))
		return
	case raw == nil:
		fail("no owner approval")
		return
	}
	keys, err := loadKeys()
	if err != nil {
		fail(logSafe(err.Error()))
		return
	}
	if err := VerifyRecordApproval(raw, *keys, GatePathsPack, ApprovalSubjectGatePaths, opts.CandidateID, GatePathsScope, nil, statement, opts.Now); err != nil {
		fail(logSafe(err.Error()))
		return
	}
	r.add(checkGatePaths, true, "%d gate files changed%s; owner approval verified", len(touched), listDetail(touched))
}
