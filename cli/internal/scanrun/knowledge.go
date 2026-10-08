// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Knowledge is the knowledge one scan reads: the embedded snapshot
// (Embedded), or knowledge selected from a verified local knowledge
// database (Store); tests wrap either.
type Knowledge interface {
	Origin() string
	Revision() string
	PackDigest() string
	Projects() []string
	Component(slug string) (string, bool)
	Rules(project string) []cncfcheck.ScanRule
	// Evaluate evaluates the project's rules the trust policy admits over
	// the facts for one prepared input. ErrRefused means the knowledge cannot evaluate the
	// input (a fact it does not register).
	Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error)
	AttestationsFor(component, line, family string, now time.Time) []lineattest.Status
	PathPolicyFor(component string, now time.Time) upgradepath.Status
	// ServedAPIs looks up the reviewed list of "apiVersion kind" pairs the
	// component's line serves, with its freshness at now.
	ServedAPIs(component, line string, now time.Time) ServedStatus
	// Store describes the verified knowledge database the knowledge was
	// selected from; nil for the embedded knowledge.
	Store() *StoreInfo
}

// Evaluation is the result of one engine evaluation.
type Evaluation struct {
	Claims               []constraintengine.Claim
	EngineContractDigest string
}

// ErrRefused reports an input the knowledge cannot evaluate.
var ErrRefused = errors.New("input refused by the knowledge")

// Embedded is the embedded knowledge snapshot as scan reads it.
type Embedded struct {
	*cncfcheck.ScanKnowledge
}

// LoadEmbedded loads the embedded knowledge once.
func LoadEmbedded() (Embedded, error) {
	snapshot, err := cncfcheck.LoadScanKnowledge()
	if err != nil {
		return Embedded{}, err
	}
	return Embedded{snapshot}, nil
}

// Evaluate runs the native route's fact-family evaluation under the trust
// policy and checks the report's integrity.
func (k Embedded) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	return evaluateSnapshot(k.ScanKnowledge, "embedded", k.PackDigest(), policy, project, facts, inputRaw, now)
}

// Store is nil: the embedded knowledge comes from no database.
func (k Embedded) Store() *StoreInfo { return nil }

// evaluateSnapshot evaluates one prepared input over a snapshot and checks
// that the report is intact and came from the expected knowledge: its
// origin and the digest of the pack or target that holds the rules.
func evaluateSnapshot(k *cncfcheck.ScanKnowledge, origin, packDigest string, policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	report, err := k.CheckFactsWithPolicy(policy, project, facts, inputRaw, now)
	if errors.Is(err, cncfcheck.ErrInvalid) {
		return Evaluation{}, ErrRefused
	}
	if err != nil {
		return Evaluation{}, ErrIntegrity
	}
	if _, err := cncfcheck.MarshalReport(report); err != nil || report.KnowledgeOrigin != origin || report.KnowledgePackDigest != packDigest {
		return Evaluation{}, ErrIntegrity
	}
	return Evaluation{Claims: report.Check.Claims, EngineContractDigest: report.Check.EngineContractDigest}, nil
}

// ServedList is one reviewed list of the API versions a release line
// serves: the record's own component and line, its evidence basis and the
// served "apiVersion kind" pairs.
type ServedList struct {
	Component string
	Line      string
	Basis     string
	// ValidUntil is the end of the list's validity window, when known.
	ValidUntil string
	APIs       map[string]bool
}

// ServedStatus is a served-list lookup. Only a found list whose freshness is
// "current", whose component and line are the ones asked for, and whose
// basis the trust policy admits may be used.
type ServedStatus struct {
	Found     bool
	List      ServedList
	Freshness string
}

// ServedAPIs reads the embedded pack's served-API list for the component and
// line. A pack without one yields no list, so every Kubernetes API group
// document is a named gap.
func (k Embedded) ServedAPIs(component, line string, now time.Time) ServedStatus {
	status, found := k.ScanKnowledge.ServedAPIsFor(component, line, now)
	if !found {
		return ServedStatus{}
	}
	apis := make(map[string]bool, len(status.Record.APIs))
	for _, pair := range status.Record.APIs {
		apis[pair] = true
	}
	return ServedStatus{
		Found:     true,
		List:      ServedList{Component: status.Record.Component, Line: status.Record.Line, Basis: status.Record.Evidence.Basis, ValidUntil: status.Record.Evidence.ValidUntil, APIs: apis},
		Freshness: status.Freshness,
	}
}
