// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Chain verdicts. NoRule is only ever the verdict of the end-to-end
// transition: no reviewed rule matches the whole range, which says nothing
// against the hops and is not a gap.
const (
	ChainPass    = "PASS"
	ChainBlocked = "BLOCKED"
	ChainUnknown = "UNKNOWN"
	ChainNoRule  = "NO_RULE"

	// ChainSchema names the chained report.
	ChainSchema = "prufyx.io/cncf-chain-check/v1alpha1"

	// MaxChainVia bounds the declared intermediate versions.
	MaxChainVia = 32
)

// reasonTransitionNotReviewed is the reason of a rule whose subject the
// transition does not match: the rule says nothing about it, and a report
// whose every claim has it holds no rule for the transition.
const reasonTransitionNotReviewed = "RULE_TRANSITION_NOT_REVIEWED"

// ChainHop is one transition of a declared path with its own sealed report.
type ChainHop struct {
	Index   int    `json:"index,omitempty"`
	From    string `json:"from"`
	To      string `json:"to"`
	Verdict string `json:"verdict"`
	// Decided counts the verdict claims of rules that match the transition
	// (notices, leads and rules for other transitions excluded); a hop with
	// none has no rule and is UNKNOWN.
	Decided int    `json:"decided"`
	Report  Report `json:"report"`
}

// ChainReport is the result of checking an upgrade over a declared path.
// Verdict is BLOCKED when any hop or the end-to-end transition is blocked,
// PASS only when every hop passed on at least one decided claim and the
// end-to-end transition did not object, UNKNOWN otherwise.
type ChainReport struct {
	Schema  string   `json:"schema"`
	Project string   `json:"project"`
	Verdict string   `json:"verdict"`
	Path    []string `json:"path"`
	// InputFileDigest is the digest of the input bytes the caller gave.
	InputFileDigest string `json:"inputFileDigest"`
	// Scope is fixed text: what the facts of the input mean on every hop.
	Scope string     `json:"scope"`
	Hops  []ChainHop `json:"hops"`
	Whole ChainHop   `json:"whole"`
	// NextAction names what the verdict still needs.
	NextAction string `json:"nextAction"`
}

// ChainScope is the fixed scope statement of every chained report.
const ChainScope = "facts of the input are applied unchanged to every hop; proposed-side facts describe the final target"

// CheckChain checks an upgrade from the input's current version to its
// proposed version through the versions in via, in order. Every hop is
// evaluated with the same facts as the input, by the same engine and rules as
// Check; the end-to-end pair is evaluated too, so a rule reviewed for the
// whole range is not lost. via is the operator's declared path: nothing here
// invents an intermediate version.
func (c Checker) CheckChain(project string, inputRaw []byte, via []string, now time.Time) (ChainReport, error) {
	// the original bytes go through the engine's own input gate once: every hop is a re-encoding of them, which
	// would otherwise hide a duplicate key (last value wins) that a single check refuses
	if err := ValidateCanonicalInput(project, inputRaw); err != nil {
		return ChainReport{}, err
	}
	return checkChain(func(raw []byte) (Report, error) { return c.Check(project, raw, now) }, project, inputRaw, via)
}

func checkChain(evaluate func([]byte) (Report, error), project string, inputRaw []byte, via []string) (ChainReport, error) {
	from, to, ok := inputTransition(inputRaw)
	if !ok || len(via) == 0 || len(via) > MaxChainVia {
		return ChainReport{}, ErrInvalid
	}
	path := append(append([]string{from}, via...), to)
	for i := 0; i+1 < len(path); i++ {
		order, ok := constraintengine.CompareVersions(path[i], path[i+1])
		if !ok || order >= 0 {
			return ChainReport{}, ErrInvalid
		}
	}
	chain := ChainReport{Schema: ChainSchema, Project: project, Path: path, InputFileDigest: digest(inputRaw), Scope: ChainScope}
	for i := 0; i+1 < len(path); i++ {
		hop, err := chainHop(evaluate, inputRaw, path[i], path[i+1])
		if err != nil {
			return ChainReport{}, err
		}
		hop.Index = i + 1
		chain.Hops = append(chain.Hops, hop)
	}
	whole, err := chainHop(evaluate, inputRaw, from, to)
	if err != nil {
		return ChainReport{}, err
	}
	if whole.Verdict == ChainUnknown && whole.Decided == 0 && (whole.Report.TrustPolicy == nil || whole.Report.TrustPolicy.ExcludedRules == 0) {
		whole.Verdict = ChainNoRule
	}
	chain.Whole = whole
	chain.Verdict, chain.NextAction = chainVerdict(chain.Hops, whole)
	return chain, nil
}

func chainHop(evaluate func([]byte) (Report, error), inputRaw []byte, from, to string) (ChainHop, error) {
	raw, err := withTransition(inputRaw, from, to)
	if err != nil {
		return ChainHop{}, err
	}
	report, err := evaluate(raw)
	if err != nil {
		return ChainHop{}, err
	}
	hop := ChainHop{From: from, To: to, Report: report}
	for _, claim := range report.Check.Claims {
		if !claim.IsVerdictNeutral() && claim.ReasonCode != reasonTransitionNotReviewed {
			hop.Decided++
		}
	}
	switch ClaimExit(report) {
	case 0:
		hop.Verdict = ChainPass
	case 10:
		hop.Verdict = ChainBlocked
	case 3:
		return ChainHop{}, ErrIntegrity
	default:
		hop.Verdict = ChainUnknown
	}
	return hop, nil
}

// chainVerdict combines the hop verdicts: any BLOCKED wins, then any UNKNOWN
// (a hop without a deciding rule is never absorbed), else PASS.
func chainVerdict(hops []ChainHop, whole ChainHop) (string, string) {
	blocked, unknown := []string{}, []string{}
	for _, hop := range append(append([]ChainHop(nil), hops...), whole) {
		label := hop.From + " -> " + hop.To
		switch hop.Verdict {
		case ChainBlocked:
			blocked = append(blocked, label)
		case ChainUnknown:
			unknown = append(unknown, label)
		}
	}
	switch {
	case len(blocked) > 0:
		return ChainBlocked, "fix the blockers of " + strings.Join(blocked, ", ") + " before upgrading; the other hops are still evaluated and listed"
	case len(unknown) > 0:
		return ChainUnknown, "no reviewed rule decided " + strings.Join(unknown, ", ") + "; the result stays UNKNOWN until a maintainer publishes one or you check those hops by hand"
	}
	return ChainPass, "every declared hop passed its reviewed rules with the facts of the input, which are the same on every hop; the path is the one you declared and runtime behavior remains unverified"
}

// ChainExit is the exit code of a chained report: 0 PASS, 10 BLOCKED, 11
// otherwise, 3 for a report that does not verify.
func ChainExit(chain ChainReport) int {
	if _, err := MarshalChain(chain); err != nil {
		return 3
	}
	switch chain.Verdict {
	case ChainPass:
		return 0
	case ChainBlocked:
		return 10
	}
	return 11
}

// MarshalChain verifies every sealed report of the chain and encodes it.
func MarshalChain(chain ChainReport) ([]byte, error) {
	if chain.Schema != ChainSchema || chain.Scope != ChainScope || chain.InputFileDigest == "" || len(chain.Hops) == 0 || len(chain.Path) != len(chain.Hops)+1 {
		return nil, ErrIntegrity
	}
	for _, hop := range append(append([]ChainHop(nil), chain.Hops...), chain.Whole) {
		if _, err := MarshalReport(hop.Report); err != nil {
			return nil, ErrIntegrity
		}
	}
	raw, err := json.Marshal(chain)
	if err != nil {
		return nil, ErrIntegrity
	}
	return raw, nil
}

type transitionShape struct {
	Current  struct{ Components []struct{ Version string } }
	Proposed struct{ Components []struct{ Version string } }
}

// inputTransition reads the versions of an input with exactly one component
// on each side.
func inputTransition(raw []byte) (from, to string, ok bool) {
	var shape transitionShape
	if json.Unmarshal(raw, &shape) != nil || len(shape.Current.Components) != 1 || len(shape.Proposed.Components) != 1 {
		return "", "", false
	}
	return shape.Current.Components[0].Version, shape.Proposed.Components[0].Version, true
}

// withTransition returns the input with the versions of its single component
// on each side replaced; everything else, the facts included, is unchanged.
func withTransition(raw []byte, from, to string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if decoder.Decode(&document) != nil {
		return nil, ErrInvalid
	}
	for side, version := range map[string]string{"current": from, "proposed": to} {
		holder, _ := document[side].(map[string]any)
		components, _ := holder["components"].([]any)
		if len(components) != 1 {
			return nil, ErrInvalid
		}
		component, _ := components[0].(map[string]any)
		if component == nil {
			return nil, ErrInvalid
		}
		component["version"] = version
	}
	out, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalid
	}
	return out, nil
}
