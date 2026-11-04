// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/certmanagervalues"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

const declaredSchema = "prufyx.io/declared-state-plan/v1alpha1"
const declaredLimit = 1 << 20

// The manifest is a fixed-order encoding, not general JSON canonicalization.
// Paths are separate locators and never participate in artifact identity.
type declaredComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
}
type declaredEntry struct {
	Role                string `json:"role"`
	LogicalName         string `json:"logicalName"`
	Length              int    `json:"length"`
	Digest              string `json:"digest"`
	Distribution        string `json:"distribution"`
	Complete            *bool  `json:"complete"`
	TargetApplyRequired bool   `json:"targetApplyRequired"`
	SchemaValidation    string `json:"schemaValidation"`
	ChartDigest         string `json:"chartDigest"`
}
type declaredManifest struct {
	Schema     string              `json:"schema"`
	Target     string              `json:"target"`
	Intent     string              `json:"intent"`
	Components []declaredComponent `json:"components"`
	Entries    []declaredEntry     `json:"entries"`
}
type declaredFile struct {
	Role        string `json:"role"`
	LogicalName string `json:"logicalName"`
	Path        string `json:"path"`
}
type declaredArtifact struct {
	Name     string           `json:"name"`
	Manifest declaredManifest `json:"manifest"`
	Files    []declaredFile   `json:"files"`
}
type declaredContext struct {
	Target                     string `json:"target"`
	Intent                     string `json:"intent"`
	PolicyID                   string `json:"policyId"`
	PolicyDigest               string `json:"policyDigest"`
	TrustBases                 string `json:"trustBases"`
	EvaluatedAt                string `json:"evaluatedAt"`
	KnowledgeOrigin            string `json:"knowledgeOrigin"`
	KnowledgeRevision          string `json:"knowledgeRevision"`
	KnowledgeDigest            string `json:"knowledgeDigest"`
	CertManagerKnowledgeDigest string `json:"certManagerKnowledgeDigest"`
}
type declaredStage struct {
	Index        int    `json:"index"`
	Component    string `json:"component"`
	From         string `json:"from"`
	To           string `json:"to"`
	Before       string `json:"before"`
	After        string `json:"after"`
	BeforeDigest string `json:"beforeDigest"`
	AfterDigest  string `json:"afterDigest"`
}
type declaredRequest struct {
	Schema    string             `json:"schema"`
	Context   declaredContext    `json:"context"`
	Artifacts []declaredArtifact `json:"artifacts"`
	Stages    []declaredStage    `json:"stages"`
}
type admittedDeclaredArtifact struct {
	manifest declaredManifest
	digest   string
	inputs   [][]byte
}
type declaredIdentity struct {
	Name     string           `json:"name"`
	Digest   string           `json:"digest"`
	Manifest declaredManifest `json:"manifest"`
}
type declaredStageResult struct {
	Stage               declaredStage   `json:"stage"`
	Status              string          `json:"status"`
	Gaps                []string        `json:"gaps"`
	SourceDigest        string          `json:"sourceDigest,omitempty"`
	PreparedInputDigest string          `json:"preparedInputDigest,omitempty"`
	EngineInputDigest   string          `json:"engineInputDigest,omitempty"`
	Report              json.RawMessage `json:"report,omitempty"`
}
type declaredResult struct {
	Schema     string                `json:"schema"`
	Context    declaredContext       `json:"context"`
	Artifacts  []declaredIdentity    `json:"artifacts"`
	Stages     []declaredStageResult `json:"stages"`
	Status     string                `json:"status"`
	Scope      string                `json:"scope"`
	Omissions  []string              `json:"omissions"`
	NextAction string                `json:"nextAction"`
	seal       *string
}

func declaredHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Requiring the typed re-encoding byte-for-byte also rejects unknown fields,
// duplicate keys, case aliases and alternate scalar encodings at every level.
func decodeDeclared(raw []byte) (declaredRequest, error) {
	var req declaredRequest
	if len(raw) == 0 || len(raw) > declaredLimit || !utf8.Valid(raw) {
		return req, cncfcheck.ErrInvalid
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, cncfcheck.ErrInvalid
	}
	canonical, err := json.Marshal(req)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(raw, []byte("\n")), canonical) || req.Schema != declaredSchema {
		return req, cncfcheck.ErrInvalid
	}
	return req, nil
}

func readDeclaredFile(path string) ([]byte, error) {
	raw, info, err := currentbundle.ReadBoundedFileInfo(path, declaredLimit)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0 {
		return nil, cncfcheck.ErrInvalid
	}
	return raw, nil
}

func admitDeclared(req declaredRequest, root string) (map[string]admittedDeclaredArtifact, error) {
	if len(req.Artifacts) > 16 || len(req.Stages) > 32 {
		return nil, cncfcheck.ErrInvalid
	}
	artifacts := make(map[string]admittedDeclaredArtifact)
	total := 0
	for _, a := range req.Artifacts {
		if a.Name == "" || artifacts[a.Name].digest != "" || a.Manifest.Schema != declaredSchema || len(a.Manifest.Entries) > 8 || len(a.Manifest.Components) > 8 || len(a.Files) != len(a.Manifest.Entries) {
			return nil, cncfcheck.ErrInvalid
		}
		m := a.Manifest
		if m.Target != req.Context.Target || m.Intent != req.Context.Intent {
			return nil, cncfcheck.ErrIntegrity
		}
		for i, c := range m.Components {
			if c.Name == "" || c.Version == "" || c.Mode == "" || (i > 0 && m.Components[i-1].Name >= c.Name) {
				return nil, cncfcheck.ErrInvalid
			}
		}
		canonical, _ := json.Marshal(m)
		admitted := admittedDeclaredArtifact{manifest: m, digest: declaredHash(canonical)}
		for i, e := range m.Entries {
			if e.Role != "kubernetes" && e.Role != "cilium" && e.Role != "cert-manager" {
				return nil, cncfcheck.ErrInvalid
			}
			key := e.Role + "\x00" + e.LogicalName
			if e.Role == "" || e.LogicalName == "" || e.Length <= 0 || e.Length > declaredLimit || (i > 0 && m.Entries[i-1].Role+"\x00"+m.Entries[i-1].LogicalName >= key) {
				return nil, cncfcheck.ErrInvalid
			}
			f := a.Files[i]
			if f.Role != e.Role || f.LogicalName != e.LogicalName || filepath.IsAbs(f.Path) || f.Path == "." || filepath.Clean(f.Path) != f.Path || strings.Contains(f.Path, "\\") || f.Path == ".." || strings.HasPrefix(f.Path, "../") {
				return nil, cncfcheck.ErrInvalid
			}
			raw, err := readDeclaredFile(filepath.Join(root, f.Path))
			if err != nil {
				return nil, err
			}
			total += len(raw)
			if total > 8*declaredLimit {
				return nil, cncfcheck.ErrInvalid
			}
			if len(raw) != e.Length || declaredHash(raw) != e.Digest {
				return nil, cncfcheck.ErrIntegrity
			}
			// This one admitted slice supplies both the identity above and parser below.
			admitted.inputs = append(admitted.inputs, raw)
		}
		artifacts[a.Name] = admitted
	}
	return artifacts, nil
}

func declaredVersion(a admittedDeclaredArtifact, name string) (string, string) {
	for _, c := range a.manifest.Components {
		if c.Name == name {
			return c.Version, c.Mode
		}
	}
	return "", ""
}

func evaluateDeclared(req declaredRequest, artifacts map[string]admittedDeclaredArtifact) (declaredResult, error) {
	result := declaredResult{Schema: declaredSchema, Context: req.Context, Status: "UNKNOWN", Scope: "authored reference states and scoped embedded rules; no executed transition or whole-upgrade safety", Omissions: []string{"NO_OBSERVED_STAGE_OUTPUT", "MIGRATION_NOT_VERIFIED", "APP_ORDERING_NOT_VERIFIED", "STORAGE_NOT_EVALUATED", "RUNTIME_PROVIDER_WORKLOAD_NOT_EVALUATED"}, NextAction: "reproduce each required migration, ordering, storage and runtime claim in an appropriate validation environment"}
	for _, a := range req.Artifacts {
		admitted, ok := artifacts[a.Name]
		if !ok {
			return result, cncfcheck.ErrIntegrity
		}
		canonical, _ := json.Marshal(admitted.manifest)
		expected, _ := json.Marshal(a.Manifest)
		if !bytes.Equal(canonical, expected) || admitted.manifest.Target != req.Context.Target || admitted.manifest.Intent != req.Context.Intent {
			return result, cncfcheck.ErrIntegrity
		}
		if declaredHash(canonical) != admitted.digest || len(admitted.inputs) != len(admitted.manifest.Entries) {
			return result, cncfcheck.ErrIntegrity
		}
		for i, e := range admitted.manifest.Entries {
			if len(admitted.inputs[i]) != e.Length || declaredHash(admitted.inputs[i]) != e.Digest {
				return result, cncfcheck.ErrIntegrity
			}
		}
		result.Artifacts = append(result.Artifacts, declaredIdentity{a.Name, admitted.digest, admitted.manifest})
	}
	previous := ""
	for i, s := range req.Stages {
		r := declaredStageResult{Stage: s, Status: "UNKNOWN", Gaps: []string{}}
		if s.Index != i {
			return result, cncfcheck.ErrIntegrity
		}
		before, bok := artifacts[s.Before]
		after, aok := artifacts[s.After]
		if !bok || !aok {
			r.Gaps = append(r.Gaps, "supply the missing before and after reference artifacts")
			result.Stages = append(result.Stages, r)
			previous = ""
			continue
		}
		if (s.BeforeDigest != "" && s.BeforeDigest != before.digest) || (s.AfterDigest != "" && s.AfterDigest != after.digest) || (previous != "" && previous != before.digest) {
			return result, cncfcheck.ErrIntegrity
		}
		previous = after.digest
		if s.BeforeDigest == "" || s.AfterDigest == "" {
			r.Gaps = append(r.Gaps, "declare both exact manifest digest assertions")
		}
		if s.Component == "declared-edit" {
			if s.From != "" || s.To != "" {
				return result, cncfcheck.ErrIntegrity
			}
			r.Gaps = append(r.Gaps, "validate the authored edit separately; it is not observed remediation output")
			result.Stages = append(result.Stages, r)
			continue
		}
		from, fromMode := declaredVersion(before, s.Component)
		to, toMode := declaredVersion(after, s.Component)
		if from == "" || to == "" {
			r.Gaps = append(r.Gaps, "supply component versions and deployment modes in both manifests")
			result.Stages = append(result.Stages, r)
			continue
		}
		if (constraintengine.RuleTransition{From: from, To: to}).Match(s.From, s.To) != constraintengine.MatchAnchor {
			return result, cncfcheck.ErrIntegrity
		}
		if fromMode != toMode {
			r.Gaps = append(r.Gaps, "obtain reviewed knowledge for the deployment mode change")
		}
		mode := map[string]string{"kubernetes": "official-rendered-apply-set", "cilium": "official-policy-set", "cert-manager": "official-chart-merged-values"}[s.Component]
		if mode == "" || fromMode != mode || toMode != mode {
			r.Gaps = append(r.Gaps, "supply a supported route and deployment mode or obtain a reviewed adapter for this mode")
			result.Stages = append(result.Stages, r)
			continue
		}
		if err := evaluateDeclaredRoute(req.Context, s, before, after, &r); err != nil {
			return result, err
		}
		if r.Status == "BLOCKED" {
			result.Status = "BLOCKED"
		}
		result.Stages = append(result.Stages, r)
	}
	if len(req.Stages) == 0 {
		result.NextAction = "supply at least one declared stage with exact before/after artifact references"
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return result, err
	}
	seal := declaredHash(raw)
	result.seal = &seal
	return result, nil
}

func evaluateDeclaredRoute(ctx declaredContext, s declaredStage, before, after admittedDeclaredArtifact, out *declaredStageResult) error {
	if ctx.KnowledgeOrigin != "embedded" {
		out.Gaps = append(out.Gaps, "select embedded knowledge explicitly; other origins are unsupported in this mode")
		return nil
	}
	if ctx.Target == "" || ctx.Intent == "" {
		out.Gaps = append(out.Gaps, "declare target identity and change intent")
	}
	var entry *declaredEntry
	var raw []byte
	for i, e := range before.manifest.Entries {
		if e.Role == s.Component {
			if entry != nil {
				return cncfcheck.ErrIntegrity
			}
			entry = &before.manifest.Entries[i]
			raw = before.inputs[i]
		}
	}
	if entry == nil {
		out.Gaps = append(out.Gaps, "supply the selected route's minimized input in the before artifact")
		return nil
	}
	out.SourceDigest = entry.Digest
	if s.Component == "cert-manager" {
		return evaluateDeclaredCert(ctx, s, *entry, raw, after, out)
	}
	var p cncfprepare.Prepared
	var err error
	var facts []string
	switch s.Component {
	case "kubernetes":
		p, _, err = cncfprepare.PrepareKubernetesRemovedAPIsLocated(raw, entry.LogicalName, s.From, s.To, entry.Distribution, entry.TargetApplyRequired, entry.Complete != nil && *entry.Complete)
		facts = cncfprepare.KubernetesRemovedAPIFacts(s.From, s.To)
	case "cilium":
		p, err = cncfprepare.PrepareCilium(raw, s.From, s.To, entry.Complete)
		facts = []string{cncfprepare.CiliumRequiresFact}
	default:
		out.Gaps = append(out.Gaps, "obtain a reviewed adapter for this component")
		return nil
	}
	if err != nil {
		return err
	}
	if p.SourceDigest != entry.Digest {
		return cncfcheck.ErrIntegrity
	}
	out.PreparedInputDigest = p.InputDigest
	policy, err := cncfcheck.ParseTrustPolicy(ctx.TrustBases)
	if err != nil {
		return err
	}
	if ctx.TrustBases == "" {
		out.Gaps = append(out.Gaps, "declare the accepted evidence bases explicitly; the engine used its default policy")
	}
	now, err := time.Parse(time.RFC3339, ctx.EvaluatedAt)
	if ctx.EvaluatedAt == "" {
		out.Gaps = append(out.Gaps, "declare an exact UTC evaluation clock")
		return nil
	}
	if err != nil || now.Location() != time.UTC || now.Nanosecond() != 0 {
		return cncfcheck.ErrInvalid
	}
	r := runtime{trust: policy}
	report, err := r.cncfChecker().CheckFacts(s.Component, facts, p.CanonicalInputJSON, now)
	if err != nil {
		return err
	}
	if report.InputFileDigest != p.InputDigest || report.Check.EvaluatedAt != ctx.EvaluatedAt || report.Project != s.Component || report.KnowledgeOrigin != "embedded" {
		return cncfcheck.ErrIntegrity
	}
	for _, pair := range [][2]string{{ctx.PolicyID, report.Check.PolicyID}, {ctx.PolicyDigest, report.Check.PolicyDigest}, {ctx.KnowledgeRevision, report.KnowledgeRevision}, {ctx.KnowledgeDigest, report.KnowledgePackDigest}} {
		if pair[0] == "" {
			out.Gaps = append(out.Gaps, "declare the exact policy and embedded knowledge identities from the issued report")
		} else if pair[0] != pair[1] {
			return cncfcheck.ErrIntegrity
		}
	}
	out.EngineInputDigest = report.Check.InputDigest
	out.Report, err = cncfcheck.MarshalReport(report)
	if err != nil {
		return err
	}
	out.Gaps = append(out.Gaps, p.Omissions...)
	for _, c := range report.Check.Claims {
		if c.Status == "BLOCKED" {
			out.Status = "BLOCKED"
		}
	}
	return nil
}

func evaluateDeclaredCert(ctx declaredContext, s declaredStage, e declaredEntry, raw []byte, after admittedDeclaredArtifact, out *declaredStageResult) error {
	values, err := certmanagervalues.ParseArtifact(raw, e.Digest)
	if err != nil {
		return err
	}
	targetDigest := ""
	for _, ae := range after.manifest.Entries {
		if ae.Role == "cert-manager" {
			targetDigest = ae.ChartDigest
		}
	}
	report, err := certmanagervalues.Evaluate(certmanagervalues.Request{Values: values, From: s.From, To: s.To, CurrentChartDigest: e.ChartDigest, TargetChartDigest: targetDigest, SchemaValidation: e.SchemaValidation})
	if err != nil {
		return err
	}
	if report.Inputs.ValuesDigest != e.Digest || (e.SchemaValidation != "" && report.Policy.SchemaValidation != e.SchemaValidation) {
		return cncfcheck.ErrIntegrity
	}
	if report.Transition.DeclaredTransitionState == "exact_reviewed" {
		if (constraintengine.RuleTransition{From: report.Transition.ReviewedFrom, To: report.Transition.ReviewedTo}).Match(s.From, s.To) != constraintengine.MatchAnchor {
			return cncfcheck.ErrIntegrity
		}
	} else {
		out.Gaps = append(out.Gaps, "obtain a reviewed cert-manager contract for these exact chart endpoints")
	}
	if ctx.CertManagerKnowledgeDigest != "" && ctx.CertManagerKnowledgeDigest != report.Inputs.KnowledgeRevisionDigest {
		return cncfcheck.ErrIntegrity
	}
	if ctx.CertManagerKnowledgeDigest == "" {
		out.Gaps = append(out.Gaps, "declare the cert-manager source contract digest separately")
	}
	if e.SchemaValidation == "" || e.ChartDigest == "" || targetDigest == "" {
		out.Gaps = append(out.Gaps, "declare schema validation mode and both exact official chart digests")
	}
	out.Gaps = append(out.Gaps, "cert-manager does not bind an evaluation clock or general policy; obtain an evaluator contract covering those fields")
	out.Gaps = append(out.Gaps, report.Omissions...)
	out.Report, err = certmanagervalues.MarshalReport(report)
	if report.Claim.Status == "BLOCKED" {
		out.Status = "BLOCKED"
	}
	return err
}

func marshalDeclared(result declaredResult) ([]byte, error) {
	raw, err := json.Marshal(result)
	if err != nil || result.seal == nil || declaredHash(raw) != *result.seal {
		return nil, cncfcheck.ErrIntegrity
	}
	return raw, nil
}

func replayDeclared(req declaredRequest, artifacts map[string]admittedDeclaredArtifact, receipt []byte) error {
	result, err := evaluateDeclared(req, artifacts)
	if err != nil {
		return err
	}
	raw, err := marshalDeclared(result)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, bytes.TrimSuffix(receipt, []byte("\n"))) {
		return cncfcheck.ErrIntegrity
	}
	return nil
}

func (r runtime) declaredPlan(args []string) int {
	if len(args) != 2 || args[0] != "--declared-state" {
		return r.fail("use prufyx plan --declared-state REQUEST.json (canonical private JSON)", ExitUsage)
	}
	path, err := filepath.Abs(args[1])
	if err != nil {
		return r.fail("invalid declared-state request path", ExitUsage)
	}
	raw, err := readDeclaredFile(path)
	if err != nil {
		return r.fail("declared-state request admission failed", ExitIntegrity)
	}
	req, err := decodeDeclared(raw)
	if err != nil {
		return r.fail("declared-state request must use the canonical typed schema", ExitUsage)
	}
	artifacts, err := admitDeclared(req, filepath.Dir(path))
	if err != nil {
		return r.fail("declared-state artifact admission or integrity failed", ExitIntegrity)
	}
	result, err := evaluateDeclared(req, artifacts)
	if err != nil {
		return r.fail("declared-state evaluation integrity failed", ExitIntegrity)
	}
	output, err := marshalDeclared(result)
	if err != nil {
		return r.fail("declared-state serialization integrity failed", ExitIntegrity)
	}
	if _, err = fmt.Fprintln(r.stdout, string(output)); err != nil {
		return ExitIntegrity
	}
	if result.Status == "BLOCKED" {
		return 10
	}
	return 11
}
