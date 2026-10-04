// SPDX-License-Identifier: AGPL-3.0-only

// Package inventory prints the complete mechanical inventory an extractor
// parsed at one upstream commit: every feature gate, every served
// group/version/kind or every custom resource version, as canonical JSON.
//
// An inventory is either complete or not printed: whenever the extractor
// cannot establish the commit completely (a file is not local, a listed
// path is missing, a parse is refused) Build returns an *Incomplete error
// and no list. A consumer that checks a claim against an inventory
// (does this gate exist at this commit?) can therefore never read absence
// from a partial list.
//
// The package reads through the extractors' exported entry points only, so
// it does not change any extractor's source and therefore not its code
// digest: feature gates and CRD versions come from the extractor's own
// proof of a pair whose two sides are the same commit; served kinds are the
// group/version/kinds the commit's OpenAPI specification declares, parsed
// by the same rule the extractor applies (a test holds the two equal on
// every fixture commit).
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sfeaturegates"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

// Schema identifies an inventory document.
const Schema = "prufyx.io/extractor-inventory/v1"

// Incomplete means the commit's inventory cannot be established completely.
type Incomplete struct{ Reason string }

func (e *Incomplete) Error() string { return "incomplete: " + e.Reason }

// IsIncomplete reports whether err is an *Incomplete.
func IsIncomplete(err error) (*Incomplete, bool) {
	var i *Incomplete
	if errors.As(err, &i) {
		return i, true
	}
	return nil, false
}

// Document is the head every inventory shares.
type Document struct {
	Schema    string `json:"schema"`
	Extractor string `json:"extractor"`
	Repo      string `json:"repo"`
	Commit    string `json:"commit"`
	Kind      string `json:"kind"`
}

// Kinds of inventory.
const (
	KindFeatureGates = "feature-gates"
	KindServedAPIs   = "served-apis"
	KindCRDVersions  = "crd-versions"
)

// noEvidence reports a reader error that means "no evidence": the caller
// must treat the inventory as incomplete.
func noEvidence(err error) bool {
	for _, e := range []error{
		factorymirror.ErrBlobNotLocal, factorymirror.ErrCommitUnknown, factorymirror.ErrRepoNotMirrored,
		factorymirror.ErrPathNotFound, factorymirror.ErrNotAFile, factorymirror.ErrTooLarge,
		factorymirror.ErrRepoFrozen, extract.ErrNotFound,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// Build returns the canonical JSON inventory of extractor ex at commit of
// repo, read through r.
func Build(ctx context.Context, ex extract.Extractor, r extract.PinnedReader, repo extract.RepoRef, commit string) ([]byte, error) {
	if !extract.IsCommitSHA(commit) {
		return nil, errors.New("the commit must be a full lowercase 40-character SHA")
	}
	if !ex.Applies(repo) {
		return nil, fmt.Errorf("extractor %s does not read repository %q", ex.ID(), repo.Key)
	}
	head := Document{Schema: Schema, Extractor: ex.ID(), Repo: repo.Key, Commit: commit}
	switch {
	case ex.ID() == k8sfeaturegates.ID:
		head.Kind = KindFeatureGates
		return featureGates(ctx, ex, r, repo, head)
	case ex.ID() == k8sservedapis.ID:
		head.Kind = KindServedAPIs
		return servedAPIs(r, repo, head)
	case strings.HasPrefix(ex.ID(), crdversions.IDPrefix):
		head.Kind = KindCRDVersions
		return crdVersions(ctx, ex, r, repo, head)
	}
	return nil, fmt.Errorf("extractor %s has no inventory", ex.ID())
}

// proofOf runs the extractor on the pair whose two sides are the commit and
// returns its proof as JSON. A withheld pair is incomplete.
func proofOf(ctx context.Context, ex extract.Extractor, r extract.PinnedReader, repo extract.RepoRef, commit string) ([]byte, error) {
	pair := extract.VersionPair{Repo: repo, From: "inventory", FromTag: "inventory", FromCommit: commit, To: "inventory", ToTag: "inventory", ToCommit: commit}
	res, err := ex.Extract(ctx, r, pair)
	if w, ok := extract.IsWithheld(err); ok {
		return nil, &Incomplete{Reason: w.Reason}
	}
	if err != nil {
		if noEvidence(err) {
			return nil, &Incomplete{Reason: err.Error()}
		}
		return nil, err
	}
	return json.Marshal(res.Proof)
}

func featureGates(ctx context.Context, ex extract.Extractor, r extract.PinnedReader, repo extract.RepoRef, head Document) ([]byte, error) {
	raw, err := proofOf(ctx, ex, r, repo, head.Commit)
	if err != nil {
		return nil, err
	}
	var proof struct {
		From struct {
			Complete bool     `json:"complete"`
			Problems []string `json:"problems"`
			Declared []string `json:"declared"`
		} `json:"from"`
		To struct {
			Complete bool     `json:"complete"`
			Problems []string `json:"problems"`
			Names    []string `json:"names"`
		} `json:"to"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return nil, err
	}
	if !proof.From.Complete || !proof.To.Complete {
		reason := "the feature-gate registry is not complete"
		if len(proof.To.Problems) > 0 {
			reason += ": " + proof.To.Problems[0]
		} else if len(proof.From.Problems) > 0 {
			reason += ": " + proof.From.Problems[0]
		}
		return nil, &Incomplete{Reason: reason}
	}
	if len(proof.From.Declared) == 0 {
		return nil, &Incomplete{Reason: "no feature gate is declared at this commit"}
	}
	declared, names := append([]string{}, proof.From.Declared...), append([]string{}, proof.To.Names...)
	sort.Strings(declared)
	sort.Strings(names)
	return extract.Canonical(struct {
		Document
		Declared []string `json:"declared"`
		Names    []string `json:"names"`
	}{head, declared, names})
}

// GVK is one served group/version/kind.
type GVK struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

const specPath = "api/openapi-spec/swagger.json"

func servedAPIs(r extract.PinnedReader, repo extract.RepoRef, head Document) ([]byte, error) {
	src, err := r.Read(repo, head.Commit, specPath)
	if err != nil {
		if noEvidence(err) {
			return nil, &Incomplete{Reason: specPath + ": " + err.Error()}
		}
		return nil, err
	}
	gvks, err := ParseSpec(src)
	if err != nil {
		return nil, &Incomplete{Reason: specPath + ": " + err.Error()}
	}
	return extract.Canonical(struct {
		Document
		GVKs []GVK `json:"gvks"`
	}{head, gvks})
}

// ParseSpec returns the group/version/kinds an OpenAPI document declares
// through x-kubernetes-group-version-kind, sorted by group, version, kind.
// It applies the rule of the served-API extractor: every entry names a
// version and a kind, and a document that declares nothing is refused.
func ParseSpec(src []byte) ([]GVK, error) {
	var doc struct {
		Swagger     string `json:"swagger"`
		Definitions map[string]struct {
			GVK []GVK `json:"x-kubernetes-group-version-kind"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	set := map[GVK]bool{}
	for _, d := range doc.Definitions {
		for _, g := range d.GVK {
			if g.Version == "" || g.Kind == "" {
				return nil, fmt.Errorf("incomplete group-version-kind %+v", g)
			}
			set[g] = true
		}
	}
	if doc.Swagger == "" || len(set) == 0 {
		return nil, fmt.Errorf("not a Kubernetes OpenAPI specification declaring kinds (%d)", len(set))
	}
	out := make([]GVK, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	key := func(g GVK) string { return g.Group + "\x00" + g.Version + "\x00" + g.Kind }
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out, nil
}

// CRDVersion is one version of a custom resource definition.
type CRDVersion struct {
	Name    string `json:"name"`
	Served  bool   `json:"served"`
	Storage bool   `json:"storage"`
}

// CRD is one custom resource definition at the commit.
type CRD struct {
	Name           string       `json:"name"`
	Group          string       `json:"group"`
	Kind           string       `json:"kind"`
	Scope          string       `json:"scope"`
	Path           string       `json:"path"`
	StorageVersion string       `json:"storageVersion"`
	Versions       []CRDVersion `json:"versions"`
}

func crdVersions(ctx context.Context, ex extract.Extractor, r extract.PinnedReader, repo extract.RepoRef, head Document) ([]byte, error) {
	raw, err := proofOf(ctx, ex, r, repo, head.Commit)
	if err != nil {
		return nil, err
	}
	var proof struct {
		Target  string `json:"target"`
		Earlier *struct {
			Complete bool   `json:"complete"`
			Problem  string `json:"problem"`
			CRDs     []CRD  `json:"crds"`
		} `json:"from"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return nil, err
	}
	if proof.Earlier == nil || !proof.Earlier.Complete || len(proof.Earlier.CRDs) == 0 {
		return nil, &Incomplete{Reason: "the custom resource inventory is not complete"}
	}
	crds := make([]CRD, 0, len(proof.Earlier.CRDs))
	for _, c := range proof.Earlier.CRDs {
		vs := append([]CRDVersion{}, c.Versions...)
		sort.Slice(vs, func(i, j int) bool { return vs[i].Name < vs[j].Name })
		c.Versions = vs
		crds = append(crds, c)
	}
	sort.Slice(crds, func(i, j int) bool { return crds[i].Name < crds[j].Name })
	return extract.Canonical(struct {
		Document
		Project string `json:"project"`
		CRDs    []CRD  `json:"crds"`
	}{head, proof.Target, crds})
}
