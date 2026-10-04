// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sfeaturegates"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

// Inventory kinds.
const (
	// InventoryFeatureGates is every feature gate the release declares.
	InventoryFeatureGates = "feature-gates"
	// InventoryFeatureGateNames is every feature gate name the release's
	// source spells anywhere (the set a removal must be absent from).
	InventoryFeatureGateNames = "feature-gate-names"
	// InventoryServedAPIVersions is every group/version the release's
	// OpenAPI specification declares a kind for.
	InventoryServedAPIVersions = "served-api-versions"
)

// InventorySchema identifies the canonical form an inventory digest is
// computed over.
const InventorySchema = "prufyx.io/consensus-inventory/v1"

// Incomplete means an inventory cannot be established completely. A
// consumer must never read absence from an incomplete inventory.
type Incomplete struct{ Reason string }

func (e *Incomplete) Error() string { return "incomplete: " + e.Reason }

// IsIncomplete reports whether err is an *Incomplete.
func IsIncomplete(err error) bool {
	var i *Incomplete
	return errors.As(err, &i)
}

// Inventory is the complete set of names of one kind at one commit.
type Inventory struct {
	Kind   string
	Repo   string
	Commit string
	Names  map[string]bool
	// Digest is "sha256:<hex>" over the canonical JSON of the inventory.
	Digest string
}

func newInventory(kind, repo, commit string, names []string) (*Inventory, error) {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	sorted := make([]string, 0, len(set))
	for n := range set {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	raw, err := extract.Canonical(struct {
		Schema string   `json:"schema"`
		Kind   string   `json:"kind"`
		Repo   string   `json:"repo"`
		Commit string   `json:"commit"`
		Names  []string `json:"names"`
	}{InventorySchema, kind, repo, commit, sorted})
	if err != nil {
		return nil, err
	}
	return &Inventory{Kind: kind, Repo: repo, Commit: commit, Names: set, Digest: "sha256:" + FileDigest(raw)}, nil
}

// Inventories serves complete mechanical inventories. It returns an
// *Incomplete error whenever the inventory is not complete.
type Inventories interface {
	Inventory(ctx context.Context, kind string, repo extract.RepoRef, commit string) (*Inventory, error)
}

// ExtractorInventories builds inventories with the extractors compiled into
// this binary, through their exported entry points only (their source and
// code digests are untouched): feature gates from the feature-gate
// extractor's own proof of a pair whose two sides are the same commit,
// served API versions from the commit's OpenAPI specification.
type ExtractorInventories struct {
	Reader      extract.PinnedReader
	Concurrency int

	mu    sync.Mutex
	cache map[string]*Inventory
	errs  map[string]error
}

// Inventory implements Inventories.
func (x *ExtractorInventories) Inventory(ctx context.Context, kind string, repo extract.RepoRef, commit string) (*Inventory, error) {
	key := kind + "\x00" + repo.Key + "\x00" + commit
	x.mu.Lock()
	if inv, ok := x.cache[key]; ok {
		x.mu.Unlock()
		return inv, nil
	}
	if err, ok := x.errs[key]; ok {
		x.mu.Unlock()
		return nil, err
	}
	x.mu.Unlock()
	inv, err := x.build(ctx, kind, repo, commit)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.cache == nil {
		x.cache, x.errs = map[string]*Inventory{}, map[string]error{}
	}
	if err != nil {
		if ctx.Err() == nil {
			// A cancelled or timed-out build is not a property of the
			// commit; only other errors are remembered.
			x.errs[key] = err
		}
		return nil, err
	}
	x.cache[key] = inv
	return inv, nil
}

func (x *ExtractorInventories) build(ctx context.Context, kind string, repo extract.RepoRef, commit string) (*Inventory, error) {
	if !extract.IsCommitSHA(commit) {
		return nil, errors.New("the commit must be a full lowercase 40-character SHA")
	}
	if repo.Key != KubernetesRepo {
		return nil, &Incomplete{Reason: "no inventory for repository " + repo.Key}
	}
	switch kind {
	case InventoryFeatureGates, InventoryFeatureGateNames:
		declared, names, err := x.featureGates(ctx, repo, commit)
		if err != nil {
			return nil, err
		}
		if kind == InventoryFeatureGates {
			return newInventory(kind, repo.Key, commit, declared)
		}
		return newInventory(kind, repo.Key, commit, names)
	case InventoryServedAPIVersions:
		return x.servedAPIVersions(repo, commit)
	}
	return nil, &Incomplete{Reason: "no inventory of kind " + kind}
}

// noEvidence reports reader errors that mean "no evidence".
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

func (x *ExtractorInventories) featureGates(ctx context.Context, repo extract.RepoRef, commit string) ([]string, []string, error) {
	concurrency := x.Concurrency
	if concurrency < 1 {
		concurrency = 4
	}
	ex := k8sfeaturegates.New(concurrency)
	pair := extract.VersionPair{Repo: repo, From: "inventory", FromTag: "inventory", FromCommit: commit, To: "inventory", ToTag: "inventory", ToCommit: commit}
	res, err := ex.Extract(ctx, x.Reader, pair)
	if w, ok := extract.IsWithheld(err); ok {
		return nil, nil, &Incomplete{Reason: w.Reason}
	}
	if err != nil {
		if noEvidence(err) {
			return nil, nil, &Incomplete{Reason: err.Error()}
		}
		return nil, nil, err
	}
	raw, err := json.Marshal(res.Proof)
	if err != nil {
		return nil, nil, err
	}
	var proof struct {
		From struct {
			Complete bool     `json:"complete"`
			Declared []string `json:"declared"`
		} `json:"from"`
		To struct {
			Complete bool     `json:"complete"`
			Names    []string `json:"names"`
		} `json:"to"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return nil, nil, err
	}
	if !proof.From.Complete || !proof.To.Complete {
		return nil, nil, &Incomplete{Reason: "the feature gate registry is not complete"}
	}
	if len(proof.From.Declared) == 0 || len(proof.To.Names) == 0 {
		return nil, nil, &Incomplete{Reason: "no feature gate is declared at this commit"}
	}
	return proof.From.Declared, proof.To.Names, nil
}

const openAPISpecPath = "api/openapi-spec/swagger.json"

func (x *ExtractorInventories) servedAPIVersions(repo extract.RepoRef, commit string) (*Inventory, error) {
	src, err := x.Reader.Read(repo, commit, openAPISpecPath)
	if err != nil {
		if noEvidence(err) {
			return nil, &Incomplete{Reason: openAPISpecPath + ": " + err.Error()}
		}
		return nil, err
	}
	versions, err := servedGroupVersions(src)
	if err != nil {
		return nil, &Incomplete{Reason: openAPISpecPath + ": " + err.Error()}
	}
	return newInventory(InventoryServedAPIVersions, repo.Key, commit, versions)
}

// servedGroupVersions returns the group/version of every kind an OpenAPI
// document declares through x-kubernetes-group-version-kind ("v1" for the
// core group). Every entry must name a version and a kind, and a document
// that declares nothing is refused: the rule of the served-API extractor.
func servedGroupVersions(src []byte) ([]string, error) {
	var doc struct {
		Swagger     string `json:"swagger"`
		Definitions map[string]struct {
			GVK []struct {
				Group   string `json:"group"`
				Version string `json:"version"`
				Kind    string `json:"kind"`
			} `json:"x-kubernetes-group-version-kind"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, d := range doc.Definitions {
		for _, g := range d.GVK {
			if g.Version == "" || g.Kind == "" {
				return nil, fmt.Errorf("incomplete group-version-kind %+v", g)
			}
			gv := g.Version
			if g.Group != "" {
				gv = g.Group + "/" + g.Version
			}
			set[gv] = true
		}
	}
	if doc.Swagger == "" || len(set) == 0 {
		return nil, fmt.Errorf("not a Kubernetes OpenAPI specification declaring kinds")
	}
	out := make([]string, 0, len(set))
	for gv := range set {
		out = append(out, gv)
	}
	sort.Strings(out)
	return out, nil
}
