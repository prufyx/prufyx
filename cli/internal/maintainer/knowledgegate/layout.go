// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/corpusattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgetargets"
	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
	"github.com/prufyx/prufyx/cli/internal/maintainer/supportinventory"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

// PackStats is what admitting one pack reports.
type PackStats struct {
	Entries                         int
	TargetBytes, MaxTargetBytes     int
	RegistryFacts, MaxRegistryFacts int
	// Split is true for a pack also published as one target per project
	// plus an index; Targets are those targets, SplitErr why the pack
	// could not be split.
	Split    bool
	Targets  []knowledgetargets.Target
	SplitErr error
}

// PackSpec describes one rule pack the gate checks. Paths are relative to
// the repository root, with forward slashes.
type PackSpec struct {
	// Name is the pack's short name, also its reattestation pack name.
	Name string
	// Path is the rules.json path. It is also the pack path a
	// reattestation worklist must name.
	Path string
	// Admit admits the pack as the engine admits shipped knowledge, from
	// the files of a tree, and reports its size.
	Admit func(t Tree) (PackStats, error)
	// View decodes the pack file as admission decodes it: its top-level
	// members other than entries, and its entries, each re-encoded from
	// the engine's own types. Entry does the same for one entry.
	View  func(raw []byte) (map[string]json.RawMessage, []json.RawMessage, error)
	Entry func(raw []byte) (json.RawMessage, error)
	// AttestationPath is the committed corpus attestation; Attest
	// regenerates it from the tree's files.
	AttestationPath string
	Attest          func(t Tree) ([]byte, error)
	// CapabilityDigest is the engine identity reattestation statements
	// for this pack are bound to.
	CapabilityDigest func() (string, error)
	// Records is true for a pack that may carry line attestations and
	// path policies: they are then read and diffed record by record.
	// For any other pack a change to those members is a pack-member
	// change.
	Records bool
	// RequiredSchema returns the lowest schema the pack file's content
	// requires and SchemaLevel the ascending level of a schema (false for
	// an unknown one). Both set admit the first change of the pack's
	// schema to the level its content needs (schema.go); a pack without
	// them never admits a schema change.
	RequiredSchema func(raw []byte) (string, error)
	SchemaLevel    func(schema string) (int, bool)
}

// GeneratedPair is a generated JSON and Markdown output pair.
type GeneratedPair struct {
	JSONPath, MarkdownPath string
	Generate               func(t Tree) (jsonRaw []byte, markdown string, err error)
}

// Layout names every knowledge file the gate reads.
type Layout struct {
	Packs []PackSpec
	// PausePath is the kill switch: while it exists in the base or the
	// head, every loosening change fails.
	PausePath string
	// ReattestDir holds, per pack, <pack>/chain (the signed statement
	// chain), <pack>/worklists/<stem>.worklist.json (the worklist each
	// statement was prepared from) and <pack>/review-records.
	ReattestDir string
	// TrustRootPath is the reattestation trust root. It is read from the
	// base tree only; its digest must be supplied separately.
	TrustRootPath string
	// ApprovalDir holds owner approvals as <pack>/<rule id>.json.
	ApprovalDir string
	// BatchDir holds owner batch approvals as <batch id>.json (see
	// batch.go). It is not under a pack's approval directory, whose
	// readers refuse a subdirectory. Empty disables batch approvals.
	BatchDir string
	// ApprovalKeysPath pins the owner-approval keys. It is read from the
	// base tree only.
	ApprovalKeysPath string
	// BaselinesPath is the owner baseline file (package repinbaselines). A
	// change to it needs an owner approval per entry, kept under
	// ApprovalDir/repin-baselines/.
	BaselinesPath string
	// ConsensusClaimsDir holds, as <pack>/<rule id>.json, the claims
	// bundle of a consensus rule. The gate re-runs the consensus verifier
	// on it and reports the verdict; it never admits the rule.
	ConsensusClaimsDir string
	// Generated are outputs that must regenerate byte-identically.
	Generated []GeneratedPair
	// AutoMergePaths lists the paths an automatically mergeable change may
	// touch: an entry ending in "/" is a directory prefix, any other entry
	// an exact file. Trust material is never among them.
	AutoMergePaths []string
	// TrustPaths lists trust material (same form as AutoMergePaths). Any
	// file named trust-root* or *approval-keys* is trust material too.
	TrustPaths []string
	// RegistryPaths lists the registry JSON files named here (the
	// landscape, the portfolio, the community project registry). The
	// Go-coded fact registry is not a file in this list; a change of it moves
	// the pack's registryDigest member, which is a top-level member change
	// and refuses the schema change on its own. A change of a pack's schema level is never admitted in a
	// change that also touches one of them.
	RegistryPaths []string
}

// Repository paths of the default layout.
const (
	cliDir         = "cli"
	cncfRulesPath  = "cli/internal/cncfcheck/data/rules.json"
	cncfAttestPath = "cli/internal/cncfcheck/data/corpus-attestation.json"
	commRulesPath  = "cli/internal/projectcheck/data/rules.json"
	commAttestPath = "cli/internal/projectcheck/data/corpus-attestation.json"
	inventoryJSON  = "cli/docs/generated/community-support-inventory.json"
	inventoryMD    = "cli/docs/generated/community-support-inventory.md"
	trustDir       = "cli/knowledge/trust/"
	reattestDir    = "cli/knowledge/reattestation"
	approvalDir    = "cli/knowledge/approvals"
	trustRootPath  = "cli/knowledge/reattestation/trust-root.json"
	approvalKeys   = "cli/knowledge/trust/web-approval-keys.json"
	consensusDir   = "cli/knowledge/consensus-claims"
)

func readAll(t Tree, rels ...string) ([][]byte, error) {
	out := make([][]byte, len(rels))
	for i, rel := range rels {
		raw, err := t.Read(rel, MaxFileBytes)
		if err != nil {
			return nil, err
		}
		out[i] = raw
	}
	return out, nil
}

// DefaultLayout is the layout of this repository.
func DefaultLayout() Layout {
	return Layout{
		Packs: []PackSpec{
			{
				Name: evidencereattest.PackCNCF, Path: cncfRulesPath,
				Admit: func(t Tree) (PackStats, error) {
					files, err := readAll(t, "cli/internal/cncfcheck/data/landscape-projects.json", "cli/internal/cncfcheck/data/priority-portfolio.json", cncfRulesPath)
					if err != nil {
						return PackStats{}, err
					}
					r, err := cncfcheck.CheckPackFiles(files[0], files[1], files[2])
					if err != nil {
						return PackStats{}, err
					}
					stats := PackStats{Entries: r.Entries, TargetBytes: r.TargetBytes, MaxTargetBytes: r.MaxTargetBytes, RegistryFacts: r.RegistryFacts, MaxRegistryFacts: r.MaxRegistryFacts, Split: true, SplitErr: r.SplitErr}
					for _, target := range r.ProjectTargets {
						stats.Targets = append(stats.Targets, knowledgetargets.Target{Path: target.Path, Bytes: int64(len(target.Bytes))})
					}
					return stats, nil
				},
				View: cncfcheck.AdmittedPackView, Entry: cncfcheck.AdmittedEntry,
				AttestationPath: cncfAttestPath,
				Attest: func(t Tree) ([]byte, error) {
					return corpusattest.DocumentFromFiles(corpusattest.PackCNCF, t.readUnder(cliDir))
				},
				CapabilityDigest: cncfcheck.ExternalCapabilityDigest,
				Records:          true,
				RequiredSchema:   cncfcheck.RequiredPackSchema,
				SchemaLevel:      cncfcheck.PackSchemaLevel,
			},
			{
				Name: evidencereattest.PackCommunity, Path: commRulesPath,
				Admit: func(t Tree) (PackStats, error) {
					files, err := readAll(t, "cli/internal/projectcheck/data/projects.json", commRulesPath)
					if err != nil {
						return PackStats{}, err
					}
					r, err := projectcheck.CheckPackFiles(files[0], files[1])
					if err != nil {
						return PackStats{}, err
					}
					return PackStats{Entries: r.Entries, TargetBytes: r.TargetBytes, MaxTargetBytes: r.MaxTargetBytes, RegistryFacts: r.RegistryFacts, MaxRegistryFacts: r.MaxRegistryFacts}, nil
				},
				View: projectcheck.AdmittedPackView, Entry: projectcheck.AdmittedEntry,
				AttestationPath: commAttestPath,
				Attest: func(t Tree) ([]byte, error) {
					return corpusattest.DocumentFromFiles(corpusattest.PackCommunity, t.readUnder(cliDir))
				},
				CapabilityDigest: func() (string, error) { return constraintengine.EngineContractDigest(), nil },
			},
		},
		PausePath:          "factory/PAUSE",
		ReattestDir:        reattestDir,
		TrustRootPath:      trustRootPath,
		ApprovalDir:        approvalDir,
		BatchDir:           approvalDir + "/batches",
		ApprovalKeysPath:   approvalKeys,
		BaselinesPath:      repinbaselines.DefaultPath,
		ConsensusClaimsDir: consensusDir,
		Generated: []GeneratedPair{{
			JSONPath: inventoryJSON, MarkdownPath: inventoryMD,
			Generate: func(t Tree) ([]byte, string, error) {
				return supportinventory.Generate(supportInventoryConfig(t))
			},
		}},
		AutoMergePaths: []string{
			cncfRulesPath, cncfAttestPath, commRulesPath, commAttestPath, inventoryJSON, inventoryMD,
			approvalDir + "/",
			reattestDir + "/" + evidencereattest.PackCNCF + "/chain/",
			reattestDir + "/" + evidencereattest.PackCNCF + "/worklists/",
			reattestDir + "/" + evidencereattest.PackCNCF + "/review-records/",
			reattestDir + "/" + evidencereattest.PackCommunity + "/chain/",
			reattestDir + "/" + evidencereattest.PackCommunity + "/worklists/",
			reattestDir + "/" + evidencereattest.PackCommunity + "/review-records/",
		},
		TrustPaths: []string{trustDir, trustRootPath, approvalKeys},
		RegistryPaths: []string{
			"cli/internal/cncfcheck/data/landscape-projects.json",
			"cli/internal/cncfcheck/data/priority-portfolio.json",
			"cli/internal/projectcheck/data/projects.json",
		},
	}
}

// supportInventoryConfig points the support inventory generator at a tree's
// files, the same inputs the maintainer command uses by default, read
// through the tree's own reader.
func supportInventoryConfig(t Tree) supportinventory.Config {
	p := func(rel string) string { return filepath.Join(t.Root, cliDir, filepath.FromSlash(rel)) }
	return supportinventory.Config{
		Rules:                  p("internal/cncfcheck/data/rules.json"),
		Landscape:              p("internal/cncfcheck/data/landscape-projects.json"),
		CertContract:           p("internal/certmanagervalues/source-contract-v1.json"),
		PrometheusContract:     p("internal/prometheusmode/source-contract-v1.json"),
		SPIFFEProfile:          p("internal/spiffex509svid/data/profile.json"),
		CloudEventsProfile:     p("internal/cloudeventsstructuredjson/data/profile.json"),
		TiKVProfile:            p("internal/tikvgcpv2/data/profile.json"),
		CNCFPrepareSource:      p("internal/communityapp/cncf_prepare.go"),
		ProjectRules:           p("internal/projectcheck/data/rules.json"),
		ProjectRegistry:        p("internal/projectcheck/data/projects.json"),
		SelectedSourceManifest: p("docs/data/selected-source-records-v1.json"),
		// Every input is read through the tree: no links, no FIFOs or
		// devices, bounded sizes.
		ReadFile: t.readPath,
	}
}

// autoMergePath reports whether a change to rel is allowed in an
// automatically mergeable change.
func (l Layout) autoMergePath(rel string) bool {
	if l.trustPath(rel) {
		return false
	}
	for _, allowed := range l.AutoMergePaths {
		if strings.HasSuffix(allowed, "/") {
			if strings.HasPrefix(rel, allowed) {
				return true
			}
		} else if rel == allowed {
			return true
		}
	}
	return false
}
