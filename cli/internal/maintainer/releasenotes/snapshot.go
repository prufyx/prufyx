// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

// Paths of the data files a snapshot is read from.
const (
	cncfRulesPath     = "cli/internal/cncfcheck/data/rules.json"
	projectRulesPath  = "cli/internal/projectcheck/data/rules.json"
	inventoryPath     = "cli/docs/generated/community-support-inventory.json"
	onboardingDir     = "cli/knowledge/onboarding"
	crdTablePath      = "cli/internal/customresources/table.json"
	readmePath        = "README.md"
	kubernetesPackage = "pkg:github/kubernetes/kubernetes"
	maxFile           = 64 << 20
)

// Catalogue names the rule file a rule comes from.
type Catalogue string

const (
	CNCF      Catalogue = "CNCF"
	Community Catalogue = "community-project"
)

type projectKey struct {
	Catalogue Catalogue
	Project   string
}

// Depth holds the version-coverage figures of the README coverage block,
// which scripts/readme-coverage.sh generates from `coverage report` and CI
// keeps current.
type Depth struct {
	GeneratedOn string
	Projects    int
	Pairs       int
	Decided     int // A + B
	Exact       int // S
	Gap         int // G
}

// OnboardedProject is one project entry of an owner-approved onboarding batch.
type OnboardedProject struct {
	Batch    string
	Slug     string
	Catalog  string
	Kind     string
	FromTag  string
	ToTag    string
	Decision string
}

// CRDProject is one project of the custom-resource version table.
type CRDProject struct {
	Catalog string
	Groups  int
}

// Snapshot is what is read from one tree.
type Snapshot struct {
	Counts     map[string]int
	Projects   map[string]string // inventory projectID -> display name
	Executable map[string]bool   // projects with at least one executable check
	Rules      map[projectKey]map[string]bool
	Withdrawn  map[string]bool
	Lines      map[string]map[string]bool // component -> attested lines
	Onboarding map[string][]OnboardedProject
	Decisions  map[string]string // batchId -> decision
	Depth      *Depth
	CRD        map[string]CRDProject // custom-resource table, slug -> entry
	HasCRD     bool                  // the tree has the table file
	Missing    []string              // data files this tree does not have
}

func readOptional(t Tree, name string, s *Snapshot) ([]byte, error) {
	b, err := t.Read(name)
	if errors.Is(err, fs.ErrNotExist) {
		s.Missing = append(s.Missing, name)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxFile)
	}
	return b, nil
}

type ruleFile struct {
	Entries []struct {
		Project string `json:"project"`
		Rule    struct {
			ID string `json:"id"`
		} `json:"rule"`
	} `json:"entries"`
	LineAttestations []struct {
		Component string `json:"component"`
		Line      string `json:"line"`
	} `json:"lineAttestations"`
}

type inventoryFile struct {
	Counts   map[string]int `json:"counts"`
	Projects []struct {
		ProjectID    string `json:"projectID"`
		DisplayName  string `json:"displayName"`
		SupportState string `json:"supportState"`
	} `json:"projects"`
	WithdrawnRules []struct {
		RuleID string `json:"ruleID"`
	} `json:"withdrawnRules"`
}

type crdTableFile struct {
	Projects []struct {
		Slug    string            `json:"slug"`
		Catalog string            `json:"catalog"`
		Groups  []json.RawMessage `json:"groups"`
	} `json:"projects"`
}

type batchFile struct {
	Record struct {
		BatchID  string `json:"batchId"`
		Decision string `json:"decision"`
		Projects []struct {
			Slug    string `json:"slug"`
			Catalog string `json:"catalog"`
			Kind    string `json:"kind"`
			Proof   struct {
				Pair struct {
					FromTag string `json:"fromTag"`
					ToTag   string `json:"toTag"`
				} `json:"pair"`
			} `json:"proof"`
		} `json:"projects"`
	} `json:"record"`
}

// ReadSnapshot reads one tree. A data file the tree does not have (an older
// tag) is recorded in Missing and counts as empty.
func ReadSnapshot(t Tree) (*Snapshot, error) {
	s := &Snapshot{
		Counts:     map[string]int{},
		Projects:   map[string]string{},
		Executable: map[string]bool{},
		Rules:      map[projectKey]map[string]bool{},
		Withdrawn:  map[string]bool{},
		Lines:      map[string]map[string]bool{},
		Onboarding: map[string][]OnboardedProject{},
		Decisions:  map[string]string{},
		CRD:        map[string]CRDProject{},
	}
	for _, rf := range []struct {
		path string
		cat  Catalogue
	}{{cncfRulesPath, CNCF}, {projectRulesPath, Community}} {
		raw, err := readOptional(t, rf.path, s)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			continue
		}
		var f ruleFile
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", rf.path, err)
		}
		for _, e := range f.Entries {
			if e.Project == "" || e.Rule.ID == "" {
				return nil, fmt.Errorf("%s: a rule has no project or id", rf.path)
			}
			k := projectKey{rf.cat, e.Project}
			if s.Rules[k] == nil {
				s.Rules[k] = map[string]bool{}
			}
			s.Rules[k][e.Rule.ID] = true
		}
		for _, a := range f.LineAttestations {
			if s.Lines[a.Component] == nil {
				s.Lines[a.Component] = map[string]bool{}
			}
			s.Lines[a.Component][a.Line] = true
		}
	}
	raw, err := readOptional(t, inventoryPath, s)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		var inv inventoryFile
		if err := json.Unmarshal(raw, &inv); err != nil {
			return nil, fmt.Errorf("%s: %w", inventoryPath, err)
		}
		s.Counts = inv.Counts
		if s.Counts == nil {
			s.Counts = map[string]int{}
		}
		for _, p := range inv.Projects {
			s.Projects[p.ProjectID] = p.DisplayName
			if strings.HasPrefix(p.SupportState, "executable") {
				s.Executable[p.ProjectID] = true
			}
		}
		for _, w := range inv.WithdrawnRules {
			s.Withdrawn[w.RuleID] = true
		}
	}
	names, err := t.List(onboardingDir)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := t.Read(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		var b batchFile
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if b.Record.BatchID == "" {
			return nil, fmt.Errorf("%s: no batchId", name)
		}
		s.Decisions[b.Record.BatchID] = b.Record.Decision
		for _, p := range b.Record.Projects {
			s.Onboarding[b.Record.BatchID] = append(s.Onboarding[b.Record.BatchID], OnboardedProject{
				Batch: b.Record.BatchID, Slug: p.Slug, Catalog: p.Catalog, Kind: p.Kind,
				FromTag: p.Proof.Pair.FromTag, ToTag: p.Proof.Pair.ToTag, Decision: b.Record.Decision,
			})
		}
		if len(b.Record.Projects) == 0 {
			s.Onboarding[b.Record.BatchID] = nil
		}
	}
	// The table file is absent from older tags; report.go says so once, so it
	// is not recorded in Missing.
	if raw, err := t.Read(crdTablePath); err == nil {
		if len(raw) > maxFile {
			return nil, fmt.Errorf("%s: larger than %d bytes", crdTablePath, maxFile)
		}
		var tf crdTableFile
		if err := json.Unmarshal(raw, &tf); err != nil {
			return nil, fmt.Errorf("%s: %w", crdTablePath, err)
		}
		s.HasCRD = true
		for _, p := range tf.Projects {
			s.CRD[p.Slug] = CRDProject{Catalog: p.Catalog, Groups: len(p.Groups)}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", crdTablePath, err)
	}
	readme, err := readOptional(t, readmePath, s)
	if err != nil {
		return nil, err
	}
	s.Depth = parseDepth(string(readme))
	return s, nil
}

var (
	depthDate     = regexp.MustCompile(`(?m)^Generated on (\d{4}-\d{2}-\d{2}) by `)
	depthProjects = regexp.MustCompile(`of the (\d+) projects with a release-line snapshot \((\d+) upgrades`)
	depthDecided  = regexp.MustCompile(`(?m)^\| Decided for the whole release-line pair[^|]*\| (\d+) \|`)
	depthExact    = regexp.MustCompile(`(?m)^\| Rule for one exact version pair only[^|]*\| (\d+) \|`)
	depthGap      = regexp.MustCompile(`(?m)^\| Gap, no valid rule[^|]*\| (\d+) \|`)
)

// parseDepth reads the README coverage block. It returns nil unless every
// figure is present, so a reworded block shows as unavailable, never as zero.
func parseDepth(readme string) *Depth {
	const begin, end = "<!-- coverage:begin -->", "<!-- coverage:end -->"
	i, j := strings.Index(readme, begin), strings.Index(readme, end)
	if i < 0 || j < i {
		return nil
	}
	block := readme[i:j]
	date, pr := depthDate.FindStringSubmatch(block), depthProjects.FindStringSubmatch(block)
	dec, ex, gap := depthDecided.FindStringSubmatch(block), depthExact.FindStringSubmatch(block), depthGap.FindStringSubmatch(block)
	if date == nil || pr == nil || dec == nil || ex == nil || gap == nil {
		return nil
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	return &Depth{GeneratedOn: date[1], Projects: n(pr[1]), Pairs: n(pr[2]), Decided: n(dec[1]), Exact: n(ex[1]), Gap: n(gap[1])}
}
