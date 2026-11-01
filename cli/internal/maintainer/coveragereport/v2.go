// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Metric v2 (Decided Pair Coverage). A pair of the last three release lines
// of a tiered project is split into cells, one per fact family that applies
// to the project. Only an attested cell is decided. DPC-reachable counts an
// attested cell only when the shipped client can produce the fact it tests;
// a cell that is declared but not reachable is never coverage.

// Schemas of the v2 data files.
const (
	TiersSchema         = "prufyx.io/coverage-tiers/v1"
	ApplicabilitySchema = "prufyx.io/coverage-family-applicability/v1"
)

// Cell states.
const (
	CellAttested = "attested" // pair is A and the family decides it: counted
	CellBounded  = "bounded"  // pair is B and the family decides it: shown, not counted
	CellOpen     = "open"     // anything else: not counted
)

// Producers of a fact in the shipped client.
const (
	ProducerManifest = "manifest"
	ProducerNone     = "none"
)

// V2Families are the fact families of the metric, in print order.
var V2Families = []string{"crd.versions", "crd.schema", "helm.values", "cli.flags", "config.keys", "k8s.api", "k8s.min"}

// v2Source maps a v2 family to the v1 family whose attestations or rules
// decide it. A v2 family without an entry has no measurement source in the
// code today: its cells are open.
var v2Source = map[string]string{
	"crd.versions": lineattest.FamilyCustomResourceVersions,
	"k8s.api":      lineattest.FamilyKubernetesRemovedServedGVK,
}

// producerFor says how the shipped client produces the fact of a family for
// a project. FactDefinition carries no producer field (a registry change
// that needs its own release), so the answer is derived from the scan routes that read
// the facts: the custom-resource version set of a CNCF catalog row is read
// from manifests by scan; the Kubernetes removed-GVK facts likewise. Any
// other family has no producer here.
func producerFor(family, project string) string {
	switch family {
	case "crd.versions":
		if p, ok := customresources.ProjectFor(project); ok && !p.Community() {
			return ProducerManifest
		}
	case "k8s.api":
		if project == "kubernetes" {
			return ProducerManifest
		}
	}
	return ProducerNone
}

//go:embed data/tiers.json
var embeddedTiers []byte

//go:embed data/family-applicability.json
var embeddedApplicability []byte

// Tier is one tier's project list.
type Tier struct {
	Tier     int      `json:"tier"`
	Projects []string `json:"projects"`
}

// TiersFile is the reviewed tier list.
type TiersFile struct {
	Schema string `json:"schema"`
	// Verified says whether the list was checked against its source; the
	// README states it when false.
	Verified bool   `json:"verified"`
	Source   string `json:"source"`
	Tiers    []Tier `json:"tiers"`
}

// Exemption declares a family inapplicable for a project.
type Exemption struct {
	Project string `json:"project"`
	Family  string `json:"family"`
	Reason  string `json:"reason"`
	Basis   string `json:"basis"`
}

// ApplicabilityFile lists the reviewed exemptions; every family applies to
// every project otherwise.
type ApplicabilityFile struct {
	Schema     string      `json:"schema"`
	Exemptions []Exemption `json:"exemptions"`
}

func strictDecode(raw []byte, v any, what string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, what, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: %s: trailing data", ErrInvalid, what)
	}
	return nil
}

var v2Slug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// ParseTiers strictly decodes the tier list: tiers 1 and 2 once each, sorted
// unique slugs, no project in two tiers.
func ParseTiers(raw []byte) (TiersFile, error) {
	var f TiersFile
	if err := strictDecode(raw, &f, "tiers"); err != nil {
		return f, err
	}
	if f.Schema != TiersSchema || f.Source == "" || len(f.Tiers) != 2 {
		return f, fmt.Errorf("%w: tiers: schema, source and tiers 1 and 2 are required", ErrInvalid)
	}
	seen := map[string]bool{}
	for i, t := range f.Tiers {
		if t.Tier != i+1 || t.Projects == nil {
			return f, fmt.Errorf("%w: tiers: entries must be tier 1 then tier 2, with a project array", ErrInvalid)
		}
		for j, p := range t.Projects {
			if !v2Slug.MatchString(p) || seen[p] || (j > 0 && t.Projects[j-1] >= p) {
				return f, fmt.Errorf("%w: tiers: tier %d: %q is not a sorted unique slug", ErrInvalid, t.Tier, p)
			}
			seen[p] = true
		}
	}
	return f, nil
}

// ParseApplicability strictly decodes the exemption file.
func ParseApplicability(raw []byte) (ApplicabilityFile, error) {
	var f ApplicabilityFile
	if err := strictDecode(raw, &f, "applicability"); err != nil {
		return f, err
	}
	if f.Schema != ApplicabilitySchema || f.Exemptions == nil {
		return f, fmt.Errorf("%w: applicability: schema and exemptions are required", ErrInvalid)
	}
	known := map[string]bool{}
	for _, id := range V2Families {
		known[id] = true
	}
	seen := map[[2]string]bool{}
	for i, e := range f.Exemptions {
		k := [2]string{e.Project, e.Family}
		if !v2Slug.MatchString(e.Project) || !known[e.Family] || e.Reason == "" || e.Basis == "" || seen[k] {
			return f, fmt.Errorf("%w: applicability: exemption %d needs a project, a known family, a reason, a basis and no duplicate", ErrInvalid, i)
		}
		if i > 0 && (f.Exemptions[i-1].Project > e.Project || (f.Exemptions[i-1].Project == e.Project && f.Exemptions[i-1].Family >= e.Family)) {
			return f, fmt.Errorf("%w: applicability: exemptions must be sorted by project and family", ErrInvalid)
		}
		seen[k] = true
	}
	return f, nil
}

// V2FamilyRow counts the cells of one family.
type V2FamilyRow struct {
	Family    string `json:"family"`
	Producer  string `json:"producer"`
	Cells     int    `json:"cells"`
	Attested  int    `json:"attested"`
	Bounded   int    `json:"bounded"`
	Reachable int    `json:"reachable"`
}

// V2 is the metric v2 section of a report.
type V2 struct {
	TiersVerified bool     `json:"tiersVerified"`
	Tier1         int      `json:"tier1Projects"`
	Tier2         int      `json:"tier2Projects"`
	NoLines       []string `json:"projectsWithoutLines"`
	// Excluded lists tiered community-catalog projects left out on purpose.
	Excluded []string `json:"projectsExcluded"`
	Pairs    int      `json:"pairs"`
	Cells    int      `json:"cells"`
	Attested int      `json:"attested"`
	Bounded  int      `json:"bounded"`
	Open     int      `json:"open"`
	// Reachable counts attested cells whose family has a producer for the
	// project in the shipped client.
	Reachable int `json:"reachable"`
	// DeclaredOnly counts attested cells without a producer.
	DeclaredOnly int `json:"declaredOnly"`
	// FullPairs counts pairs whose every cell is attested.
	FullPairs int `json:"pairsFullyAttested"`
	Exempt    int `json:"exemptCells"`
	// DPCDeclared and DPCReachable are weighted shares in [0,1], computed in
	// exact integers (see cellScale) and rounded to four places.
	DPCDeclared  float64       `json:"dpcDeclared"`
	DPCReachable float64       `json:"dpcReachable"`
	Families     []V2FamilyRow `json:"families"`
	// num/den are the exact integers behind the shares, for the README.
	declNum, reachNum, den int64
}

// cellScale is lcm(1..7): the fraction a/n of a pair (n applicable cells,
// n <= 7) is a*cellScale/n exactly, so no floating point enters the sums.
const cellScale = 420

func recencyWeight(fromEnd int) int64 { // 0 = newest pair
	if fromEnd == 0 {
		return 2
	}
	return 1
}

// applyV2 fills Pair.Cells and Pair.Weight for the tiered projects' last
// two pairs and sets report.V2. It changes nothing else.
func applyV2(r *Report, tiers TiersFile, app ApplicabilityFile) {
	exempt := map[[2]string]bool{}
	for _, e := range app.Exemptions {
		exempt[[2]string{e.Project, e.Family}] = true
	}
	tierOf := map[string]int{}
	for _, t := range tiers.Tiers {
		for _, p := range t.Projects {
			tierOf[p] = t.Tier
		}
	}
	v := &V2{TiersVerified: tiers.Verified, NoLines: []string{}, Excluded: []string{}}
	rows := map[string]*V2FamilyRow{}
	for _, f := range V2Families {
		rows[f] = &V2FamilyRow{Family: f, Producer: ProducerNone}
	}
	have := map[string]bool{}
	for i := range r.Projects {
		p := &r.Projects[i]
		tier, ok := tierOf[p.Project]
		if !ok {
			continue
		}
		if p.Catalog == CatalogCommunity {
			have[p.Project] = true
			v.Excluded = append(v.Excluded, p.Project)
			continue
		}
		have[p.Project] = true
		if tier == 1 {
			v.Tier1++
		} else {
			v.Tier2++
		}
		var fams []string
		for _, f := range V2Families {
			if exempt[[2]string{p.Project, f}] {
				v.Exempt += min(2, len(p.Pairs))
				continue
			}
			fams = append(fams, f)
			if producerFor(f, p.Project) != ProducerNone {
				rows[f].Producer = ProducerManifest // over the universe, not only attested cells
			}
		}
		first := max(0, len(p.Pairs)-2)
		for j := first; j < len(p.Pairs); j++ {
			pair := &p.Pairs[j]
			tw := int64(1)
			if tier == 1 {
				tw = 3
			}
			w := tw * recencyWeight(len(p.Pairs)-1-j)
			pair.Weight = float64(w) / 2
			pair.Cells = map[string]string{}
			var att, reach int
			for _, f := range fams {
				state := CellOpen
				if src, ok := v2Source[f]; ok && (pair.Status == StatusA || pair.Status == StatusB) {
					for _, pf := range pair.Families {
						if pf == src {
							state = map[string]string{StatusA: CellAttested, StatusB: CellBounded}[pair.Status]
						}
					}
				}
				pair.Cells[f] = state
				row := rows[f]
				row.Cells++
				v.Cells++
				switch state {
				case CellAttested:
					row.Attested++
					v.Attested++
					att++
					if producerFor(f, p.Project) != ProducerNone {
						row.Reachable++
						v.Reachable++
						reach++
					} else {
						v.DeclaredOnly++
					}
				case CellBounded:
					row.Bounded++
					v.Bounded++
				default:
					v.Open++
				}
			}
			v.Pairs++
			if n := int64(len(fams)); n > 0 {
				v.den += w * cellScale
				v.declNum += w * int64(att) * (cellScale / n)
				v.reachNum += w * int64(reach) * (cellScale / n)
				if int64(att) == n {
					v.FullPairs++
				}
			}
		}
	}
	for _, t := range tiers.Tiers {
		for _, p := range t.Projects {
			if !have[p] {
				v.NoLines = append(v.NoLines, p)
			}
		}
	}
	sort.Strings(v.NoLines)
	if v.den > 0 {
		v.DPCDeclared = math.Round(float64(v.declNum)/float64(v.den)*10000) / 10000
		v.DPCReachable = math.Round(float64(v.reachNum)/float64(v.den)*10000) / 10000
	}
	for _, f := range V2Families {
		v.Families = append(v.Families, *rows[f])
	}
	r.V2 = v
}

// v2Pct prints num/den floored to one decimal, from exact integers.
func v2Pct(num, den int64) string {
	if den == 0 {
		return "0%"
	}
	return fmt.Sprintf("%g%%", float64(num*1000/den)/10)
}

// checkExemptions refuses an exemption whose project is in no tier: it would
// look reviewed and do nothing.
func checkExemptions(tiers TiersFile, app ApplicabilityFile) error {
	in := map[string]bool{}
	for _, t := range tiers.Tiers {
		for _, p := range t.Projects {
			in[p] = true
		}
	}
	for _, e := range app.Exemptions {
		if !in[e.Project] {
			return fmt.Errorf("%w: applicability: %s is in no tier", ErrInvalid, e.Project)
		}
	}
	return nil
}
