// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing/fstest"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/maintainer/docstables"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// OnboardingLayout names the files an onboarding batch may change. An empty
// Dir disables onboarding batches.
type OnboardingLayout struct {
	// Dir holds the onboarding batches as <batch id>.json.
	Dir string
	// Pack is the pack whose registryDigest moves with the table.
	Pack string
	// TargetsDir holds the CRD version targets, target-<slug>.json.
	TargetsDir string
	// TablePath is the reviewed custom-resource table.
	TablePath string
	// DocsDir is the directory of the generated documentation tables
	// (package docstables) the targets and the table are rendered to.
	DocsDir string
	// LandscapePath and PriorityPath are the CNCF catalog files the pack is
	// admitted with.
	LandscapePath, PriorityPath string
}

func defaultOnboardingLayout() OnboardingLayout {
	return OnboardingLayout{
		Dir:           "cli/knowledge/onboarding",
		Pack:          "cncf",
		TargetsDir:    "cli/internal/extract/crdversions",
		TablePath:     "cli/internal/customresources/table.json",
		DocsDir:       "cli",
		LandscapePath: "cli/internal/cncfcheck/data/landscape-projects.json",
		PriorityPath:  "cli/internal/cncfcheck/data/priority-portfolio.json",
	}
}

const maxTargetFiles = 4096

// treeTargets reads the target files (target-*.json) directly inside dir,
// by name. Nothing else in the directory is opened.
func treeTargets(t Tree, dir string) (map[string][]byte, error) {
	d, err := t.openDir(dir)
	if errors.Is(err, ErrMissing) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(maxTargetFiles + 1)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maxTargetFiles {
		return nil, fmt.Errorf("%s holds more than %d entries", dir, maxTargetFiles)
	}
	out := map[string][]byte{}
	for _, name := range names {
		if ok, _ := path.Match("target-*.json", name); !ok {
			continue
		}
		raw, err := t.Read(dir+"/"+name, MaxFileBytes)
		if err != nil {
			return nil, err
		}
		out[name] = raw
	}
	return out, nil
}

// onboardingSide is what the gate reads from one tree.
type onboardingSide struct {
	targets  map[string][]byte
	loaded   []crdversions.Target
	table    []byte
	projects []customresources.Project
	reserved []customresources.ReservedGroup
	state    OnboardingState
	// members are the pack's revision and registryDigest members (the
	// revision is read to require that it does not change).
	revision, registryDigest string
}

// onboardingState is what an onboarding batch is checked against, computed
// from the base and head trees and their classification only.
type onboardingState struct {
	layout          Layout
	base, head      onboardingSide
	cls             *Classification
	changedPaths    []string
	baseTree        Tree
	headTree        Tree
	changeSetDigest string
	// landscape maps a CNCF slug to its repository URL.
	landscape map[string]string
}

func targetsDigest(targets map[string][]byte) (string, error) {
	type item struct {
		Digest string `json:"digest"`
		Name   string `json:"name"`
	}
	list := make([]item, 0, len(targets))
	for name, raw := range targets {
		list = append(list, item{Digest: CandidateDigest(raw), Name: name})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return domainDigest(onboardingTargetsDomain, list)
}

// readOnboardingSide reads one tree with the base's loaders: every target
// file (strict JSON, then crdversions.LoadTargets), the table (strict JSON,
// then customresources.LoadTable), the registry the base's code compiles
// from the table, and the pack members.
func readOnboardingSide(ol OnboardingLayout, t Tree, p *loadedPack) (onboardingSide, error) {
	var s onboardingSide
	var err error
	if s.targets, err = treeTargets(t, ol.TargetsDir); err != nil {
		return s, err
	}
	fsys := fstest.MapFS{}
	for name, raw := range s.targets {
		if err := strictjson.Check(raw); err != nil {
			return s, fmt.Errorf("%s: %v", logSafe(name), err)
		}
		fsys[name] = &fstest.MapFile{Data: raw}
	}
	if s.loaded, err = crdversions.LoadTargets(fsys); err != nil {
		return s, fmt.Errorf("the CRD version targets do not load: %v", logSafe(err.Error()))
	}
	if s.table, err = t.Read(ol.TablePath, MaxFileBytes); err != nil {
		return s, err
	}
	if err := strictjson.Check(s.table); err != nil {
		return s, fmt.Errorf("%s: %v", ol.TablePath, err)
	}
	if s.projects, s.reserved, err = customresources.LoadTable(s.table); err != nil {
		return s, fmt.Errorf("the custom-resource table does not load: %v", logSafe(err.Error()))
	}
	if canonical, err := customresources.CanonicalTable(s.projects, s.reserved); err != nil || !bytes.Equal(canonical, s.table) {
		return s, fmt.Errorf("%s is not in its canonical spelling", ol.TablePath)
	}
	if s.state.RegistryDigest, err = cncfcheck.TableRegistryDigest(s.table); err != nil {
		return s, fmt.Errorf("the registry does not compile from the custom-resource table: %v", err)
	}
	s.state.TableDigest = CandidateDigest(s.table)
	if s.state.TargetsDigest, err = targetsDigest(s.targets); err != nil {
		return s, err
	}
	if p == nil || !p.Present {
		return s, errors.New("the pack file is missing")
	}
	for _, m := range []struct {
		name string
		dst  *string
	}{{"revision", &s.revision}, {"registryDigest", &s.registryDigest}} {
		raw, ok := p.Members[m.name]
		if !ok || json.Unmarshal(raw, m.dst) != nil {
			return s, fmt.Errorf("the pack has no string member %s", m.name)
		}
	}
	s.state.PackRevision = s.revision
	return s, nil
}

// onboardingChangeSet is the change as the change-set digest binds it: the
// gate's classification and every changed path.
type onboardingChangeSet struct {
	Changes       []changeSetItem `json:"changes"`
	ChainsChanged []string        `json:"chainsChanged"`
	Paths         []string        `json:"paths"`
	Paused        bool            `json:"paused"`
}

// newOnboardingState reads both trees. An error means the change cannot be
// read as an onboarding change at all.
func newOnboardingState(layout Layout, base, head Tree, cls *Classification, changedPaths []string) (*onboardingState, error) {
	ol := layout.Onboarding
	st := &onboardingState{layout: layout, cls: cls, changedPaths: changedPaths, baseTree: base, headTree: head, landscape: map[string]string{}}
	var err error
	if st.base, err = readOnboardingSide(ol, base, cls.base[ol.Pack]); err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	if st.head, err = readOnboardingSide(ol, head, cls.head[ol.Pack]); err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	raw, err := base.Read(ol.LandscapePath, MaxFileBytes)
	if err != nil {
		return nil, err
	}
	var landscape struct {
		Projects []struct {
			Slug          string `json:"slug"`
			RepositoryURL string `json:"repositoryURL"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &landscape); err != nil {
		return nil, fmt.Errorf("the landscape does not decode: %v", err)
	}
	for _, p := range landscape.Projects {
		st.landscape[p.Slug] = p.RepositoryURL
	}
	set := onboardingChangeSet{Changes: []changeSetItem{}, ChainsChanged: append([]string{}, cls.ChainsChanged...), Paths: []string{}, Paused: cls.Paused}
	for _, c := range cls.Changes {
		b, h := c.canonicalSides()
		set.Changes = append(set.Changes, changeSetItem{Pack: c.Pack, Section: c.Section, Member: c.Member, ID: c.RuleID, Class: c.Class, Kinds: c.Kinds, Basis: c.Basis, Project: c.Project, Base: canonicalDigest(b), Head: canonicalDigest(h)})
	}
	for _, p := range changedPaths {
		// The batch file itself is not part of what it signs.
		if !strings.HasPrefix(p, ol.Dir+"/") {
			set.Paths = append(set.Paths, p)
		}
	}
	if st.changeSetDigest, err = domainDigest(onboardingChangeDomain, set); err != nil {
		return nil, err
	}
	return st, nil
}

// docs are the generated documentation tables an onboarding change moves,
// by repository path, as the base's code renders them from the head.
func (st *onboardingState) docs() map[string]string {
	dir := st.layout.Onboarding.DocsDir
	if dir == "" {
		return nil
	}
	return map[string]string{
		dir + "/" + docstables.CRDTargetsPath:      docstables.CRDTargets(st.head.loaded),
		dir + "/" + docstables.CustomResourcesPath: docstables.CustomResources(st.head.projects, st.head.reserved),
	}
}

func targetPath(ol OnboardingLayout, slug string) string {
	return ol.TargetsDir + "/" + crdversions.TargetFileName(slug)
}

// allowedPaths are the only paths an onboarding change may touch.
func (st *onboardingState) allowedPaths(rec OnboardingRecord, batchPath string) map[string]bool {
	ol := st.layout.Onboarding
	allowed := map[string]bool{batchPath: true, ol.TablePath: true}
	for _, spec := range st.layout.Packs {
		if spec.Name == ol.Pack {
			allowed[spec.Path], allowed[spec.AttestationPath] = true, true
		}
	}
	for _, g := range st.layout.Generated {
		allowed[g.JSONPath], allowed[g.MarkdownPath] = true, true
	}
	for _, p := range rec.Projects {
		allowed[targetPath(ol, p.Slug)] = true
	}
	for rel := range st.docs() {
		allowed[rel] = true
	}
	for rel := range st.layout.admittedBlocks(st.baseTree, st.headTree) {
		allowed[rel] = true
	}
	return allowed
}

// groupListing is one project's listing of an API group in the head table.
type groupListing struct {
	slug  string
	kinds []string
}

// newRowGroups are the groups, by name, that a new project of the batch lists
// with kinds in the head table: the groups the batch may share.
func newRowGroups(rec OnboardingRecord, headRows map[string]customresources.Project) map[string]bool {
	out := map[string]bool{}
	for _, p := range rec.Projects {
		row, ok := headRows[p.Slug]
		if p.Kind != OnboardingKindNew || !ok {
			continue
		}
		for _, g := range row.Groups {
			if len(g.Kinds) > 0 {
				out[g.Name] = true
			}
		}
	}
	return out
}

// kindsChange is one listing an amendment gives kinds.
type kindsChange struct {
	Slug, Group string
	Kinds       []string
}

// kindsAmendment reports whether the head row of an existing project is its
// base row with kinds added to whole listings of groups the batch shares
// (the groups of sharing), and nothing else. The kinds only narrow what the
// listing attributes: an object of a kind no project lists is attributed to
// none and keeps every set incomplete.
func kindsAmendment(base, head customresources.Project, sharing map[string]bool) ([]kindsChange, bool) {
	if len(base.Groups) != len(head.Groups) {
		return nil, false
	}
	rest := head
	rest.Groups = make([]customresources.Group, len(head.Groups))
	var changes []kindsChange
	for i, g := range head.Groups {
		rest.Groups[i] = g
		b := base.Groups[i]
		if !reflect.DeepEqual(b.Kinds, g.Kinds) {
			if b.Kinds != nil || len(g.Kinds) == 0 || !sharing[g.Name] {
				return nil, false
			}
			changes = append(changes, kindsChange{Slug: head.Slug, Group: g.Name, Kinds: g.Kinds})
		}
		rest.Groups[i].Kinds = b.Kinds
	}
	return changes, len(changes) > 0 && reflect.DeepEqual(base, rest)
}

// amendments are the kinds the batch adds to existing rows, ordered by slug
// and group. check refuses every other change of an existing row.
func (st *onboardingState) amendments(rec OnboardingRecord) []kindsChange {
	baseRows, headRows := projectsBySlug(st.base.projects), projectsBySlug(st.head.projects)
	sharing := newRowGroups(rec, headRows)
	var out []kindsChange
	for _, p := range st.head.projects {
		b, ok := baseRows[p.Slug]
		if !ok || reflect.DeepEqual(b, p) {
			continue
		}
		if changes, ok := kindsAmendment(b, p, sharing); ok {
			out = append(out, changes...)
		}
	}
	return out
}

func projectsBySlug(list []customresources.Project) map[string]customresources.Project {
	out := map[string]customresources.Project{}
	for _, p := range list {
		out[p.Slug] = p
	}
	return out
}

// check runs O2 to O5 for rec: what the change touches, what the batch
// says about the two states, what the base's loaders read from the head and
// what the base's code registers. It returns every problem found.
func (st *onboardingState) check(rec OnboardingRecord, batchPath string) []string {
	ol := st.layout.Onboarding
	var problems []string
	bad := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	// O2: the path allow-list over the whole change.
	allowed := st.allowedPaths(rec, batchPath)
	var outside []string
	for _, p := range st.changedPaths {
		if !allowed[p] {
			outside = append(outside, logSafe(p))
		}
	}
	if len(outside) > 0 {
		bad("O2: an onboarding change may change only the batch file, the listed projects' target files, the custom-resource table, the %s pack file, its corpus attestation, the generated support inventory and the regenerated README coverage block; it also changes %d other files%s", ol.Pack, len(outside), listDetail(outside))
	}
	// O2: the classification holds, with a new project, the pack's
	// registryDigest; nothing else. The pack's revision never changes: it is
	// a release step, not part of a data change.
	newProjects := 0
	for _, p := range rec.Projects {
		if p.Kind == OnboardingKindNew {
			newProjects++
		}
	}
	wantMembers := map[string]bool{}
	if newProjects > 0 {
		wantMembers["registryDigest"] = true
	}
	seenMembers := map[string]bool{}
	for _, c := range st.cls.Changes {
		if c.Pack == ol.Pack && c.Member != "" && wantMembers[c.Member] && !seenMembers[c.Member] {
			seenMembers[c.Member] = true
			continue
		}
		what := "rule " + logSafe(c.RuleID)
		switch {
		case c.Member != "":
			what = "member " + logSafe(c.Member)
		case c.Section != "":
			what = c.Section + " record " + logSafe(c.RuleID)
		}
		bad("O2: an onboarding change may not change %s of the %s pack", what, c.Pack)
	}
	for m := range wantMembers {
		if !seenMembers[m] {
			bad("O2: the %s pack member %s does not change", ol.Pack, m)
		}
	}
	if len(st.cls.ChainsChanged) > 0 {
		bad("O2: an onboarding change may not change a reattestation statement chain")
	}

	// O2: the generated documentation tables are the base's rendering of
	// the head's targets and table.
	for rel, want := range st.docs() {
		have, err := st.headTree.ReadOptional(rel, MaxFileBytes)
		if err != nil || string(have) != want {
			bad("O2: %s differs from its regeneration from the head's targets and table", rel)
		}
	}

	// O3: the two states.
	if rec.Base != st.base.state {
		bad("O3: the base state differs from the one the batch was signed for")
	}
	if rec.Head != st.head.state {
		bad("O3: the head state differs from the one the batch was signed for")
	}
	if st.base.state.RegistryDigest != st.base.registryDigest {
		bad("O3: the base pack's registryDigest is not the registry the base's code compiles from the base table")
	}
	if st.head.state.RegistryDigest != st.head.registryDigest {
		bad("O3: the head pack's registryDigest is not the registry the base's code compiles from the head table")
	}
	if st.head.revision != st.base.revision || rec.Head.PackRevision != rec.Base.PackRevision {
		bad("O3: the pack revision may not change in an onboarding change; it moves in a release step of its own")
	}

	// O4 and O5, per project.
	baseRows, headRows := projectsBySlug(st.base.projects), projectsBySlug(st.head.projects)
	listed := map[string]OnboardingProject{}
	for _, p := range rec.Projects {
		listed[p.Slug] = p
	}
	if !reflect.DeepEqual(st.base.reserved, st.head.reserved) {
		bad("O4: the reserved groups of the custom-resource table changed; a reserved group is recorded on its own, never in an onboarding batch")
	}
	sharing := newRowGroups(rec, headRows)
	for slug, b := range baseRows {
		h, ok := headRows[slug]
		switch {
		case !ok:
			bad("O2: the table row of %s is removed", logSafe(slug))
		case !reflect.DeepEqual(b, h):
			if _, ok := kindsAmendment(b, h, sharing); !ok {
				bad("O2: the table row of %s changes; an onboarding batch only adds rows, and amends a row only by adding kinds to a whole listing of a group a new project of the batch shares", logSafe(slug))
			}
		}
	}
	for slug := range headRows {
		if _, inBase := baseRows[slug]; !inBase {
			if p, ok := listed[slug]; !ok || p.Kind != OnboardingKindNew {
				bad("O2: the table adds a row for %s, which the batch does not list as a new project", logSafe(slug))
			}
		}
	}
	for name := range st.base.targets {
		if _, ok := st.head.targets[name]; !ok {
			bad("O2: the target file %s is removed", logSafe(name))
		}
	}
	for name, raw := range st.head.targets {
		slug := strings.TrimSuffix(strings.TrimPrefix(name, "target-"), ".json")
		if b, ok := st.base.targets[name]; ok && bytes.Equal(b, raw) {
			continue
		}
		if _, ok := listed[slug]; !ok {
			bad("O2: the target file %s changes for a project the batch does not list", logSafe(name))
		}
	}
	factOwners := map[string][]string{}
	for _, p := range st.head.projects {
		factOwners[p.FactProject] = append(factOwners[p.FactProject], p.Slug)
	}
	for fp, owners := range factOwners {
		if len(owners) > 1 {
			bad("O4: the fact project %s is used by %s", logSafe(fp), logSafe(strings.Join(owners, ", ")))
		}
	}
	groupOwners := map[string][]groupListing{}
	for _, p := range st.head.projects {
		for _, g := range p.Groups {
			groupOwners[g.Name] = append(groupOwners[g.Name], groupListing{slug: p.Slug, kinds: g.Kinds})
		}
	}
	baseDefs := map[string]constraintengine.FactDefinition{}
	for _, d := range cncfcheck.TableDefinitions(st.base.projects) {
		baseDefs[d.ID] = d
	}
	headDefs := map[string]constraintengine.FactDefinition{}
	for _, d := range cncfcheck.TableDefinitions(st.head.projects) {
		headDefs[d.ID] = d
	}
	added := map[string]constraintengine.FactDefinition{}
	for id, h := range headDefs {
		b, ok := baseDefs[id]
		switch {
		case !ok:
			added[id] = h
		case !reflect.DeepEqual(b, h):
			bad("O5: the fact %s is redefined", logSafe(id))
		}
	}
	for id := range baseDefs {
		if _, ok := headDefs[id]; !ok {
			bad("O5: the fact %s is no longer registered", logSafe(id))
		}
	}
	wantAdded := map[string]bool{}
	for _, p := range rec.Projects {
		problems = append(problems, st.checkProject(p, baseRows, headRows, groupOwners)...)
		if p.Kind == OnboardingKindNew {
			if row, ok := headRows[p.Slug]; ok {
				wantAdded[row.FactID()] = true
				if d, ok := added[row.FactID()]; !ok || d.Type != constraintengine.FactSet || d.Component != row.Component || len(d.EnumTokens) != 0 {
					bad("O5: %s: the registry does not gain exactly its custom-resource version set", logSafe(p.Slug))
				}
			}
		}
	}
	for id := range added {
		if !wantAdded[id] {
			bad("O5: the head registers the fact %s, which is not the custom-resource version set of a new project of the batch", logSafe(id))
		}
	}
	sort.Strings(problems)
	return problems
}

// checkProject runs O3 (artifacts) and O4 (what the base's loaders read)
// for one project.
func (st *onboardingState) checkProject(p OnboardingProject, baseRows, headRows map[string]customresources.Project, groupOwners map[string][]groupListing) []string {
	ol := st.layout.Onboarding
	var problems []string
	bad := func(format string, args ...any) {
		problems = append(problems, logSafe(p.Slug)+": "+fmt.Sprintf(format, args...))
	}
	name := crdversions.TargetFileName(p.Slug)
	headRaw, inHead := st.head.targets[name]
	baseRaw, inBase := st.base.targets[name]
	if !inHead {
		bad("O4: the head has no target file %s", name)
		return problems
	}
	if len(p.Artifacts) != 1 || p.Artifacts[0].Path != targetPath(ol, p.Slug) {
		bad("O3: the artifacts must be exactly the target file %s", targetPath(ol, p.Slug))
	} else if p.Artifacts[0].Digest != CandidateDigest(headRaw) {
		bad("O3: the target file differs from the one the batch was signed for")
	}
	head, err := crdversions.LoadTarget(name, headRaw)
	if err != nil {
		bad("O4: %v", logSafe(err.Error()))
		return problems
	}
	row, hasRow := headRows[p.Slug]
	if !hasRow {
		bad("O4: the custom-resource table has no row for the project")
		return problems
	}
	var groups []string
	for _, g := range row.Groups {
		groups = append(groups, g.Name)
	}
	if !reflect.DeepEqual(groups, p.Groups) {
		bad("O4: the groups differ from the table row's")
	}
	if len(p.Facts) != 1 || p.Facts[0] != row.FactID() {
		bad("O5: the facts must be exactly %s", row.FactID())
	}
	if head.Catalog != string(row.Catalog) {
		bad("O4: the target and the table row name different catalogs")
	}
	if p.Catalog != string(row.Catalog) {
		bad("O4: the batch names another catalog than the table row's")
	}
	// Defence in depth: targets.go and customresources.go already force the
	// target and the row to agree, so this is not expected to fire.
	if head.FactProject != row.FactProject || head.Component != row.Component {
		bad("O4: the target and the table row name different facts or components")
	}
	switch p.Kind {
	case OnboardingKindNew:
		if inBase {
			bad("O4: kind new, but the base already holds the target file")
		}
		if _, ok := baseRows[p.Slug]; ok {
			bad("O4: kind new, but the base table already holds the project")
		}
		_, inLandscape := st.landscape[p.Slug]
		switch row.Catalog {
		case customresources.CatalogCommunity:
			// A community project is outside the landscape: its identity is
			// the table row's upstream record, which the target must name.
			if inLandscape {
				bad("O4: a community catalog project may not be in the CNCF landscape catalog")
			}
			if row.Upstream.Repository == "" || "https://"+head.Repo != row.Upstream.Repository {
				bad("O4: the target repository %s is not the table row's upstream repository", logSafe(head.Repo))
			}
		default:
			if !inLandscape {
				bad("O4: the project is not in the CNCF landscape catalog")
			}
		}
		if head.Attest {
			bad("O4: a new target may not attest; attestation is turned on by a later batch for a project of the base")
		}
		if head.Remote != nil || len(head.Channels) > 0 || head.DeclaredChannel != "" {
			bad("O4: a remote source or install channels are reviewed per project, never in an onboarding batch")
		}
		if len(head.Exclude) > 0 {
			// An exclusion does nothing while the target does not attest and
			// everything once it does: it is reviewed per project, never
			// admitted blind by an onboarding batch.
			bad("O4: a new target may not exclude files from the full-tree scan (%d exclusions); exclusions are reviewed per project", len(head.Exclude))
		}
		if repo := st.landscape[p.Slug]; row.Catalog != customresources.CatalogCommunity && !sameLandscapeRepo(repo, head.Repo) {
			bad("O4: the target repository %s is not the landscape repository %s", logSafe(head.Repo), logSafe(repo))
		}
		for _, g := range row.Groups {
			// Defence in depth: the table does not load with such a group
			// unless a reviewed ownership record lists it.
			if customresources.ReservedNamespace(g.Name) || customresources.KubernetesGroup(g.Name) {
				bad("O4: the group %s is reserved; a reserved group is recorded on its own, never in an onboarding batch", logSafe(g.Name))
			}
			// A shared group is allowed when every listing of it, the new
			// row's own included, names kinds. The head table has loaded, so
			// the kind sets are disjoint (Validate).
			if owners := groupOwners[g.Name]; len(owners) != 1 {
				var slugs, whole []string
				for _, l := range owners {
					slugs = append(slugs, l.slug)
					if len(l.kinds) == 0 {
						whole = append(whole, l.slug)
					}
				}
				if len(whole) > 0 {
					bad("O4: the group %s is shared with %s, and the listing of %s names no kinds; a shared group is listed with disjoint kinds by every project", logSafe(g.Name), logSafe(strings.Join(slugs, ", ")), logSafe(strings.Join(whole, ", ")))
				}
			}
		}
	case OnboardingKindAttest:
		if !inBase {
			bad("O4: kind attest, but the base holds no target file for the project")
			return problems
		}
		base, err := crdversions.LoadTarget(name, baseRaw)
		if err != nil {
			bad("O4: the base target does not load: %v", logSafe(err.Error()))
			return problems
		}
		if len(head.Exclude) > 0 || head.Remote != nil || len(head.Channels) > 0 || head.DeclaredChannel != "" {
			bad("O4: a target with scan exclusions, a remote source or install channels is never turned on for attestation by a batch (%d exclusions)", len(head.Exclude))
		}
		if base.Attest || !head.Attest {
			bad("O4: kind attest turns attestation on: the base target must not attest and the head target must")
		}
		if why := onlyAttestChanged(baseRaw, headRaw); why != "" {
			bad("O4: %s", why)
		}
		if b, ok := baseRows[p.Slug]; !ok || !reflect.DeepEqual(b, row) {
			bad("O4: kind attest leaves the project's table row unchanged")
		}
		if p.Proof.Claims.Refuted != 0 {
			bad("O4: attestation is turned on only for a project with no refuted claim (as the proposal reports it; the gate's own evidence is the attested dry-run pair)")
		}
	}
	return problems
}

// onlyAttestChanged says why the head target is not the base target with
// attest turned on, or "" when it is: both decode to the same document once
// the head's attest member is set back to false.
func onlyAttestChanged(baseRaw, headRaw []byte) string {
	var b, h map[string]any
	if json.Unmarshal(baseRaw, &b) != nil || json.Unmarshal(headRaw, &h) != nil {
		return "the target files do not decode"
	}
	ht, ok := h["target"].(map[string]any)
	if !ok {
		return "the head target file has no target"
	}
	if v, ok := ht["attest"].(bool); !ok || !v {
		return "the head target does not attest"
	}
	ht["attest"] = false
	if bt, ok := b["target"].(map[string]any); ok {
		if _, has := bt["attest"]; !has {
			delete(ht, "attest")
		}
	}
	if !reflect.DeepEqual(b, h) {
		return "kind attest may change only the target's attest member"
	}
	return ""
}

// sameLandscapeRepo reports whether the landscape's repository URL names the
// target's repository. A target repository is always lowercase (the target
// loader and extract.ParseRepo lower it, as GitHub owner and repository names
// are case-insensitive), while the landscape keeps the spelling of the
// project. The comparison therefore folds ASCII case only: both sides must be
// ASCII, the scheme and host must match exactly, and nothing else is
// loosened (no trailing slash, no other host, no Unicode folding).
func sameLandscapeRepo(landscapeURL, targetRepo string) bool {
	want := "https://" + targetRepo
	if landscapeURL == "" || targetRepo == "" || !isASCII(landscapeURL) || !isASCII(want) {
		return false
	}
	// Both sides are ASCII here, so EqualFold is an ASCII case fold.
	return strings.EqualFold(landscapeURL, want)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
