// SPDX-License-Identifier: AGPL-3.0-only

// Package scanrun runs one scan: it reads the configuration and the inputs,
// plans each targeted component's upgrade, evaluates every hop with the
// unchanged engine against one knowledge snapshot, classifies the hops and
// assembles the report. It never uses the network.
//
// A hop is COVERED only when every rule that overlaps it covers it and is
// decided, and a current line review lists exactly the rules that decide it.
// Every hop that is not COVERED or BLOCKED is explained by a named gap, and
// any gap keeps the whole answer from PASS.
package scanrun

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/intake"
	knowledgestore "github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/knowledgeauto"
	"github.com/prufyx/prufyx/cli/internal/knowledgepin"
	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/validation"
)

// Options are the parts of a scan that do not come from the command line.
type Options struct {
	// Stdin is read for the path "-".
	Stdin io.Reader
	// Knowledge, when nil, is the embedded knowledge.
	Knowledge Knowledge
	// Clock gives the current time when the request has no --now.
	Clock func() time.Time
	// Build, when nil, is this binary's build identity.
	Build *buildidentity.Identity
	// AutoLocalDB lets a scan with no --knowledge-db and no --now use the
	// verified database of the default store location (see knowledgeauto).
	AutoLocalDB bool
	// PinnedRoot gives the pinned initial root digest of a knowledge
	// profile; nil means the product pin (knowledgepin.Digest).
	PinnedRoot func(profile string) string
	// OpenStore, CompareEmbedded and ExpiredRoot are test seams; nil means
	// OpenStore, cncfcheck.CompareWithEmbedded and
	// knowledge.ExpiredStoreRootDigest.
	OpenStore       func(path string, projects []string) (*Store, error)
	CompareEmbedded func(map[string]cncfcheck.ExternalBundle) (cncfcheck.EmbeddedComparison, error)
	ExpiredRoot     func(storeRoot string) (string, error)
}

// Result is a finished scan.
type Result struct {
	Report scanreport.Report
	Exit   int
	// KnowledgeAge is a one-line note for standard error, without the
	// "prufyx: " prefix: some of the knowledge used has expired or expires
	// within 30 days of the evaluation instant. It is empty otherwise and is
	// never part of the report.
	KnowledgeAge string
	// PinnedNowWarning is a one-line warning for standard error, without the
	// "prufyx: " prefix: --now is earlier than the real time and knowledge
	// rules have expired in between. The report then holds a gap, so it cannot
	// pass. Empty otherwise.
	PinnedNowWarning string
	// KnowledgeSource is a one-line note for standard error saying which
	// knowledge an automatic selection used; empty when the source was
	// explicit (--knowledge-db, --now, supplied knowledge) or not automatic.
	KnowledgeSource string
	// KnowledgeNote is the staleness note of an automatic database, for
	// standard error; it changes no verdict.
	KnowledgeNote string
}

// Run performs the scan. A *UsageError is input the scan does not accept
// (exit 2); ErrIntegrity is a knowledge or report integrity failure (exit 3).
func Run(request Request, options Options) (Result, error) {
	knowledge := options.Knowledge
	knowledgeSource, knowledgeNote := "", ""
	var selection *scanreport.KnowledgeSelection
	autoStore := false
	if knowledge == nil && options.AutoLocalDB && request.KnowledgeDB == "" && request.Now.IsZero() && request.KnowledgeMode != "embedded" {
		root, present, err := knowledgeauto.Locate()
		if err != nil {
			var refused *knowledgeauto.Refused
			if errors.As(err, &refused) {
				return Result{}, &StoreError{Reason: refused.Reason, Auto: true}
			}
			return Result{}, ErrIntegrity
		}
		if present {
			request.KnowledgeDB, autoStore = root, true
		} else {
			knowledgeSource = "knowledge source: embedded, no local knowledge database installed"
			selection = &scanreport.KnowledgeSelection{Chosen: knowledgeauto.SourceEmbedded, Reason: knowledgeauto.ReasonNoStore}
		}
	} else if knowledge == nil && options.AutoLocalDB && request.KnowledgeDB == "" && request.KnowledgeMode == "embedded" {
		knowledgeSource = "knowledge source: embedded, forced by --knowledge=embedded"
		selection = &scanreport.KnowledgeSelection{Chosen: knowledgeauto.SourceEmbedded, Reason: knowledgeauto.ReasonForced}
	}
	// The catalog checks component names. With --knowledge-db it is the
	// compiled catalog alone: the database is opened once the targets are
	// known, and nothing else of the embedded knowledge is read.
	var catalog componentCatalog = knowledge
	switch {
	case knowledge != nil && request.KnowledgeDB != "" && knowledge.Store() == nil:
		// A database was asked for but the caller supplied knowledge that
		// does not come from one: never answer from it instead.
		return Result{}, ErrIntegrity
	case knowledge != nil:
	case request.KnowledgeDB != "":
		loaded, err := cncfcheck.LoadScanCatalog()
		if err != nil {
			return Result{}, ErrIntegrity
		}
		catalog = loaded
	default:
		loaded, err := LoadEmbedded()
		if err != nil {
			return Result{}, ErrIntegrity
		}
		knowledge, catalog = loaded, loaded
	}
	build := options.Build
	if build == nil {
		identity, err := buildidentity.Report()
		if err != nil {
			return Result{}, ErrIntegrity
		}
		build = &identity
	}

	config, configDir, err := loadConfig(request)
	if err != nil {
		return Result{}, err
	}
	charts, err := helmFlags(request, config)
	if err != nil {
		return Result{}, err
	}
	effective := scanconfig.Merge(config, scanconfig.FlagDeclarations{
		Inputs: request.Paths, Current: request.From, Target: request.To,
		Distribution: request.Distribution, ResourceScopeComplete: request.ResourceScopeComplete, TargetApplyRequired: request.TargetApplyRequired,
		MinimumKubeletVersion: request.KubeletVersionMin, MaximumKubeletVersion: request.KubeletVersionMax,
		Helm: charts,
	})
	if err := checkComponents(catalog, effective); err != nil {
		return Result{}, err
	}
	if err := checkCharts(effective); err != nil {
		return Result{}, err
	}
	kubelet, err := kubeletDeclarationOf(effective)
	if err != nil {
		return Result{}, err
	}
	// openKnowledge opens the knowledge database a scan reads (never called
	// when knowledge was supplied). A community project named in the scan is
	// looked up right after the component names are checked, as that check
	// always answered for it before; every other scan opens the database
	// after its input, as before.
	useEmbedded := func(source string, sel *scanreport.KnowledgeSelection) error {
		loaded, err := LoadEmbedded()
		if err != nil {
			return ErrIntegrity
		}
		request.KnowledgeDB, autoStore = "", false
		knowledgeSource, selection = source, sel
		knowledge = loaded
		return nil
	}
	openKnowledge := func() error {
		targets := make([]string, 0, len(effective.Target)+len(request.NewestCovered))
		for slug := range effective.Target {
			targets = append(targets, slug)
		}
		targets = append(targets, request.NewestCovered...)
		// A community project named only as the current version is asked
		// of the database too: whether it holds data for it decides if the
		// project is known.
		for slug := range effective.Current {
			if _, named := effective.Target[slug]; !named && isCommunity(slug) {
				targets = append(targets, slug)
			}
		}
		sort.Strings(targets)
		open := options.OpenStore
		if open == nil {
			open = OpenStore
		}
		pinned := options.PinnedRoot
		if pinned == nil {
			pinned = knowledgepin.Digest
		}
		opened, err := open(request.KnowledgeDB, targets)
		var storeErr *StoreError
		if err != nil && autoStore && errors.As(err, &storeErr) && storeErr.Fallback != "" {
			// A failure that only warrants the fallback (an expired, too-new or
			// trust-advanced store): the
			// embedded knowledge is used, with a warning. The pin still
			// has to match, so a store of another trust root stays refused.
			expiredRoot := options.ExpiredRoot
			if expiredRoot == nil {
				expiredRoot = knowledgestore.ExpiredStoreRootDigest
			}
			root, rerr := expiredRoot(request.KnowledgeDB)
			switch {
			case rerr != nil:
				return &StoreError{Reason: scanreport.KnowledgeDBIntegrity, Auto: true}
			case knowledgeauto.CheckPin(pinned(knowledgeauto.Profile), root) != nil:
				return &StoreError{Reason: scanreport.KnowledgeDBPinMismatch, Auto: true}
			}
			return useEmbedded("warning: knowledge source: embedded, "+knowledgeauto.FallbackWarning(storeErr.Fallback, storeErr.FallbackMin, request.KnowledgeDB),
				&scanreport.KnowledgeSelection{Chosen: knowledgeauto.SourceEmbedded, Reason: storeErr.Fallback})
		}
		if err == nil && autoStore {
			err = knowledgeauto.CheckPin(pinned(knowledgeauto.Profile), opened.InitialRootDigest())
			if err != nil {
				err = &StoreError{Reason: scanreport.KnowledgeDBPinMismatch}
			}
		}
		if err == nil && autoStore && opened.info.Provenance.Layout != cncfknowledge.LayoutPerProject {
			err = &StoreError{Reason: scanreport.KnowledgeDBLayout}
		}
		if err != nil {
			if autoStore && errors.As(err, &storeErr) {
				storeErr.Auto = true
			}
			return err
		}
		if autoStore {
			// The store is fully verified. The newer knowledge wins.
			compare := options.CompareEmbedded
			if compare == nil {
				compare = cncfcheck.CompareWithEmbedded
			}
			cmp, cerr := compare(opened.bundles)
			if cerr != nil {
				return &StoreError{Reason: scanreport.KnowledgeDBIntegrity, Auto: true}
			}
			choice := knowledgeauto.Choose(cmp.StoreEvidenceAt, cmp.EmbeddedEvidenceAt, cmp.Identical, cmp.StaleProject)
			sel := &scanreport.KnowledgeSelection{Chosen: choice.Chosen, Reason: choice.Reason, EmbeddedEvidenceAt: cmp.EmbeddedEvidenceAt.UTC().Format(time.RFC3339), StoreEvidenceAt: cmp.StoreEvidenceAt.UTC().Format(time.RFC3339)}
			if !choice.UseStore() {
				return useEmbedded("knowledge source: embedded, "+choice.EmbeddedWhy(), sel)
			}
			selection = sel
			knowledgeNote = knowledgeauto.StalenessNote(opened.info.Provenance.ImportedVerifiedAt, "")
			knowledgeSource = "knowledge source: local-db, revision " + opened.Revision() + ", bundle digest " + opened.PackDigest() + " (" + choice.StoreDetail() + ")"
		}
		knowledge = opened
		return nil
	}
	if knowledge == nil && namesCommunity(effective) {
		if err := openKnowledge(); err != nil {
			return Result{}, err
		}
	}
	if err := checkCommunityKnown(knowledge, effective); err != nil {
		return Result{}, err
	}
	if len(effective.Target) == 0 && len(request.NewestCovered) == 0 {
		return Result{}, usage(scanreport.UsageNoTarget)
	}
	paths, err := inputPaths(effective, configDir)
	if err != nil {
		return Result{}, err
	}
	workspace, err := intake.Open(paths, intake.Options{Permissions: request.Permissions, Stdin: options.Stdin})
	if err != nil {
		return Result{}, inputError(err, request)
	}
	if knowledge == nil {
		if err := openKnowledge(); err != nil {
			return Result{}, err
		}
	}
	store := knowledge.Store()
	now := request.Now
	switch {
	case store != nil && !now.IsZero():
		return Result{}, usage(scanreport.UsageKnowledgeDBNow)
	case store != nil:
		// A verified database is evaluated at the verifier's clock only.
		now = store.EvaluatedAt.UTC().Truncate(time.Second)
	case now.IsZero():
		clock := options.Clock
		if clock == nil {
			clock = time.Now
		}
		now = clock().UTC().Truncate(time.Second)
	}

	wallClock := options.Clock
	if wallClock == nil {
		wallClock = time.Now
	}
	pinnedNowWarning, pinnedNowGap := pinnedNowExpiry(knowledge, request.Now, wallClock().UTC().Truncate(time.Second))

	if err := resolveNewestCovered(&effective, request.NewestCovered, knowledge, now); err != nil {
		return Result{}, err
	}

	// Declared charts are resolved through the reviewed chart-source table
	// at the evaluation instant, and their values read, before anything is
	// evaluated.
	declaredCharts, err := resolveCharts(effective, configDir, request, now)
	if err != nil {
		return Result{}, err
	}

	report := scanreport.Report{Provenance: scanreport.Provenance{
		EvaluatedAt: now.Format(time.RFC3339), InputDigest: workspace.Digest, ConfigDigest: config.Digest,
		KnowledgeOrigin: knowledge.Origin(), KnowledgeRevision: knowledge.Revision(), KnowledgeDigest: knowledge.PackDigest(),
		Build: *build, KnowledgeSelection: selection,
	}}
	if store != nil {
		provenance := store.Provenance
		provenance.Projects = append([]scanreport.KnowledgeStoreProject(nil), store.Provenance.Projects...)
		report.Provenance.KnowledgeStore = &provenance
	}
	manifests := splitConfigDocuments(workspace, &report)
	report.Summary.DocumentsRead = len(manifests.Documents)
	report.Summary.DocumentsAllowlistSkipped = workspace.AllowlistSkipped
	readable := 0
	for _, file := range workspace.Files {
		if report.Anchor == "" && file.Policy != intake.ModeNotApplicable {
			report.Anchor = file.Display
		}
		if file.Policy == intake.ModeReadableByOthers {
			readable++
		}
	}
	// Without an input file (standard input only), results that belong to the
	// whole scan sit at the configuration file the user named, if any.
	if report.Anchor == "" && request.Config != "" {
		report.Anchor = request.Config
	}
	if readable > 0 {
		report.Notes = append(report.Notes, scanreport.PermissionNote(readable))
	}

	if err := detectCurrent(&effective, declaredCharts, manifests.Documents, now, &report, func() (chartLookup, error) { return loadEmbeddedCharts() }); err != nil {
		return Result{}, err
	}

	kubeletUsed := false
	slugs := make([]string, 0, len(effective.Target)+len(effective.Current))
	inventory := map[string]*scanreport.Component{}
	for slug, value := range effective.Current {
		component := entry(inventory, knowledge, slug, &slugs)
		component.Current, component.CurrentSource = value.Value, string(value.Source)
	}
	for slug, value := range effective.Target {
		component := entry(inventory, knowledge, slug, &slugs)
		component.Target, component.TargetSource = value.Value, string(value.Source)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		if decl, ok := declaredCharts[slug]; ok {
			inventory[slug].Chart = decl.chart.Name
			report.Provenance.HelmValues = append(report.Provenance.HelmValues, decl.provenance)
		}
	}
	// A project of the community catalog is labelled wherever it appears: in
	// the inventory and in a note every output format carries.
	if labeller, ok := knowledge.(interface{ Catalog(slug string) string }); ok {
		for _, slug := range slugs {
			if labeller.Catalog(slug) == cncfcheck.CatalogCommunity {
				inventory[slug].Catalog = cncfcheck.CatalogCommunity
				report.Notes = append(report.Notes, scanreport.Text(scanreport.NoteCommunityCatalog, slug))
			}
		}
	}
	// A pre-release Kubernetes version is labelled in the inventory and in a
	// note, and the scan can never pass: the gap holds for every path that
	// reads the version (the Kubernetes hops, a chart hop given a Kubernetes
	// version).
	if component, ok := inventory[kubernetesSlug]; ok {
		for i, version := range []string{component.Current, component.Target} {
			if !constraintengine.PreRelease(version) || i == 1 && version == component.Current {
				continue
			}
			component.VersionStage = scanreport.VersionStagePreRelease
			report.Notes = append(report.Notes, scanreport.Text(scanreport.NotePreRelease, version))
			report.Gaps = append(report.Gaps, scanreport.NewGap(kubernetesSlug, nil, scanreport.GapVersionPreRelease, version))
		}
	}
	for _, slug := range slugs {
		component := inventory[slug]
		if component.Target == "" {
			report.Inventory = append(report.Inventory, *component)
			continue
		}
		if decl, ok := declaredCharts[slug]; ok {
			// A declared chart hop: its versions are chart versions, so no
			// application rule (custom-resource, Kubernetes) is run on them.
			report.Inventory = append(report.Inventory, *component)
			if store != nil && store.Absent[slug] {
				report.Gaps = append(report.Gaps, scanreport.NewGap(slug, nil, scanreport.GapProjectNotInKnowledge, slug))
				continue
			}
			run := &helmChartRun{knowledge: knowledge, now: now, report: &report, workspace: manifests, slug: slug, component: component.Component, decl: decl, policy: request.TrustPolicy}
			if value, ok := effective.Current[kubernetesSlug]; ok {
				run.kubernetesFrom = value.Value
			}
			if value, ok := effective.Target[kubernetesSlug]; ok {
				run.kubernetesTo = value.Value
			}
			if run.kubernetesFrom != "" || run.kubernetesTo != "" {
				purl, known := knowledge.Component(kubernetesSlug)
				if !known {
					return Result{}, ErrIntegrity
				}
				run.kubernetes = purl
			}
			if err := run.evaluate(component.Current, component.Target); err != nil {
				return Result{}, err
			}
			continue
		}
		if run, ok := newCustomResourceRun(knowledge, now, &report, manifests, slug, component.Component, declarationsOf(effective), request.TrustPolicy); ok {
			// Checked for custom-resource versions only: never covered.
			report.Inventory = append(report.Inventory, *component)
			if store != nil && store.Absent[slug] {
				report.Gaps = append(report.Gaps, scanreport.NewGap(slug, nil, scanreport.GapProjectNotInKnowledge, slug))
				continue
			}
			if err := run.evaluate(component.Current, component.Target); err != nil {
				return Result{}, err
			}
			continue
		}
		if slug != kubernetesSlug {
			report.Gaps = append(report.Gaps, scanreport.NewGap(slug, nil, scanreport.GapComponentNotCovered, slug))
			report.Inventory = append(report.Inventory, *component)
			continue
		}
		if store != nil && store.Absent[slug] {
			// The selected index has no target for the component: no rule,
			// review or policy can apply, and nothing is borrowed from the
			// embedded knowledge.
			report.Gaps = append(report.Gaps, scanreport.NewGap(slug, nil, scanreport.GapProjectNotInKnowledge, slug))
			report.Inventory = append(report.Inventory, *component)
			continue
		}
		component.Covered = true
		report.Inventory = append(report.Inventory, *component)
		declared := declarationsOf(effective)
		declared.kubelet = kubelet
		run := &kubernetesRun{
			knowledge: knowledge, now: now, report: &report, workspace: manifests,
			component: component.Component, declarations: declared, policy: request.TrustPolicy,
		}
		if err := run.evaluate(component.Current, component.Target); err != nil {
			return Result{}, err
		}
		skew := scanreport.OmissionNodeSkew
		if kubelet.Minimum != "" {
			skew = scanreport.OmissionNodeSkewDeclared
		}
		report.Omissions = append(report.Omissions, skew, scanreport.OmissionKubernetesScope)
		kubeletUsed = true
		if kubelet.Minimum != "" {
			report.Provenance.KubeletVersions = &scanreport.KubeletVersions{Minimum: kubelet.Minimum, Maximum: kubelet.Maximum, Source: kubelet.Source}
			report.Notes = append(report.Notes, scanreport.NoteKubeletHops)
			if kubelet.Maximum == "" {
				report.Notes = append(report.Notes, scanreport.NoteKubeletMaxNotDeclared)
			}
		}
	}
	if kubelet.Minimum != "" && !kubeletUsed {
		report.Notes = append(report.Notes, scanreport.NoteKubeletUnused)
	}

	dropShadowedNotDetected(&report)
	if pinnedNowGap != nil {
		report.Gaps = append(report.Gaps, *pinnedNowGap)
	}
	scanreport.Finalize(&report)
	if request.Redact {
		scanreport.Redact(&report)
	}
	return Result{Report: report, Exit: scanreport.Exit(report), KnowledgeAge: knowledgeAgeNote(knowledge, now), PinnedNowWarning: pinnedNowWarning, KnowledgeSource: knowledgeSource, KnowledgeNote: knowledgeNote}, nil
}

// knowledgeAgeNote words the age note for the knowledge a scan used,
// evaluated at now. Knowledge that cannot list its rules' end dates gives
// no note.
func knowledgeAgeNote(knowledge Knowledge, now time.Time) string {
	aged, ok := knowledge.(interface {
		KnowledgeAge() []knowledgeage.Source
	})
	if !ok {
		return ""
	}
	return knowledgeage.Line(knowledgeage.Summarize(aged.KnowledgeAge(), now), now, knowledge.Store() == nil)
}

// pinnedNowExpiry finds knowledge rules that have expired at the real time
// wall but not at the --now the request pinned: the pin hides them. It
// returns the warning for standard error and the gap that stops a PASS, or
// nothing when no --now was given, --now is not earlier than wall, a
// knowledge database fixes the time, or no rule expired in between. It uses
// the same expiry count as the knowledge age note.
func pinnedNowExpiry(knowledge Knowledge, pinned, wall time.Time) (string, *scanreport.Gap) {
	if pinned.IsZero() || knowledge.Store() != nil || !pinned.Before(wall) {
		return "", nil
	}
	aged, ok := knowledge.(interface {
		KnowledgeAge() []knowledgeage.Source
	})
	if !ok {
		return "", nil
	}
	sources := aged.KnowledgeAge()
	expired := knowledgeage.Summarize(sources, wall).Expired
	if expired <= knowledgeage.Summarize(sources, pinned).Expired {
		return "", nil
	}
	return PinnedNowText(pinned, wall, expired), gapPtr(scanreport.NewGap("knowledge", nil, scanreport.GapPinnedNowStale, pinned.Format(time.RFC3339), wall.Format("2006-01-02"), expired))
}

// PinnedNowText words the warning for a --now earlier than the real time wall
// when expired knowledge rules hide behind it.
func PinnedNowText(pinned, wall time.Time, expired int) string {
	return fmt.Sprintf("warning: --now %s is earlier than today (%s) and %d knowledge rules have expired since; the pinned time hides it. Drop --now to evaluate at the real time", pinned.Format(time.RFC3339), wall.Format("2006-01-02"), expired)
}

func gapPtr(gap scanreport.Gap) *scanreport.Gap { return &gap }

// componentCatalog names the catalog's projects and their components.
type componentCatalog interface {
	Projects() []string
	Component(slug string) (string, bool)
}

func entry(inventory map[string]*scanreport.Component, knowledge componentCatalog, slug string, slugs *[]string) *scanreport.Component {
	if component, found := inventory[slug]; found {
		return component
	}
	purl, _ := knowledge.Component(slug)
	component := &scanreport.Component{Name: slug, Component: purl}
	inventory[slug] = component
	*slugs = append(*slugs, slug)
	return component
}

// loadConfig reads --config, or prufyx.yaml next to the first input (the
// current directory when no input is named). It returns the directory that
// relative inputs in the file are resolved against.
func loadConfig(request Request) (scanconfig.Config, string, error) {
	path := request.Config
	if path == "" {
		first := "."
		if len(request.Paths) > 0 {
			first = request.Paths[0]
		}
		found, ok, err := scanconfig.Discover(first)
		if err != nil {
			return scanconfig.Config{}, "", configError(err, request)
		}
		if !ok {
			return scanconfig.Config{}, "", nil
		}
		path = found
	}
	config, err := scanconfig.Load(path, request.Permissions)
	if err != nil {
		return scanconfig.Config{}, "", configError(err, request)
	}
	return config, filepath.Dir(path), nil
}

func configError(err error, request Request) error {
	var configErr interface{ Unwrap() error }
	switch {
	case errors.Is(err, intake.ErrPermissions):
		return permissionError(err, request)
	case errors.Is(err, scanconfig.ErrConfig) && errors.As(err, &configErr):
		return usage(scanreport.UsageConfig, err.Error())
	}
	return usage(scanreport.UsageInputNotAccepted, scanreport.UsageConfigNotAccepted)
}

func permissionError(err error, request Request) error {
	message := scanreport.Text(scanreport.UsagePermissions, request.PermissionsName)
	if request.Permissions == intake.RefuseWritable {
		message = scanreport.Text(scanreport.UsagePermissionsWrite)
	}
	if !request.Redact {
		message = scanreport.Text(scanreport.UsageInputDetail, message, err.Error())
	}
	return usage(scanreport.UsageInputNotAccepted, message)
}

// inputError turns an intake refusal into a usage error. The underlying
// message names the path; it is left out under --redact.
func inputError(err error, request Request) error {
	if errors.Is(err, intake.ErrPermissions) {
		return permissionError(err, request)
	}
	message := scanreport.Text(scanreport.UsageInputUnreadable)
	switch {
	case errors.Is(err, intake.ErrLimit):
		message = scanreport.Text(scanreport.UsageInputLimit)
	case errors.Is(err, intake.ErrDecode):
		message = scanreport.Text(scanreport.UsageInputDecode)
	case errors.Is(err, validation.ErrUnsupportedPlatform):
		// A fixed message, shown even when paths are redacted.
		message = scanreport.Text(scanreport.UsageInputWindows)
	}
	if !request.Redact {
		message = scanreport.Text(scanreport.UsageInputDetail, message, err.Error())
	}
	return usage(scanreport.UsageInputNotAccepted, message)
}

// checkComponents refuses a component name that is not in the catalog,
// naming the closest ones.
func checkComponents(knowledge componentCatalog, effective scanconfig.Effective) error {
	names := make([]string, 0, len(effective.Current)+len(effective.Target)+len(effective.Helm))
	for slug := range effective.Current {
		names = append(names, slug)
	}
	for slug := range effective.Target {
		names = append(names, slug)
	}
	for slug := range effective.Helm {
		names = append(names, slug)
	}
	sort.Strings(names)
	for _, slug := range names {
		if _, ok := knowledge.Component(slug); !ok {
			if _, community := cncfprepare.CommunityCustomResourceProject(slug); community {
				return usage(scanreport.UsageCommunityComponent, quote(slug))
			}
			if near := closest(slug, knowledge.Projects(), 3); len(near) > 0 {
				return usage(scanreport.UsageUnknownComponent, quote(slug), strings.Join(near, ", "))
			}
			return usage(scanreport.UsageUnknownComponentNoMatch, quote(slug))
		}
	}
	return nil
}

// inputPaths are the paths given on the command line, else the inputs of the
// configuration file resolved against its directory, else ".".
func inputPaths(effective scanconfig.Effective, configDir string) ([]string, error) {
	if !effective.Inputs.Set || len(effective.Inputs.Value) == 0 {
		return []string{"."}, nil
	}
	if effective.Inputs.Source == scanconfig.FromFlag {
		return effective.Inputs.Value, nil
	}
	paths := make([]string, 0, len(effective.Inputs.Value))
	for _, input := range effective.Inputs.Value {
		joined := filepath.Join(configDir, input)
		if rel, err := filepath.Rel(configDir, joined); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, usage(scanreport.UsageInputNotAccepted, scanreport.UsageConfigInputs)
		}
		paths = append(paths, joined)
	}
	return paths, nil
}

// omittedConfigDocument is the reason a scan configuration document found
// among the inputs is not evaluated.
const omittedConfigDocument = "CONFIG_DOCUMENT"

// splitConfigDocuments drops scan configuration documents from the
// manifests and lists them, with every intake omission, as omitted. The
// returned workspace is the apply set the preparation reads.
func splitConfigDocuments(workspace intake.Workspace, report *scanreport.Report) intake.Workspace {
	// Auxiliary documents (a chart's Chart.yaml) say which documents of a raw
	// chart may not be rendered.
	manifests := intake.Workspace{Omissions: workspace.Omissions, Auxiliary: workspace.Auxiliary, Digest: workspace.Digest}
	for _, document := range workspace.Documents {
		if scanconfig.IsConfigDocument(document.APIVersion, document.Kind) {
			report.Omitted = append(report.Omitted, omitted(document.Source, omittedConfigDocument))
			continue
		}
		manifests.Documents = append(manifests.Documents, document)
	}
	for _, omission := range workspace.Omissions {
		report.Omitted = append(report.Omitted, omitted(omission.Source, string(omission.Reason)))
	}
	return manifests
}

// omissionCounts counts the intake omissions by the gap each reason maps to;
// a reason without a mapping counts as a document shape gap. Every route
// that reads the workspace turns these into gaps, never into a pass.
func omissionCounts(omissions []intake.Omission) map[scanreport.GapKey]int {
	counts := map[scanreport.GapKey]int{}
	for _, omission := range omissions {
		outcome, known := reasonOutcomes[string(omission.Reason)]
		if !known || outcome.gap == "" {
			outcome.gap = scanreport.GapDocumentsShape
		}
		counts[outcome.gap]++
	}
	return counts
}

func omitted(source intake.Source, reason string) scanreport.Omitted {
	return scanreport.Omitted{File: source.Display, Document: source.Document, Item: source.Item, Line: source.Line, Reason: reason}
}

// declarations are the Kubernetes declarations after flags override the file.
type declarations struct {
	distribution    string
	distributionSet bool
	scopeComplete   bool
	applyRequired   bool
	// kubelet are the declared kubelet versions; the zero value declares none.
	kubelet cncfprepare.KubeletDeclaration
}

// kubeletDeclarationOf reads the declared kubelet versions after flags
// override the file and validates them with the check route's rules. A
// declaration that does not validate is a usage error: it is never ignored
// and never read as a pass.
func kubeletDeclarationOf(effective scanconfig.Effective) (cncfprepare.KubeletDeclaration, error) {
	minimum, maximum := effective.MinimumKubeletVersion, effective.MaximumKubeletVersion
	if !minimum.Set && !maximum.Set {
		return cncfprepare.KubeletDeclaration{}, nil
	}
	if !minimum.Set {
		// A maximum without a minimum.
		return cncfprepare.KubeletDeclaration{}, usage(scanreport.UsageKubeletVersions)
	}
	declaration := cncfprepare.KubeletDeclaration{Minimum: minimum.Value, Maximum: maximum.Value, Source: string(minimum.Source)}
	if maximum.Set && maximum.Source != minimum.Source {
		declaration.Source = "mixed"
	}
	// An empty value is "declared but empty", not "not declared".
	if declaration.Minimum == "" || maximum.Set && declaration.Maximum == "" || cncfprepare.ValidateKubeletVersionDeclarations(declaration.Minimum, declaration.Maximum) != nil {
		return cncfprepare.KubeletDeclaration{}, usage(scanreport.UsageKubeletVersions)
	}
	return declaration, nil
}

func declarationsOf(effective scanconfig.Effective) declarations {
	return declarations{
		distribution: effective.Distribution.Value, distributionSet: effective.Distribution.Set,
		scopeComplete: effective.ResourceScopeComplete.Set && effective.ResourceScopeComplete.Value,
		applyRequired: effective.TargetApplyRequired.Set && effective.TargetApplyRequired.Value,
	}
}

// isCommunity reports whether slug is a community project of the reviewed
// custom-resource table (outside the embedded CNCF landscape catalog).
func isCommunity(slug string) bool {
	_, community := cncfprepare.CommunityCustomResourceProject(slug)
	return community
}

// namesCommunity reports whether the scan names a community project.
func namesCommunity(effective scanconfig.Effective) bool {
	for slug := range effective.Current {
		if isCommunity(slug) {
			return true
		}
	}
	for slug := range effective.Target {
		if isCommunity(slug) {
			return true
		}
	}
	return false
}

// checkCommunityKnown refuses a community project the knowledge holds no
// data for, with the answer given for every community project before the
// community knowledge step. The component catalog names community projects
// when it is the compiled catalog alone (a scan with --knowledge-db); the
// knowledge they are looked up in is known only once it is open.
func checkCommunityKnown(knowledge Knowledge, effective scanconfig.Effective) error {
	if knowledge == nil {
		return nil
	}
	names := make([]string, 0, len(effective.Current)+len(effective.Target))
	for slug := range effective.Current {
		names = append(names, slug)
	}
	for slug := range effective.Target {
		names = append(names, slug)
	}
	sort.Strings(names)
	for _, slug := range names {
		if !isCommunity(slug) {
			continue
		}
		if _, ok := knowledge.Component(slug); !ok {
			return usage(scanreport.UsageCommunityComponent, quote(slug))
		}
	}
	return nil
}
