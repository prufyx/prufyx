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
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/knowledgeauto"
	"github.com/prufyx/prufyx/cli/internal/knowledgepin"
	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
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
		}
	} else if knowledge == nil && options.AutoLocalDB && request.KnowledgeDB == "" && request.KnowledgeMode == "embedded" {
		knowledgeSource = "knowledge source: embedded, forced by --knowledge=embedded"
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
	effective := scanconfig.Merge(config, scanconfig.FlagDeclarations{
		Inputs: request.Paths, Current: request.From, Target: request.To,
		Distribution: request.Distribution, ResourceScopeComplete: request.ResourceScopeComplete, TargetApplyRequired: request.TargetApplyRequired,
	})
	if err := checkComponents(catalog, effective); err != nil {
		return Result{}, err
	}
	if len(effective.Target) == 0 {
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
		targets := make([]string, 0, len(effective.Target))
		for slug := range effective.Target {
			targets = append(targets, slug)
		}
		sort.Strings(targets)
		opened, err := OpenStore(request.KnowledgeDB, targets)
		if err == nil && autoStore {
			pinned := options.PinnedRoot
			if pinned == nil {
				pinned = knowledgepin.Digest
			}
			err = knowledgeauto.CheckPin(pinned(knowledgeauto.Profile), opened.InitialRootDigest())
			if err != nil {
				err = &StoreError{Reason: scanreport.KnowledgeDBPinMismatch}
			}
		}
		if err == nil && autoStore && opened.info.Provenance.Layout != cncfknowledge.LayoutPerProject {
			err = &StoreError{Reason: scanreport.KnowledgeDBLayout}
		}
		if err != nil {
			var storeErr *StoreError
			if autoStore && errors.As(err, &storeErr) {
				storeErr.Auto = true
			}
			return Result{}, err
		}
		if autoStore {
			knowledgeNote = knowledgeauto.StalenessNote(opened.info.Provenance.ImportedVerifiedAt, "")
		}
		if autoStore {
			knowledgeSource = "knowledge source: local-db, revision " + opened.Revision() + ", bundle digest " + opened.PackDigest()
		}
		knowledge = opened
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

	report := scanreport.Report{Provenance: scanreport.Provenance{
		EvaluatedAt: now.Format(time.RFC3339), InputDigest: workspace.Digest, ConfigDigest: config.Digest,
		KnowledgeOrigin: knowledge.Origin(), KnowledgeRevision: knowledge.Revision(), KnowledgeDigest: knowledge.PackDigest(),
		Build: *build,
	}}
	if store != nil {
		provenance := store.Provenance
		provenance.Projects = append([]scanreport.KnowledgeStoreProject(nil), store.Provenance.Projects...)
		report.Provenance.KnowledgeStore = &provenance
	}
	manifests := splitConfigDocuments(workspace, &report)
	report.Summary.DocumentsRead = len(manifests.Documents)
	readable := 0
	for _, file := range workspace.Files {
		if file.Policy == intake.ModeReadableByOthers {
			readable++
		}
	}
	if readable > 0 {
		report.Notes = append(report.Notes, scanreport.PermissionNote(readable))
	}

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
		component := inventory[slug]
		if component.Target == "" {
			report.Inventory = append(report.Inventory, *component)
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
		run := &kubernetesRun{
			knowledge: knowledge, now: now, report: &report, workspace: manifests,
			component: component.Component, declarations: declarationsOf(effective), policy: request.TrustPolicy,
		}
		if err := run.evaluate(component.Current, component.Target); err != nil {
			return Result{}, err
		}
		report.Omissions = append(report.Omissions, scanreport.OmissionNodeSkew, scanreport.OmissionKubernetesScope)
	}

	scanreport.Finalize(&report)
	if request.Redact {
		scanreport.Redact(&report)
	}
	return Result{Report: report, Exit: scanreport.Exit(report), KnowledgeAge: knowledgeAgeNote(knowledge, now), KnowledgeSource: knowledgeSource, KnowledgeNote: knowledgeNote}, nil
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
	}
	if !request.Redact {
		message = scanreport.Text(scanreport.UsageInputDetail, message, err.Error())
	}
	return usage(scanreport.UsageInputNotAccepted, message)
}

// checkComponents refuses a component name that is not in the catalog,
// naming the closest ones.
func checkComponents(knowledge componentCatalog, effective scanconfig.Effective) error {
	names := make([]string, 0, len(effective.Current)+len(effective.Target))
	for slug := range effective.Current {
		names = append(names, slug)
	}
	for slug := range effective.Target {
		names = append(names, slug)
	}
	sort.Strings(names)
	for _, slug := range names {
		if _, ok := knowledge.Component(slug); !ok {
			return usage(scanreport.UsageUnknownComponent, quote(slug), strings.Join(closest(slug, knowledge.Projects(), 3), ", "))
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

func omitted(source intake.Source, reason string) scanreport.Omitted {
	return scanreport.Omitted{File: source.Display, Document: source.Document, Item: source.Item, Line: source.Line, Reason: reason}
}

// declarations are the Kubernetes declarations after flags override the file.
type declarations struct {
	distribution    string
	distributionSet bool
	scopeComplete   bool
	applyRequired   bool
}

func declarationsOf(effective scanconfig.Effective) declarations {
	return declarations{
		distribution: effective.Distribution.Value, distributionSet: effective.Distribution.Set,
		scopeComplete: effective.ResourceScopeComplete.Set && effective.ResourceScopeComplete.Value,
		applyRequired: effective.TargetApplyRequired.Set && effective.TargetApplyRequired.Value,
	}
}
