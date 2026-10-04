// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// storeFixture is a local knowledge database signed with ephemeral test
// keys, in one of the two CNCF layouts.
type storeFixture struct {
	t       *testing.T
	repo    *knowledgefixture.ProjectsRepository
	dir     string
	root    string
	store   string
	layout  string
	version int64
}

func newStoreFixture(t *testing.T, layout string) *storeFixture {
	t.Helper()
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	dir := t.TempDir()
	f := &storeFixture{t: t, repo: repo, dir: dir, store: filepath.Join(dir, "store"), layout: layout}
	f.root = f.write("root.json", repo.Root)
	return f
}

func (f *storeFixture) write(name string, raw []byte) string {
	f.t.Helper()
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

// importPack signs pack (nil: the embedded pack) at revision in the
// fixture's layout and imports it into the store.
func (f *storeFixture) importPack(pack []byte, revision string) {
	f.t.Helper()
	targets := map[string][]byte{}
	switch f.layout {
	case cncfknowledge.LayoutSingleTarget:
		var raw []byte
		var err error
		if pack == nil {
			raw, err = cncfcheck.ExportEmbeddedExternalBundle(revision)
		} else {
			raw, err = cncfcheck.ExportExternalBundleFromPack(pack, revision)
		}
		if err != nil {
			f.t.Fatal(err)
		}
		targets[knowledge.ConstraintsTargetPath] = raw
	default:
		var index cncfcheck.ExternalTarget
		var projects []cncfcheck.ExternalTarget
		var err error
		if pack == nil {
			index, projects, err = cncfcheck.BuildEmbeddedExternalTargets(revision, nil)
		} else {
			index, projects, err = cncfcheck.BuildExternalTargetsFromPack(pack, revision)
		}
		if err != nil {
			f.t.Fatal(err)
		}
		targets[index.Path] = index.Bytes
		for _, project := range projects {
			targets[project.Path] = project.Bytes
		}
	}
	f.version++
	raw, err := f.repo.Package(knowledgefixture.ProjectsPackage{Version: f.version, Targets: targets})
	if err != nil {
		f.t.Fatal(err)
	}
	request := knowledge.ImportRequest{PackagePath: f.write("package.tar", raw), StoreRoot: f.store}
	if f.version == 1 {
		request.BootstrapRootPath, request.BootstrapRootDigest = f.root, f.repo.RootDigest
	}
	if f.layout == cncfknowledge.LayoutSingleTarget {
		_, err = knowledge.ImportConstraints(request)
	} else {
		_, err = knowledge.ImportConstraintsProjects(request)
	}
	if err != nil {
		f.t.Fatal(err)
	}
}

// openAt opens the store for kubernetes and moves its evaluation instant to
// at. Only tests move the instant; the command always evaluates at the
// verifier's clock.
func openAt(t *testing.T, store, at string) *Store {
	t.Helper()
	opened, err := OpenStore(store, []string{kubernetesSlug})
	if err != nil {
		t.Fatal(err)
	}
	instant, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatal(err)
	}
	moved := *opened
	moved.info.EvaluatedAt = instant
	return &moved
}

// storeArgs are args without --now.
func storeArgs(paths []string, extra ...string) []string {
	return append(append(append([]string{}, paths...), declared...), extra...)
}

// embeddedPack is the embedded rule pack as published.
func embeddedPack(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(testdata), "..", "cncfcheck", "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// editPack rewrites the pack's entries with edit; an entry for which edit
// returns false is dropped.
func editPack(t *testing.T, raw []byte, edit func(project string, rule map[string]any) bool) []byte {
	t.Helper()
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	var kept []any
	for _, item := range pack["entries"].([]any) {
		entry := item.(map[string]any)
		if edit(entry["project"].(string), entry["rule"].(map[string]any)) {
			kept = append(kept, entry)
		}
	}
	pack["entries"] = kept
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// withoutProvenance is the report JSON with the provenance member removed.
func withoutProvenance(t *testing.T, report scanreport.Report) []byte {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(jsonOf(t, report), &members); err != nil {
		t.Fatal(err)
	}
	if _, found := members["provenance"]; !found {
		t.Fatal("report has no provenance")
	}
	delete(members, "provenance")
	out, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// humanBody is the human output before the provenance footer.
func humanBody(report scanreport.Report) string {
	human := string(scanreport.Human(report, scanreport.HumanOptions{Verbose: true, ShowPasses: true}))
	index := strings.Index(human, "\nevaluated at ")
	if index < 0 {
		return human
	}
	return human[:index]
}

var storeLayouts = []string{cncfknowledge.LayoutSingleTarget, cncfknowledge.LayoutPerProject}

// TestScanStoreMatchesEmbedded: a database that holds the embedded pack, in
// either layout, gives the embedded answer: the same exit, and the same JSON
// and human output apart from provenance. Provenance names the database.
func TestScanStoreMatchesEmbedded(t *testing.T) {
	type scenario struct {
		name     string
		options  knowledgeOptions
		manifest string
		extra    []string
		exit     int
	}
	scenarios := []scenario{
		{"one line, no reviews", knowledgeOptions{}, cronjobV1beta1, []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3"}, scanreport.ExitBlocked},
		{"reviewed path, blocked", knowledgeOptions{lines: allLines, policy: "current"}, cronjobV1beta1, []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}, scanreport.ExitBlocked},
		{"reviewed path, pass", knowledgeOptions{lines: allLines, policy: "current"}, cronjobV1, []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}, scanreport.ExitPass},
		{"one line unreviewed", knowledgeOptions{lines: without(allLines, "1.28"), policy: "current"}, cronjobV1, []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}, scanreport.ExitUnknown},
		{"require mechanical", knowledgeOptions{lines: allLines, policy: "current"}, cronjobV1, []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--require-basis", "mechanical"}, scanreport.ExitUnknown},
		{"require reviewed", knowledgeOptions{lines: allLines, policy: "current"}, cronjobV1beta1, []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--require-basis", "reviewed"}, scanreport.ExitBlocked},
		{"other component", knowledgeOptions{}, cronjobV1beta1, []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--to", "etcd=3.5.0"}, scanreport.ExitBlocked},
	}
	for _, layout := range storeLayouts {
		fixture := newStoreFixture(t, layout)
		fixture.importPack(nil, "5")
		store := openAt(t, fixture.store, testNow)
		info := store.Store()
		for _, s := range scenarios {
			dir, _ := files(t, map[string]string{"applyset.yaml": s.manifest})
			inDir(t, dir, func() {
				embedded := mustScan(t, newKnowledge(t, s.options), args([]string{"applyset.yaml"}, s.extra...)...)
				options := s.options
				options.base = store
				selected := mustScan(t, newKnowledge(t, options), storeArgs([]string{"applyset.yaml"}, s.extra...)...)
				if embedded.Exit != s.exit || selected.Exit != s.exit {
					t.Fatalf("%s %s: exit embedded %d, database %d, want %d", layout, s.name, embedded.Exit, selected.Exit, s.exit)
				}
				if a, b := withoutProvenance(t, embedded.Report), withoutProvenance(t, selected.Report); !bytes.Equal(a, b) {
					t.Fatalf("%s %s: reports differ:\nembedded %s\ndatabase %s", layout, s.name, a, b)
				}
				if a, b := humanBody(embedded.Report), humanBody(selected.Report); a != b {
					t.Fatalf("%s %s: human output differs:\nembedded %s\ndatabase %s", layout, s.name, a, b)
				}
				p, e := selected.Report.Provenance, embedded.Report.Provenance
				if p.EvaluatedAt != testNow || p.KnowledgeOrigin != "external_signed_local" || p.KnowledgeRevision != "5" || p.KnowledgeDigest != store.digest || p.EngineContractDigest != e.EngineContractDigest || p.InputDigest != e.InputDigest || e.KnowledgeStore != nil {
					t.Fatalf("%s %s: provenance %+v (embedded %+v)", layout, s.name, p, e)
				}
				ks := p.KnowledgeStore
				if ks == nil || ks.Path != fixture.store || ks.Layout != layout || ks.TrustReceiptDigest == "" || ks.Purpose != "operator_provided" || ks.ImportedVerifiedAt == "" {
					t.Fatalf("%s %s: knowledge store %+v", layout, s.name, ks)
				}
				switch layout {
				case cncfknowledge.LayoutSingleTarget:
					if ks.TargetPath != knowledge.ConstraintsTargetPath || len(ks.Projects) != 0 {
						t.Fatalf("single-target provenance %+v", ks)
					}
				default:
					if ks.TargetPath != knowledge.ConstraintsProjectsIndexTargetPath || len(ks.Projects) != 1 {
						t.Fatalf("per-project provenance %+v", ks)
					}
					project := ks.Projects[0]
					if project.Project != kubernetesSlug || project.Status != "present" || project.TargetPath != cncfcheck.ProjectTargetPath(kubernetesSlug) || project.Revision != "5" || project.Digest != store.digests[kubernetesSlug] || project.Digest == p.KnowledgeDigest {
						t.Fatalf("project provenance %+v", project)
					}
				}
				if !reflectEqualInfo(ks, &info.Provenance) {
					t.Fatalf("report provenance %+v differs from the database %+v", ks, info.Provenance)
				}
				human := string(scanreport.Human(selected.Report, scanreport.HumanOptions{}))
				if !strings.Contains(human, "knowledge database "+fixture.store+"; layout "+layout+"; target "+ks.TargetPath) {
					t.Fatalf("human provenance:\n%s", human)
				}
				conformReport(t, layout+" "+s.name, selected.Report)
			})
		}
	}
}

func reflectEqualInfo(a, b *scanreport.KnowledgeStore) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// renewedPack renews every Kubernetes rule: a later review and a later
// validUntil, as a renewal published after the embedded leases ran out.
func renewedPack(t *testing.T) []byte {
	return editPack(t, embeddedPack(t), func(project string, rule map[string]any) bool {
		if project == kubernetesSlug {
			evidence := rule["evidence"].(map[string]any)
			evidence["reviewedAt"], evidence["validUntil"] = "2026-12-01T00:00:00Z", "2027-02-28T00:00:00Z"
		}
		return true
	})
}

// afterExpiry is an instant after every embedded Kubernetes rule expired
// and inside the renewed leases.
const afterExpiry = "2027-01-15T00:00:00Z"

// TestScanStoreRenewedRule: after the embedded rules expired, a database
// holding renewed rules evaluates them as current, and the scan finds the
// blocker the stale embedded rule can no longer decide. A database holding
// the stale pack behaves exactly like the embedded knowledge.
func TestScanStoreRenewedRule(t *testing.T) {
	scanArgs := []string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3"}
	for _, layout := range storeLayouts {
		dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
		inDir(t, dir, func() {
			embedded := mustScan(t, nil, append(storeArgs([]string{"applyset.yaml"}, scanArgs...), "--now", afterExpiry)...)
			if embedded.Exit != scanreport.ExitUnknown || len(embedded.Report.Findings) != 0 || !contains(gapReasons(embedded.Report), "EVIDENCE_EXPIRED 1.24.17->1.25.3") {
				t.Fatalf("embedded after expiry: exit %d gaps %v", embedded.Exit, gapReasons(embedded.Report))
			}

			renewed := newStoreFixture(t, layout)
			renewed.importPack(renewedPack(t), "6")
			result := mustScan(t, openAt(t, renewed.store, afterExpiry), storeArgs([]string{"applyset.yaml"}, scanArgs...)...)
			if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0" || contains(gapReasons(result.Report), "EVIDENCE_EXPIRED 1.24.17->1.25.3") {
				t.Fatalf("%s renewed: exit %d findings %+v gaps %v", layout, result.Exit, result.Report.Findings, gapReasons(result.Report))
			}
			if result.Report.Provenance.EvaluatedAt != afterExpiry || result.Report.Provenance.KnowledgeRevision != "6" {
				t.Fatalf("provenance %+v", result.Report.Provenance)
			}
			// Before the renewal's review the renewed rules are not current
			// either: the database's own dates decide.
			early := mustScan(t, openAt(t, renewed.store, testNow), storeArgs([]string{"applyset.yaml"}, scanArgs...)...)
			if early.Exit != scanreport.ExitUnknown || len(early.Report.Findings) != 0 {
				t.Fatalf("%s renewed before review: exit %d gaps %v", layout, early.Exit, gapReasons(early.Report))
			}

			stale := newStoreFixture(t, layout)
			stale.importPack(nil, "5")
			same := mustScan(t, openAt(t, stale.store, afterExpiry), storeArgs([]string{"applyset.yaml"}, scanArgs...)...)
			if same.Exit != embedded.Exit || !bytes.Equal(withoutProvenance(t, same.Report), withoutProvenance(t, embedded.Report)) {
				t.Fatalf("%s stale database differs from embedded:\n%s\n%s", layout, withoutProvenance(t, same.Report), withoutProvenance(t, embedded.Report))
			}
		})
	}
}

// TestScanStoreWithdrawnRule: a rule the database withdraws is not used,
// exactly as a withdrawn embedded rule: the hop is not decided, no finding.
func TestScanStoreWithdrawnRule(t *testing.T) {
	withdrawn := editPack(t, embeddedPack(t), func(project string, rule map[string]any) bool {
		if rule["id"] == "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0" {
			rule["evidence"].(map[string]any)["state"] = "withdrawn"
		}
		return true
	})
	for _, layout := range storeLayouts {
		fixture := newStoreFixture(t, layout)
		fixture.importPack(withdrawn, "7")
		dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
		inDir(t, dir, func() {
			result := mustScan(t, openAt(t, fixture.store, testNow), storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
			if result.Exit != scanreport.ExitUnknown || len(result.Report.Findings) != 0 || !contains(gapReasons(result.Report), "EVIDENCE_EXPIRED 1.24.17->1.25.3") {
				t.Fatalf("%s withdrawn: exit %d gaps %v", layout, result.Exit, gapReasons(result.Report))
			}
		})
	}
}

// TestScanStoreProjectAbsent: a project the selected index has no target
// for is not checked at all: one named gap, the component not covered, no
// path, and nothing from the embedded knowledge.
func TestScanStoreProjectAbsent(t *testing.T) {
	pack := editPack(t, embeddedPack(t), func(project string, _ map[string]any) bool { return project != kubernetesSlug })
	// Without the Kubernetes rules no rule has a reviewed range, so the
	// pack takes the exact-only schema.
	pack = bytes.Replace(pack, []byte("cncf-source-rule-pack/v1alpha2"), []byte("cncf-source-rule-pack/v1alpha1"), 1)
	fixture := newStoreFixture(t, cncfknowledge.LayoutPerProject)
	fixture.importPack(pack, "8")
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	inDir(t, dir, func() {
		for _, extra := range [][]string{nil, {"--require-basis", "reviewed"}} {
			result := mustScan(t, openAt(t, fixture.store, testNow), storeArgs([]string{"applyset.yaml"}, append([]string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3"}, extra...)...)...)
			report := result.Report
			if result.Exit != scanreport.ExitUnknown || report.Verdict != scanreport.VerdictUnknown || len(report.Findings) != 0 || len(report.Paths) != 0 || len(report.Passes) != 0 {
				t.Fatalf("exit %d verdict %s report %+v", result.Exit, report.Verdict, report)
			}
			if got := gapReasons(report); len(got) != 1 || got[0] != scanreport.ReasonProjectNotInKnowledge {
				t.Fatalf("gaps %v", got)
			}
			if len(report.Inventory) != 1 || report.Inventory[0].Covered || report.Summary.ComponentsCovered != 0 {
				t.Fatalf("inventory %+v", report.Inventory)
			}
			projects := report.Provenance.KnowledgeStore.Projects
			if len(projects) != 1 || projects[0] != (scanreport.KnowledgeStoreProject{Project: kubernetesSlug, Status: "absent_from_index"}) {
				t.Fatalf("projects %+v", projects)
			}
			human := string(scanreport.Human(report, scanreport.HumanOptions{}))
			if !strings.Contains(human, "the selected knowledge database has no knowledge for kubernetes") || !strings.Contains(human, "knowledge for kubernetes: absent from the selected index") {
				t.Fatalf("human:\n%s", human)
			}
			conformReport(t, "absent project", report)
		}
	})
}

// TestScanStoreRedact: --redact replaces the database path with its digest
// in JSON and human output.
func TestScanStoreRedact(t *testing.T) {
	fixture := newStoreFixture(t, cncfknowledge.LayoutPerProject)
	private := filepath.Join(fixture.dir, "zz-private-store")
	fixture.store = private
	fixture.importPack(nil, "5")
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	inDir(t, dir, func() {
		result := mustScan(t, openAt(t, private, testNow), storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--redact")...)
		for _, output := range [][]byte{jsonOf(t, result.Report), scanreport.Human(result.Report, scanreport.HumanOptions{Verbose: true, ShowPasses: true})} {
			if bytes.Contains(output, []byte("zz-private-store")) || bytes.Contains(output, []byte(fixture.dir)) {
				t.Fatalf("redacted output names the database:\n%s", output)
			}
		}
		for _, format := range []string{"sarif", "markdown"} {
			out, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{ShowPasses: true, Verbose: true})
			if err != nil || bytes.Contains(out, []byte("zz-private-store")) || !bytes.Contains(out, []byte(scanreport.RedactValue(private))) || !bytes.Contains(out, []byte("knowledge/cncf/projects/kubernetes.v1.json")) {
				t.Fatalf("%s: database provenance not shown redacted (%v):\n%s", format, err, out)
			}
		}
		if got := result.Report.Provenance.KnowledgeStore.Path; got != scanreport.RedactValue(private) {
			t.Fatalf("path %q", got)
		}
		conformReport(t, "redacted database", result.Report)
		plain := mustScan(t, openAt(t, private, testNow), storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")...)
		if plain.Report.Provenance.KnowledgeStore.Path != private {
			t.Fatalf("unredacted path %q", plain.Report.Provenance.KnowledgeStore.Path)
		}
	})
}

// TestScanStoreCommandRoute: through ParseArgs and Run alone, --knowledge-db
// opens the database at the verifier's clock and gives the embedded answer
// at that instant. With --now (via a test knowledge) it is refused.
func TestScanStoreCommandRoute(t *testing.T) {
	for _, layout := range storeLayouts {
		fixture := newStoreFixture(t, layout)
		fixture.importPack(nil, "5")
		dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
		inDir(t, dir, func() {
			scanArgs := storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--to", "etcd=3.5.0")
			before := time.Now().UTC().Truncate(time.Second)
			selected := mustScan(t, nil, append(scanArgs, "--knowledge-db", fixture.store)...)
			at, err := time.Parse(time.RFC3339, selected.Report.Provenance.EvaluatedAt)
			if err != nil || at.Before(before) || at.After(time.Now().UTC()) || selected.Report.Provenance.KnowledgeStore == nil {
				t.Fatalf("evaluated at %s (started %s): %v", selected.Report.Provenance.EvaluatedAt, before, err)
			}
			embedded := mustScan(t, nil, append(scanArgs, "--now", selected.Report.Provenance.EvaluatedAt)...)
			if embedded.Exit != selected.Exit || !bytes.Equal(withoutProvenance(t, embedded.Report), withoutProvenance(t, selected.Report)) {
				t.Fatalf("%s: database and embedded differ at the same instant", layout)
			}
			if layout == cncfknowledge.LayoutPerProject {
				projects := selected.Report.Provenance.KnowledgeStore.Projects
				if len(projects) != 2 || projects[0].Project != "etcd" || projects[1].Project != kubernetesSlug {
					t.Fatalf("projects %+v", projects)
				}
			}
			// A test knowledge cannot be moved off its database clock either.
			request, err := ParseArgs(append(scanArgs, "--now", testNow))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Run(request, Options{Knowledge: openAt(t, fixture.store, testNow), Build: &testBuild}); !isUsage(err) {
				t.Fatalf("--now with a database: %v", err)
			}
		})
	}
}

// TestScanStoreVerificationFailures: every verification failure stops the
// scan with an integrity error. Nothing is evaluated and the embedded
// knowledge is never used instead.
func TestScanStoreVerificationFailures(t *testing.T) {
	admissionFile := func(t *testing.T, store, name string) string {
		t.Helper()
		matches, err := filepath.Glob(filepath.Join(store, "admissions", "*", "*", name))
		if err != nil || len(matches) != 1 {
			t.Fatalf("%s: %v %v", name, matches, err)
		}
		return matches[0]
	}
	rewrite := func(t *testing.T, path string, edit func([]byte) []byte) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, edit(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	flip := func(raw []byte) []byte {
		out := append([]byte(nil), raw...)
		out[len(out)/2] ^= 0x01
		return out
	}
	type failure struct {
		name   string
		layout string
		break_ func(t *testing.T, f *storeFixture)
		reason string
	}
	failures := []failure{
		{"tampered project target", cncfknowledge.LayoutPerProject, func(t *testing.T, f *storeFixture) {
			rewrite(t, admissionFile(t, f.store, filepath.Join("projects", "kubernetes.json")), flip)
		}, scanreport.KnowledgeDBIntegrity},
		{"missing project target", cncfknowledge.LayoutPerProject, func(t *testing.T, f *storeFixture) {
			if err := os.Remove(admissionFile(t, f.store, filepath.Join("projects", "kubernetes.json"))); err != nil {
				t.Fatal(err)
			}
		}, scanreport.KnowledgeDBIntegrity},
		{"tampered index", cncfknowledge.LayoutPerProject, func(t *testing.T, f *storeFixture) {
			rewrite(t, admissionFile(t, f.store, "target.json"), flip)
		}, scanreport.KnowledgeDBIntegrity},
		{"tampered single target", cncfknowledge.LayoutSingleTarget, func(t *testing.T, f *storeFixture) {
			rewrite(t, admissionFile(t, f.store, "target.json"), flip)
		}, scanreport.KnowledgeDBIntegrity},
		{"tampered trust receipt", cncfknowledge.LayoutPerProject, func(t *testing.T, f *storeFixture) {
			rewrite(t, admissionFile(t, f.store, "trust-receipt.json"), flip)
		}, scanreport.KnowledgeDBIntegrity},
		{"selection rolled back", cncfknowledge.LayoutPerProject, func(t *testing.T, f *storeFixture) {
			path := filepath.Join(f.store, "selection.json")
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f.importPack(nil, "6")
			rewrite(t, path, func([]byte) []byte { return old })
		}, scanreport.KnowledgeDBTrustAdvanced},
		{"single-target selection rolled back", cncfknowledge.LayoutSingleTarget, func(t *testing.T, f *storeFixture) {
			path := filepath.Join(f.store, "selection.json")
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f.importPack(nil, "6")
			rewrite(t, path, func([]byte) []byte { return old })
		}, scanreport.KnowledgeDBTrustAdvanced},
		{"clock rolled back", cncfknowledge.LayoutPerProject, func(t *testing.T, f *storeFixture) {
			future := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
			rewrite(t, filepath.Join(f.store, "clock-floor.json"), func([]byte) []byte {
				return []byte(`{"apiVersion":"prufyx.io/knowledge-clock-floor/v1","checkedAt":"` + future + "\"}\n")
			})
		}, scanreport.KnowledgeDBRollback},
		{"per-project store marked single-target", cncfknowledge.LayoutPerProject, func(t *testing.T, f *storeFixture) {
			other := newStoreFixture(t, cncfknowledge.LayoutSingleTarget)
			other.importPack(nil, "5")
			marker, err := os.ReadFile(filepath.Join(other.store, "profile.json"))
			if err != nil {
				t.Fatal(err)
			}
			rewrite(t, filepath.Join(f.store, "profile.json"), func([]byte) []byte { return marker })
		}, scanreport.KnowledgeDBIntegrity},
		{"single-target store marked per-project", cncfknowledge.LayoutSingleTarget, func(t *testing.T, f *storeFixture) {
			other := newStoreFixture(t, cncfknowledge.LayoutPerProject)
			other.importPack(nil, "5")
			marker, err := os.ReadFile(filepath.Join(other.store, "profile.json"))
			if err != nil {
				t.Fatal(err)
			}
			rewrite(t, filepath.Join(f.store, "profile.json"), func([]byte) []byte { return marker })
		}, scanreport.KnowledgeDBIntegrity},
	}
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	scanArgs := storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")
	check := func(t *testing.T, name, store, reason string) {
		t.Helper()
		inDir(t, dir, func() {
			result, err := scan(t, nil, append(scanArgs, "--knowledge-db", store)...)
			var storeErr *StoreError
			if err == nil || !errors.As(err, &storeErr) || !errors.Is(err, ErrIntegrity) || result.Exit != 0 || result.Report.Schema != "" {
				t.Fatalf("%s: err %v exit %d", name, err, result.Exit)
			}
			if reason != "" && storeErr.Reason != reason {
				t.Fatalf("%s: reason %q, want %q", name, storeErr.Reason, reason)
			}
			if strings.Contains(err.Error(), store) || !strings.Contains(err.Error(), "embedded knowledge was not used") {
				t.Fatalf("%s: message %q", name, err.Error())
			}
		})
	}
	for _, f := range failures {
		fixture := newStoreFixture(t, f.layout)
		fixture.importPack(nil, "5")
		f.break_(t, fixture)
		check(t, f.name, fixture.store, f.reason)
	}
	// A database with nothing imported has no verified selection.
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	check(t, "empty directory", empty, scanreport.KnowledgeDBNotAStore)
	// Refused before any lock: nothing is written into a directory that is
	// not a database.
	if entries, err := os.ReadDir(empty); err != nil || len(entries) != 0 {
		t.Fatalf("scan wrote into a directory that is not a database: %v %v", entries, err)
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	check(t, "unrelated directory", other, scanreport.KnowledgeDBNotAStore)
	if _, err := os.Lstat(filepath.Join(other, ".lock")); !os.IsNotExist(err) {
		t.Fatalf("scan created a lock in an unrelated directory: %v", err)
	}
	// A marked database with nothing selected yet.
	marked := newStoreFixture(t, cncfknowledge.LayoutPerProject)
	marked.importPack(nil, "5")
	profile, err := os.ReadFile(filepath.Join(marked.store, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	unselected := filepath.Join(t.TempDir(), "unselected")
	if err := os.Mkdir(unselected, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unselected, "profile.json"), profile, 0o600); err != nil {
		t.Fatal(err)
	}
	check(t, "marked database without a selection", unselected, scanreport.KnowledgeDBNoSelection)
	// Not private, or a symbolic link to a database.
	public := newStoreFixture(t, cncfknowledge.LayoutPerProject)
	public.importPack(nil, "5")
	if err := os.Chmod(public.store, 0o755); err != nil {
		t.Fatal(err)
	}
	check(t, "database readable by others", public.store, scanreport.KnowledgeDBNotPrivate)
	if err := os.Chmod(public.store, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(public.store, link); err != nil {
		t.Fatal(err)
	}
	check(t, "symbolic link to a database", link, scanreport.KnowledgeDBNotPrivate)
	// A path that does not exist is refused and not created.
	missing := filepath.Join(t.TempDir(), "missing")
	check(t, "missing database", missing, scanreport.KnowledgeDBMissing)
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("scan created the database directory: %v", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check(t, "database path is a file", file, scanreport.KnowledgeDBMissing)
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// TestScanStoreEvaluationIdentity: every evaluation must come from the
// database envelope opened for the project. An evaluation from another
// envelope, or from the embedded knowledge, is an integrity failure.
func TestScanStoreEvaluationIdentity(t *testing.T) {
	fixture := newStoreFixture(t, cncfknowledge.LayoutPerProject)
	fixture.importPack(nil, "5")
	store := openAt(t, fixture.store, testNow)
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	scanArgs := storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3")
	inDir(t, dir, func() {
		if result := mustScan(t, store, scanArgs...); result.Exit != scanreport.ExitBlocked {
			t.Fatalf("baseline exit %d", result.Exit)
		}
		otherDigest := *store
		otherDigest.digests = map[string]string{kubernetesSlug: store.digest}
		embeddedSnapshot := *store
		embeddedSnapshot.snapshot = embedded.ScanKnowledge
		embeddedSnapshot.digests = map[string]string{kubernetesSlug: embedded.PackDigest()}
		notOpened := *store
		notOpened.digests = map[string]string{}
		for name, k := range map[string]*Store{"other digest": &otherDigest, "embedded snapshot": &embeddedSnapshot, "project not opened": &notOpened} {
			if _, err := scan(t, k, scanArgs...); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})
}

// TestScanStoreRefusesOtherKnowledge: a caller that asks for a database and
// also supplies knowledge that does not come from one gets an integrity
// error, never an answer from the supplied knowledge.
func TestScanStoreRefusesOtherKnowledge(t *testing.T) {
	fixture := newStoreFixture(t, cncfknowledge.LayoutPerProject)
	fixture.importPack(nil, "5")
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	inDir(t, dir, func() {
		request, err := ParseArgs(storeArgs([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--knowledge-db", fixture.store))
		if err != nil {
			t.Fatal(err)
		}
		for name, k := range map[string]Knowledge{"embedded": nil, "test knowledge": newKnowledge(t, knowledgeOptions{})} {
			if name == "embedded" {
				embedded, err := LoadEmbedded()
				if err != nil {
					t.Fatal(err)
				}
				k = embedded
			}
			result, err := Run(request, Options{Knowledge: k, Build: &testBuild})
			if !errors.Is(err, ErrIntegrity) || result.Report.Schema != "" {
				t.Fatalf("%s: err %v exit %d", name, err, result.Exit)
			}
		}
		// Knowledge from a database is accepted with the flag.
		result, err := Run(request, Options{Knowledge: openAt(t, fixture.store, testNow), Build: &testBuild})
		if err != nil || result.Report.Provenance.KnowledgeStore == nil {
			t.Fatalf("store-backed knowledge refused: %v", err)
		}
	})
}
