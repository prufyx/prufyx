// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	depDir  = "charts/app"
	depRepo = "https://charts.example.org/api"
	depURL  = "https://charts.example.org/api/api-0.1.0.tgz"
	// otherGroup is a group the synthetic inventory does not have.
	otherGroup = "other.example.org"
	depLoc     = "dependency: api@0.1.0"
	depDecl    = "dependencies:\n- name: api\n  version: 0.1.0\n  repository: " + depRepo + "\n"
)

// groupCRD renders one served-and-stored v1 definition of a group.
func groupCRD(group, kind string, versions ...string) string {
	plural := strings.ToLower(kind) + "s"
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: %s.%s\nspec:\n  group: %s\n  names:\n    kind: %s\n    plural: %s\n  scope: Namespaced\n  versions:\n", plural, group, group, kind, plural)
	for i, v := range versions {
		name, off := strings.CutSuffix(v, ":off")
		fmt.Fprintf(&b, "  - name: %s\n    served: %v\n    storage: %v\n    schema:\n      openAPIV3Schema:\n        type: object\n", name, !off, i == len(versions)-1)
	}
	return b.String()
}

// tarItem is one entry of a test archive.
type tarItem struct {
	name, body, link string
	typ              byte
}

func buildTGZ(t *testing.T, items []tarItem) []byte {
	t.Helper()
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	tw := tar.NewWriter(zw)
	for _, it := range items {
		typ := it.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: it.name, Typeflag: typ, Mode: 0o644, Linkname: it.link}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(it.body))
		}
		if typ == tar.TypeDir {
			hdr.Mode = 0o755
		}
		must(t, tw.WriteHeader(hdr))
		if typ == tar.TypeReg {
			_, err := tw.Write([]byte(it.body))
			must(t, err)
		}
	}
	must(t, tw.Close())
	must(t, zw.Close())
	return raw.Bytes()
}

// chartTGZ builds the archive of chart name at version: a top directory, a
// Chart.yaml (unless files names one) and the files (paths below the top
// directory), then extra raw entries.
func chartTGZ(t *testing.T, name, version string, files map[string]string, extra ...tarItem) []byte {
	t.Helper()
	all := map[string]string{"Chart.yaml": "apiVersion: v2\nname: " + name + "\nversion: " + version + "\n"}
	for p, c := range files {
		all[p] = c
	}
	items := []tarItem{{name: name + "/", typ: tar.TypeDir}}
	paths := make([]string, 0, len(all))
	for p := range all {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		items = append(items, tarItem{name: name + "/" + p, body: all[p]})
	}
	return buildTGZ(t, append(items, extra...))
}

func apiTGZ(t *testing.T, files map[string]string, extra ...tarItem) []byte {
	return chartTGZ(t, "api", "0.1.0", files, extra...)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// depTarget is the synthetic target with the pin of archive.
func depTarget(archive []byte, attest bool) Target {
	tg := synthTarget()
	tg.Attest = attest
	tg.ChartDependencies = []ChartDependency{{
		Chart: depDir, Name: "api", Repository: depRepo,
		Reason:   "the packaged chart ships definitions of another project",
		Evidence: "a reviewer read the packaged chart: its definitions are copies or of another group",
		Pins:     []DependencyPin{{Version: "0.1.0", URL: depURL, SHA256: sha256Hex(archive)}},
	}}
	return tg
}

type fetcher struct {
	calls []string
	fn    func(url, digest string) ([]byte, error)
}

func (f *fetcher) Archive(_ context.Context, url, digest string) ([]byte, error) {
	f.calls = append(f.calls, url)
	return f.fn(url, digest)
}

// serving returns the fetcher that serves archive for any pin.
func serving(archive []byte) *fetcher {
	return &fetcher{fn: func(string, string) ([]byte, error) { return archive, nil }}
}

// never fails the test when called.
func never(t *testing.T) *fetcher {
	return &fetcher{fn: func(url, _ string) ([]byte, error) {
		t.Errorf("unexpected fetch of %s", url)
		return nil, errors.New("must not be fetched")
	}}
}

// depOutput runs the synthetic target over s; f nil means an extractor
// without an archive source.
func depOutput(t *testing.T, tg Target, s synthRepo, f *fetcher) *extract.Output {
	t.Helper()
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	x := New(tg)
	if f != nil {
		x.UseArchives(f)
	}
	out, err := extract.Run(context.Background(), x, s, s, extract.Options{Repo: repo, DerivedAt: derivedAt})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// depTree is the tree of one release: the listed definition, the chart that
// declares decl, and the extra files.
func depTree(decl string, extra map[string]string) map[string]string {
	files := map[string]string{
		"deploy/crds/a.yaml":      crd("Alpha", "v1"),
		depDir + "/Chart.yaml":    "apiVersion: v2\nname: app\nversion: 1.0.0\n" + decl,
		depDir + "/values.yaml":   "replicas: 1\n",
		depDir + "/templates/x.y": "x\n",
	}
	for p, c := range extra {
		files[p] = c
	}
	return files
}

// depPair runs the pair 1.0.0 -> 1.1.0 over trees that are alike.
func depPair(t *testing.T, tg Target, f *fetcher, extra map[string]string) (extract.PairRecord, PairProof, *extract.Output) {
	t.Helper()
	files := depTree(depDecl, extra)
	out := depOutput(t, tg, newSynth(release{"v1.0.0", files}, release{"v1.1.0", files}), f)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	return p, proof, out
}

func classOf(s *ScanRecord, class string) []Finding {
	var out []Finding
	for _, f := range s.Findings {
		if f.Class == class {
			out = append(out, f)
		}
	}
	return out
}

func filesOf(d DependencyRecord) map[string]DependencyFile {
	out := map[string]DependencyFile{}
	for _, f := range d.Files {
		out[f.Path] = f
	}
	return out
}

// A pinned dependency whose files are copies of the inventory or definitions
// of another group is read: the Chart.yaml is no longer external, the scan
// is clean, the pair attested, and the proof records what was fetched.
func TestChartDependencyPasses(t *testing.T) {
	archive := apiTGZ(t, map[string]string{
		"templates/crds/alpha.yaml": crd("Alpha", "v1"),
		"templates/crds/other.yaml": groupCRD(otherGroup, "Other", "v1"),
		"templates/rbac.yaml":       "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: x\nrules:\n- apiGroups: [\"apiregistration.k8s.io\"]\n  resources: [\"apiservices\"]\n  resourceNames: [\"v1." + otherGroup + "\"]\n",
		"values.yaml":               "image: x # mentions CustomResourceDefinition in a comment\n",
	})
	f := serving(archive)
	p, proof, out := depPair(t, depTarget(archive, true), f, nil)
	if p.Status != extract.PairDerived || p.Attestation == nil || p.Attestation.Status != extract.PairAttested || len(out.Attestations) != 1 {
		t.Fatalf("pair %s %q attestation %+v", p.Status, p.Reason, p.Attestation)
	}
	for _, s := range []*ScanRecord{proof.From.Scan, proof.To.Scan} {
		if !s.Clean() || len(s.Findings) != 0 {
			t.Fatalf("scan not clean: %+v", s.Findings)
		}
		if len(s.Dependencies) != 1 || !slices.Contains(s.NotRead, depNotRead) {
			t.Fatalf("dependencies %+v notRead %v", s.Dependencies, s.NotRead)
		}
		d := s.Dependencies[0]
		if d.Chart != depDir || d.Name != "api" || d.Repository != depRepo || d.Version != "0.1.0" || d.URL != depURL || d.SHA256 != sha256Hex(archive) || d.Problem != "" {
			t.Fatalf("record %+v", d)
		}
		files := filesOf(d)
		alpha, other := files["api/templates/crds/alpha.yaml"], files["api/templates/crds/other.yaml"]
		if alpha.Class != ClassCopy || !slices.Equal(alpha.CRDs, []string{"alphas." + synthGroup}) || len(alpha.Extra) != 0 {
			t.Fatalf("alpha %+v", alpha)
		}
		if other.Class != ClassExtra || !slices.Equal(other.Extra, []string{"others." + otherGroup}) || other.SHA256 == "" {
			t.Fatalf("other %+v", other)
		}
		if len(files) != 2 || !slices.Equal(d.APIServices, []string{"v1." + otherGroup}) {
			t.Fatalf("files %v services %v", files, d.APIServices)
		}
	}
	// One fetch serves every release.
	if len(f.calls) != 1 || f.calls[0] != depURL {
		t.Fatalf("fetches %v", f.calls)
	}
}

// Without a matching entry nothing changes: the dependency is external, and
// the archive is never fetched.
func TestChartDependencyUnmatchedStaysExternal(t *testing.T) {
	archive := apiTGZ(t, nil)
	cases := map[string]struct {
		mutate func(*Target)
		decl   string
	}{
		"no entry":         {func(tg *Target) { tg.ChartDependencies = nil }, depDecl},
		"another version":  {func(*Target) {}, "dependencies:\n- name: api\n  version: 0.1.1\n  repository: " + depRepo + "\n"},
		"a version range":  {func(*Target) {}, "dependencies:\n- name: api\n  version: \"^0.1.0\"\n  repository: " + depRepo + "\n"},
		"another name":     {func(*Target) {}, "dependencies:\n- name: apis\n  version: 0.1.0\n  repository: " + depRepo + "\n"},
		"a trailing slash": {func(*Target) {}, "dependencies:\n- name: api\n  version: 0.1.0\n  repository: " + depRepo + "/\n"},
		"another chart":    {func(tg *Target) { tg.ChartDependencies[0].Chart = "charts/other" }, depDecl},
		"an alias is read": {func(*Target) {}, "dependencies:\n- name: api\n  version: 0.1.0\n  repository: " + depRepo + "\n  alias: apis\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tg := depTarget(archive, true)
			tc.mutate(&tg)
			files := depTree(tc.decl, nil)
			f := serving(archive)
			if name != "an alias is read" {
				f = never(t)
			}
			out := depOutput(t, tg, newSynth(release{"v1.0.0", files}, release{"v1.1.0", files}), f)
			_, proof := pairOf(t, out, "1.0.0", "1.1.0")
			ext := classOf(proof.To.Scan, ClassExternal)
			if name == "an alias is read" {
				if len(ext) != 0 || !proof.To.Scan.Clean() {
					t.Fatalf("alias: %+v", proof.To.Scan.Findings)
				}
				return
			}
			if len(ext) != 1 || ext[0].Path != depDir+"/Chart.yaml" || proof.To.Scan.Clean() || len(proof.To.Scan.Dependencies) != 0 {
				t.Fatalf("findings %+v", proof.To.Scan.Findings)
			}
		})
	}
}

// A pinned dependency that also has unpinned remote ones leaves those
// external, and only those.
func TestChartDependencyPartlyPinned(t *testing.T) {
	archive := apiTGZ(t, nil)
	decl := depDecl + "- name: other\n  version: 1.0.0\n  repository: https://charts.example.org/other\n- name: local\n  version: 1.0.0\n  repository: \"\"\n"
	files := depTree(decl, nil)
	out := depOutput(t, depTarget(archive, true), newSynth(release{"v1.0.0", files}, release{"v1.1.0", files}), serving(archive))
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	ext := classOf(proof.To.Scan, ClassExternal)
	if len(ext) != 1 || !strings.Contains(ext[0].Detail, "other 1.0.0 from https://charts.example.org/other") || strings.Contains(ext[0].Detail, "api 0.1.0") || len(proof.To.Scan.Dependencies) != 1 {
		t.Fatalf("findings %+v", proof.To.Scan.Findings)
	}
}

const lockHead = "dependencies:\n"

// The Chart.lock beside the Chart.yaml must list the same remote
// dependencies: a different one keeps the Chart.yaml external and nothing is
// fetched; a lock that cannot be read is unread.
func TestChartDependencyLock(t *testing.T) {
	archive := apiTGZ(t, nil)
	api := "- name: api\n  repository: " + depRepo + "\n  version: 0.1.0\n"
	cases := []struct {
		name, lock string
		class      string // of the finding at the chart
		fetched    bool
	}{
		{"agrees", lockHead + api + "digest: sha256:x\ngenerated: \"2026-01-01T00:00:00Z\"\n", "", true},
		{"agrees with a local dependency", lockHead + api + "- name: grafana\n  repository: \"\"\n  version: 1.0.0\n", "", true},
		{"another version", lockHead + "- name: api\n  repository: " + depRepo + "\n  version: 0.1.1\n", ClassExternal, false},
		{"another repository", lockHead + "- name: api\n  repository: https://charts.example.org/api2\n  version: 0.1.0\n", ClassExternal, false},
		{"an extra remote dependency", lockHead + api + "- name: more\n  repository: https://charts.example.org/more\n  version: 1.0.0\n", ClassExternal, false},
		{"no dependencies", "digest: sha256:x\n", ClassExternal, false},
		{"not decodable", "dependencies: [\n", ClassUnread, false},
		{"an anchor", "x: &a 1\ny: *a\n" + lockHead + api, ClassUnread, false},
		{"not a mapping", "- a\n", ClassUnread, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := serving(archive)
			if !tc.fetched {
				f = never(t)
			}
			p, proof, _ := depPair(t, depTarget(archive, true), f, map[string]string{depDir + "/Chart.lock": tc.lock})
			if p.Status != extract.PairDerived {
				t.Fatalf("pair %s %q", p.Status, p.Reason)
			}
			s := proof.To.Scan
			if tc.class == "" {
				if !s.Clean() || len(s.Dependencies) != 1 {
					t.Fatalf("findings %+v", s.Findings)
				}
				return
			}
			if s.Clean() || len(classOf(s, tc.class)) == 0 || len(s.Dependencies) != 0 {
				t.Fatalf("want %s: %+v", tc.class, s.Findings)
			}
			if tc.class == ClassExternal && classOf(s, ClassExternal)[0].Path != depDir+"/Chart.yaml" {
				t.Fatalf("external at %+v", s.Findings)
			}
		})
	}
}

// A mismatching archive is unread, however it was served.
func TestChartDependencyDigestMismatch(t *testing.T) {
	archive := apiTGZ(t, nil)
	other := apiTGZ(t, map[string]string{"templates/crds/other.yaml": groupCRD(otherGroup, "Other", "v1")})
	p, proof, _ := depPair(t, depTarget(archive, true), serving(other), nil)
	s := proof.To.Scan
	un := classOf(s, ClassUnread)
	if p.Status != extract.PairDerived || s.Clean() || !s.Complete || len(un) != 1 || un[0].Location != depLoc || !strings.Contains(un[0].Detail, "does not hash to the pin") || len(classOf(s, ClassExternal)) != 0 {
		t.Fatalf("findings %+v", s.Findings)
	}
	if len(s.Dependencies) != 1 || s.Dependencies[0].Problem == "" || len(s.Dependencies[0].Files) != 0 {
		t.Fatalf("record %+v", s.Dependencies)
	}
	if a := p.Attestation; a == nil || a.Status != extract.PairNotAttested {
		t.Fatalf("attestation %+v", a)
	}
	// unread never withholds a pair or counts as an unreadable source.
	if len(s.unreadable()) != 0 || len(s.conflicts()) != 0 {
		t.Fatalf("withholding findings: %+v", s.unreadable())
	}
}

// What blocks: a definition of a group of the inventory that the inventory
// does not hold, a different copy, anything unread, and every other class.
func TestChartDependencyBlocking(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		class string
		extra []tarItem
	}{
		{"an extra definition in a group of the inventory", map[string]string{"templates/crds/beta.yaml": crd("Beta", "v1")}, ClassDependencyExtra, nil},
		{"a mixed file: one extra of the inventory group, one of another", map[string]string{"templates/crds/mixed.yaml": groupCRD(otherGroup, "Other", "v1") + "---\n" + crd("Zeta", "v1")}, ClassDependencyExtra, nil},
		{"a different copy", map[string]string{"templates/crds/alpha.yaml": crd("Alpha", "v1", "v2")}, ClassConflict, nil},
		{"a templated extra", map[string]string{"templates/crds/o.yaml": "{{- if .Values.x }}\n" + groupCRD(otherGroup, "Other", "v1") + "{{- end }}\n"}, ClassUnread, nil},
		{"an undecodable definition", map[string]string{"templates/crds/o.yaml": "kind: CustomResourceDefinition\n  bad: [\n"}, ClassUnread, nil},
		{"a nested remote dependency", map[string]string{"Chart.yaml": "apiVersion: v2\nname: api\nversion: 0.1.0\ndependencies:\n- name: deep\n  version: 1.0.0\n  repository: https://charts.example.org/deep\n"}, ClassExternal, nil},
		{"a reference", map[string]string{"templates/x.yaml": "kind: ConfigMap\ndata:\n  crd: |\n    kind: CustomResourceDefinition\n"}, ClassReference, nil},
		{"a kustomization", map[string]string{"kustomization.yaml": "resources:\n- a.yaml\n"}, ClassUnread, nil},
		{"a template source", map[string]string{"templates/_crd.tpl": "kind: CustomResourceDefinition\n"}, ClassUnsupported, nil},
		{"a packaged chart", map[string]string{"charts/deep-1.0.0.tgz": "x"}, ClassUnread, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := apiTGZ(t, tc.files, tc.extra...)
			p, proof, _ := depPair(t, depTarget(archive, true), serving(archive), nil)
			s := proof.To.Scan
			got := classOf(s, tc.class)
			if p.Status != extract.PairDerived || s.Clean() || len(got) == 0 {
				t.Fatalf("want %s: %+v", tc.class, s.Findings)
			}
			for _, f := range got {
				if f.Location != depLoc {
					t.Fatalf("location %q", f.Location)
				}
			}
			if a := p.Attestation; a == nil || a.Status != extract.PairNotAttested {
				t.Fatalf("attestation %+v", a)
			}
			// A dependency never withholds the pair.
			if len(s.conflicts()) != 0 || len(s.unreadable()) != 0 {
				t.Fatalf("withholding findings %+v %+v", s.conflicts(), s.unreadable())
			}
		})
	}
}

// A local subchart of the packaged chart is read like the rest of it.
func TestChartDependencyLocalSubchart(t *testing.T) {
	sub := "charts/sub/templates/crds/"
	for name, tc := range map[string]struct {
		def  string
		pass bool
	}{
		"another group":            {groupCRD(otherGroup, "Other", "v1"), true},
		"a group of the inventory": {crd("Beta", "v1"), false},
	} {
		t.Run(name, func(t *testing.T) {
			archive := apiTGZ(t, map[string]string{
				"charts/sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n",
				sub + "x.yaml":          tc.def,
			})
			_, proof, _ := depPair(t, depTarget(archive, true), serving(archive), nil)
			if got := proof.To.Scan.Clean(); got != tc.pass {
				t.Fatalf("clean=%v: %+v", got, proof.To.Scan.Findings)
			}
			if _, ok := filesOf(proof.To.Scan.Dependencies[0])["api/"+sub+"x.yaml"]; !ok {
				t.Fatalf("record %+v", proof.To.Scan.Dependencies[0].Files)
			}
		})
	}
}

// An API service of a group of the inventory blocks, named in a manifest or
// in the resourceNames of an RBAC rule; one of another group does not.
func TestChartDependencyAPIService(t *testing.T) {
	rbac := func(name string) string {
		return "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: x\nrules:\n- apiGroups: [\"apiregistration.k8s.io\"]\n  resources: [\"apiservices\"]\n  resourceNames: [\"" + name + "\"]\n"
	}
	manifest := func(name string) string {
		return "apiVersion: apiregistration.k8s.io/v1\nkind: APIService\nmetadata:\n  name: " + name + "\nspec:\n  group: x\n  version: v1\n"
	}
	cases := []struct {
		name, file string
		blocks     bool
	}{
		{"rbac resourceNames", rbac("v1." + synthGroup), true},
		{"a manifest", manifest("v1alpha1." + synthGroup), true},
		{"a templated manifest", "{{- if .Values.x }}\n" + manifest("v1beta1."+synthGroup) + "{{- end }}\n", true},
		{"another group, rbac", rbac("v1." + otherGroup), false},
		{"another group, a manifest", manifest("v1." + otherGroup), false},
		{"a longer group", rbac("v1.x." + synthGroup + ".evil"), false},
		{"a version number", rbac("v1.2.3"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := apiTGZ(t, map[string]string{"templates/aggregated.yaml": tc.file})
			_, proof, _ := depPair(t, depTarget(archive, true), serving(archive), nil)
			s := proof.To.Scan
			got := classOf(s, ClassDependencyAPIService)
			if tc.blocks {
				if len(got) != 1 || got[0].Location != depLoc || got[0].Path != depDir+"/Chart.yaml" || s.Clean() {
					t.Fatalf("findings %+v", s.Findings)
				}
				return
			}
			if len(got) != 0 || !s.Clean() || !slices.Contains(s.NotRead, depNotRead) {
				t.Fatalf("findings %+v", s.Findings)
			}
		})
	}
}

// The identity of the unpacked chart must be the pinned one.
func TestChartDependencyIdentity(t *testing.T) {
	cases := map[string][]byte{
		"another name":       chartTGZ(t, "api", "0.1.0", map[string]string{"Chart.yaml": "apiVersion: v2\nname: apis\nversion: 0.1.0\n"}),
		"another version":    chartTGZ(t, "api", "0.1.0", map[string]string{"Chart.yaml": "apiVersion: v2\nname: api\nversion: 0.1.1\n"}),
		"a numeric version":  chartTGZ(t, "api", "0.1.0", map[string]string{"Chart.yaml": "apiVersion: v2\nname: api\nversion: 0.1\n"}),
		"an undecodable one": chartTGZ(t, "api", "0.1.0", map[string]string{"Chart.yaml": "name: [\n"}),
		"two documents":      chartTGZ(t, "api", "0.1.0", map[string]string{"Chart.yaml": "name: api\nversion: 0.1.0\n---\nname: api\nversion: 0.1.0\n"}),
		"another top directory": buildTGZ(t, []tarItem{
			{name: "other/", typ: tar.TypeDir}, {name: "other/Chart.yaml", body: "apiVersion: v2\nname: api\nversion: 0.1.0\n"},
		}),
		"no Chart.yaml": buildTGZ(t, []tarItem{{name: "api/", typ: tar.TypeDir}, {name: "api/values.yaml", body: "a: 1\n"}}),
	}
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			_, proof, _ := depPair(t, depTarget(archive, true), serving(archive), nil)
			un := classOf(proof.To.Scan, ClassUnread)
			if proof.To.Scan.Clean() || len(un) != 1 || un[0].Location != depLoc {
				t.Fatalf("findings %+v", proof.To.Scan.Findings)
			}
		})
	}
}

// An archive outside the bounds or of an unsafe shape is unread.
func TestChartDependencyArchiveShapes(t *testing.T) {
	ok := "apiVersion: v2\nname: api\nversion: 0.1.0\n"
	top := []tarItem{{name: "api/", typ: tar.TypeDir}, {name: "api/Chart.yaml", body: ok}}
	with := func(extra ...tarItem) []tarItem { return append(slices.Clone(top), extra...) }
	many := make([]tarItem, 0, maxDepEntries)
	for i := 0; i < maxDepEntries; i++ {
		many = append(many, tarItem{name: fmt.Sprintf("api/f%d", i)})
	}
	var names strings.Builder
	for i := 0; i <= maxDepServices; i++ {
		fmt.Fprintf(&names, "v1.a%d.example.org\n", i)
	}
	cases := map[string]struct {
		items []tarItem
		raw   []byte
		want  string
	}{
		"too many API service names": {items: with(tarItem{name: "api/names.txt", body: names.String()}), want: "API services"},
		"a symbolic link":            {items: with(tarItem{name: "api/link", typ: tar.TypeSymlink, link: "/etc/passwd"}), want: "neither a regular file"},
		"a hard link":                {items: with(tarItem{name: "api/link", typ: tar.TypeLink, link: "api/Chart.yaml"}), want: "neither a regular file"},
		"a device":                   {items: with(tarItem{name: "api/dev", typ: tar.TypeChar}), want: "neither a regular file"},
		"a parent path":              {items: with(tarItem{name: "api/../x", body: "x"}), want: "clean relative path"},
		"an absolute path":           {items: with(tarItem{name: "/api/x", body: "x"}), want: "clean relative path"},
		"an unclean path":            {items: with(tarItem{name: "api//x", body: "x"}), want: "clean relative path"},
		"a backslash":                {items: with(tarItem{name: "api/a\\b", body: "x"}), want: "clean relative path"},
		"outside the top":            {items: with(tarItem{name: "elsewhere/x", body: "x"}), want: "outside the one top directory"},
		"a file of the name":         {items: []tarItem{{name: "api", body: "x"}}, want: "outside the one top directory"},
		"the same path twice":        {items: with(tarItem{name: "api/x", body: "1"}, tarItem{name: "api/x", body: "2"}), want: "twice"},
		"a file below a file":        {items: with(tarItem{name: "api/x", body: "1"}, tarItem{name: "api/x/y", body: "2"}), want: "below a file"},
		"too many entries":           {items: append(slices.Clone(top), many...), want: "more than"},
		"over the unpacked bound":    {items: with(tarItem{name: "api/big", body: strings.Repeat("a", maxDepUnpackedBytes+1)}), want: "unpacks to more than"},
		"not gzip":                   {raw: []byte("plain"), want: "not gzip"},
		"not tar":                    {raw: gz(t, []byte("not a tar file at all, long enough to be read as a header block")), want: "not a readable tar"},
		"empty":                      {items: []tarItem{}, want: "no file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := tc.raw
			if raw == nil {
				raw = buildTGZ(t, tc.items)
			}
			da := readDependencyArchive("api", "0.1.0", raw)
			if !strings.Contains(da.unread, tc.want) || len(da.files) != 0 {
				t.Fatalf("unread %q files %d, want %q", da.unread, len(da.files), tc.want)
			}
			// End to end: unread, never a pass.
			_, proof, _ := depPair(t, depTarget(raw, true), serving(raw), nil)
			if proof.To.Scan.Clean() || len(classOf(proof.To.Scan, ClassUnread)) != 1 {
				t.Fatalf("findings %+v", proof.To.Scan.Findings)
			}
		})
	}
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	_, err := zw.Write(b)
	must(t, err)
	must(t, zw.Close())
	return raw.Bytes()
}

// A fetch that cannot be made, or made without a source, leaves the scan
// incomplete: no finding, no pass, and no further fetch is tried.
func TestChartDependencyIncomplete(t *testing.T) {
	archive := apiTGZ(t, nil)
	budget := errors.New("GitHub REST budget exhausted: the cap of 5 REST requests for this run is used up")
	cases := map[string]struct {
		f    func() *fetcher
		want string
	}{
		"no archive source": {func() *fetcher { return nil }, "no archive source is configured"},
		"a fetch error": {func() *fetcher {
			return &fetcher{fn: func(string, string) ([]byte, error) { return nil, errors.New("connection refused") }}
		}, "connection refused"},
		"the budget is used up": {func() *fetcher {
			return &fetcher{fn: func(string, string) ([]byte, error) { return nil, fmt.Errorf("fetching: %w", budget) }}
		}, "budget exhausted"},
		"an archive over the bound": {func() *fetcher {
			return &fetcher{fn: func(string, string) ([]byte, error) { return make([]byte, maxDepArchiveBytes+1), nil }}
		}, "over the"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := tc.f()
			p, proof, out := depPair(t, depTarget(archive, true), f, nil)
			s := proof.To.Scan
			if s.Complete || s.Clean() || !strings.Contains(s.Problem, tc.want) || len(s.Dependencies) != 0 {
				t.Fatalf("scan complete=%v problem=%q findings %+v", s.Complete, s.Problem, s.Findings)
			}
			if len(classOf(s, ClassUnread)) != 0 || len(classOf(s, ClassDependencyExtra)) != 0 {
				t.Fatalf("a finding for an incomplete scan: %+v", s.Findings)
			}
			if a := p.Attestation; a == nil || a.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
				t.Fatalf("attestation %+v", a)
			}
			if f != nil && len(f.calls) != 1 {
				t.Fatalf("after a failure %d fetches were tried: %v", len(f.calls), f.calls)
			}
		})
	}
}

// A cancelled context stops the run with the context's error, and is not
// remembered as a failed fetch.
func TestChartDependencyCancelled(t *testing.T) {
	archive := apiTGZ(t, nil)
	tg := depTarget(archive, true)
	ctx, cancel := context.WithCancel(context.Background())
	f := &fetcher{fn: func(string, string) ([]byte, error) { cancel(); return nil, context.Canceled }}
	files := depTree(depDecl, nil)
	s := newSynth(release{"v1.0.0", files}, release{"v1.1.0", files})
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	x := New(tg)
	x.UseArchives(f)
	if _, err = extract.Run(ctx, x, s, s, extract.Options{Repo: repo, DerivedAt: derivedAt}); err == nil {
		t.Fatal("no error")
	}
	if x.depProblem != "" || len(f.calls) != 1 {
		t.Fatalf("a cancelled fetch was recorded as a problem: %q (%d fetches)", x.depProblem, len(f.calls))
	}
}

// B2: a definition a dependency ships at one release, in a group the
// inventory of that release does not have but another release of the pair
// does, passes the single-release check and refuses the attestation.
func TestChartDependencyGroupOfAnotherRelease(t *testing.T) {
	delta := groupCRD(otherGroup, "Delta", "v1")
	archive := apiTGZ(t, map[string]string{"templates/crds/delta.yaml": delta})
	tg := depTarget(archive, true)
	earlier := depTree(depDecl, nil)
	later := depTree(depDecl, map[string]string{"deploy/crds/delta.yaml": delta})
	out := depOutput(t, tg, newSynth(release{"v1.0.0", earlier}, release{"v1.1.0", later}), serving(archive))
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || !proof.From.Scan.Clean() || !proof.To.Scan.Clean() || !proof.Completeness.Attestable {
		t.Fatalf("pair %s %q completeness %+v from %+v", p.Status, p.Reason, proof.Completeness, proof.From.Scan.Findings)
	}
	a := p.Attestation
	if a == nil || a.Status != extract.PairNotAttested || !strings.Contains(a.Reason, "api@0.1.0") || !strings.Contains(a.Reason, "deltas."+otherGroup) || len(out.Attestations) != 0 {
		t.Fatalf("attestation %+v", a)
	}
	// The same names of a group the inventory has at no release pass.
	archive = apiTGZ(t, map[string]string{"templates/crds/delta.yaml": groupCRD("elsewhere.example.net", "Delta", "v1")})
	out = depOutput(t, depTarget(archive, true), newSynth(release{"v1.0.0", earlier}, release{"v1.1.0", later}), serving(archive))
	if a := pairAttestation(t, out, "1.0.0", "1.1.0"); a.Status != extract.PairAttested {
		t.Fatalf("attestation %+v", a)
	}
}

// The same check for the API services a dependency names.
func TestDependencyGroupConflictAPIService(t *testing.T) {
	state := func(tag, group string, deps ...DependencyRecord) *tagState {
		return &tagState{tag: extract.Tag{Name: tag}, inv: &Inventory{Complete: true, CRDs: []CRD{{Name: "xs." + group, Group: group}}}, scan: &ScanRecord{Dependencies: deps}}
	}
	dep := DependencyRecord{Name: "api", Version: "0.1.0", APIServices: []string{"v1.late.example.org"}}
	if why := dependencyGroupConflict([]*tagState{state("v1.0.0", "early.example.org", dep), state("v1.1.0", "late.example.org")}); !strings.Contains(why, "API service v1.late.example.org") || !strings.Contains(why, "v1.0.0") {
		t.Fatalf("reason %q", why)
	}
	if why := dependencyGroupConflict([]*tagState{state("v1.0.0", "early.example.org", dep), state("v1.1.0", "early.example.org")}); why != "" {
		t.Fatalf("reason %q", why)
	}
	// An incomplete release has no inventory to count.
	bad := state("v1.1.0", "late.example.org")
	bad.inv.Complete = false
	if why := dependencyGroupConflict([]*tagState{state("v1.0.0", "early.example.org", dep), bad}); why != "" {
		t.Fatalf("reason %q", why)
	}
}

// A definition that leaves the listed paths and is shipped by a dependency
// is not taken for gone.
func TestChartDependencyDefinitionMoved(t *testing.T) {
	delta := groupCRD(otherGroup, "Delta", "v1")
	archive := apiTGZ(t, map[string]string{"templates/crds/delta.yaml": delta})
	tg := depTarget(archive, true)
	withDelta := depTree(depDecl, map[string]string{"deploy/crds/delta.yaml": delta})
	without := depTree(depDecl, nil)
	out := depOutput(t, tg, newSynth(release{"v1.0.0", withDelta}, release{"v1.1.0", withDelta}, release{"v1.1.1", without}), serving(archive))
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || len(proof.DefinitionsRemoved) != 0 {
		t.Fatalf("pair %s %q removed %+v", p.Status, p.Reason, proof.DefinitionsRemoved)
	}
	if a := p.Attestation; a == nil || a.Status != extract.PairNotAttested {
		t.Fatalf("attestation %+v", a)
	}
}

// The target without the member is unchanged: its scan records no
// dependency and its not-read list is the package's.
func TestNoChartDependenciesNoRecord(t *testing.T) {
	files := depTree(depDecl, nil)
	out := depOutput(t, synthTarget(), newSynth(release{"v1.0.0", files}, release{"v1.1.0", files}), nil)
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	s := proof.To.Scan
	if s.Dependencies != nil || !slices.Equal(s.NotRead, NotRead) || len(classOf(s, ClassExternal)) != 1 {
		t.Fatalf("scan %+v", s)
	}
}

// The shape of Kyverno's chart: three remote dependencies (one with a
// trailing slash in its repository), two local ones. The URLs and names are
// the real ones; the archives are built here.
func TestChartDependencyKyvernoShape(t *testing.T) {
	const (
		apiRepo  = "https://kyverno.github.io/api"
		repoRepo = "https://openreports.github.io/reports-api"
		rsRepo   = "https://kyverno.github.io/reports-server/"
	)
	policies := func(kinds ...string) map[string]string {
		out := map[string]string{}
		for _, k := range kinds {
			out["templates/crds/policies.kyverno.io_"+strings.ToLower(k)+"s.yaml"] = groupCRD("policies.kyverno.io", k, "v1")
		}
		return out
	}
	rbac := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: reports-server\nrules:\n- apiGroups: [\"apiregistration.k8s.io\"]\n  resources: [\"apiservices\"]\n  resourceNames: [\"v1.reports.kyverno.io\", \"v1alpha2.wgpolicyk8s.io\", \"v1alpha1.openreports.io\"]\n  verbs: [\"get\"]\n"
	kyvernoAPI := chartTGZ(t, "kyverno-api", "0.0.1-alpha.2", policies("ValidatingPolicy", "MutatingPolicy", "ImageValidatingPolicy"))
	openreports := chartTGZ(t, "openreports", "0.1.0", map[string]string{"templates/openreports.io_reports.yaml": groupCRD("openreports.io", "Report", "v1alpha1"), "templates/openreports.io_clusterreports.yaml": groupCRD("openreports.io", "ClusterReport", "v1alpha1")})
	reportsServer := chartTGZ(t, "reports-server", "0.1.6", map[string]string{
		"templates/cluster-roles.yaml": rbac, "charts/postgresql/Chart.yaml": "apiVersion: v2\nname: postgresql\nversion: 1.0.0\n", "charts/postgresql/templates/sts.yaml": "kind: StatefulSet\n",
	})
	archives := map[string][]byte{
		"https://kyverno.github.io/api/kyverno-api-0.0.1-alpha.2.tgz":       kyvernoAPI,
		"https://openreports.github.io/reports-api/openreports-0.1.0.tgz":   openreports,
		"https://kyverno.github.io/reports-server/reports-server-0.1.6.tgz": reportsServer,
	}
	tg := synthTarget()
	tg.Paths = []PathSpec{{Path: "config/crds", Dir: true, Recursive: true, Match: regexp.MustCompile(`^[^.][^/]*\.ya?ml$`), Guard: regexp.MustCompile(`(?i)crd`)}}
	tg.ChartDependencies = []ChartDependency{
		{Chart: "charts/kyverno", Name: "kyverno-api", Repository: apiRepo, Reason: "the packaged chart ships the policies definitions", Evidence: "a reviewer read the packaged chart: its definitions are copies of config/crds", Pins: []DependencyPin{{Version: "0.0.1-alpha.2", URL: "https://kyverno.github.io/api/kyverno-api-0.0.1-alpha.2.tgz", SHA256: sha256Hex(kyvernoAPI)}}},
		{Chart: "charts/kyverno", Name: "openreports", Repository: repoRepo, Reason: "the packaged chart ships the report definitions", Evidence: "a reviewer read the packaged chart: its definitions are of the openreports.io group", Pins: []DependencyPin{{Version: "0.1.0", URL: "https://openreports.github.io/reports-api/openreports-0.1.0.tgz", SHA256: sha256Hex(openreports)}}},
		{Chart: "charts/kyverno", Name: "reports-server", Repository: rsRepo, Reason: "the packaged chart ships no definitions", Evidence: "a reviewer read the packaged chart: it deploys a server that registers API services at run time", Pins: []DependencyPin{{Version: "0.1.6", URL: "https://kyverno.github.io/reports-server/reports-server-0.1.6.tgz", SHA256: sha256Hex(reportsServer)}}},
	}
	chart := "apiVersion: v2\nname: kyverno\nversion: 3.0.0\ndependencies:\n" +
		"- name: grafana\n  version: 0.0.1\n  repository: \"\"\n  condition: grafana.enabled\n" +
		"- name: crds\n  version: 0.0.1\n  repository: \"\"\n" +
		"- name: kyverno-api\n  version: 0.0.1-alpha.2\n  repository: " + apiRepo + "\n  condition: crds.install\n" +
		"- name: openreports\n  version: 0.1.0\n  repository: " + repoRepo + "\n  condition: openreports.enabled\n" +
		"- name: reports-server\n  version: 0.1.6\n  repository: " + rsRepo + "\n  condition: reportsServer.enabled\n"
	lock := "dependencies:\n- name: kyverno-api\n  repository: " + apiRepo + "\n  version: 0.0.1-alpha.2\n- name: openreports\n  repository: " + repoRepo + "\n  version: 0.1.0\n- name: reports-server\n  repository: " + rsRepo + "\n  version: 0.1.6\n- name: grafana\n  repository: \"\"\n  version: 0.0.1\ndigest: sha256:abc\n"
	tree := func(policyKinds ...string) map[string]string {
		files := map[string]string{
			"charts/kyverno/Chart.yaml": chart, "charts/kyverno/Chart.lock": lock,
			"config/crds/kyverno/clusterpolicies.yaml":             groupCRD("kyverno.io", "ClusterPolicy", "v1"),
			"config/crds/wgpolicyk8s.io/policyreports.yaml":        groupCRD("wgpolicyk8s.io", "PolicyReport", "v1alpha2"),
			"config/crds/reports.kyverno.io/ephemeralreports.yaml": groupCRD("reports.kyverno.io", "EphemeralReport", "v1"),
		}
		for _, k := range policyKinds {
			files["config/crds/policies.kyverno.io/"+strings.ToLower(k)+"s.yaml"] = groupCRD("policies.kyverno.io", k, "v1")
		}
		return files
	}
	f := &fetcher{fn: func(url, _ string) ([]byte, error) {
		if a, ok := archives[url]; ok {
			return a, nil
		}
		return nil, fmt.Errorf("unexpected %s", url)
	}}
	out := depOutput(t, tg, newSynth(
		release{"v1.16.0", tree("ValidatingPolicy", "MutatingPolicy")},
		release{"v1.17.0", tree("ValidatingPolicy", "MutatingPolicy", "ImageValidatingPolicy")},
	), f)
	p, proof := pairOf(t, out, "1.16.0", "1.17.0")
	if p.Status != extract.PairDerived || len(f.calls) != 3 {
		t.Fatalf("pair %s %q fetches %v", p.Status, p.Reason, f.calls)
	}
	var classes []string
	for _, tag := range []struct {
		scan *ScanRecord
		want []string
	}{
		{proof.From.Scan, []string{"dependency-apiservice dependency: reports-server@0.1.6", "dependency-extra dependency: kyverno-api@0.0.1-alpha.2"}},
		{proof.To.Scan, []string{"dependency-apiservice dependency: reports-server@0.1.6"}},
	} {
		classes = classes[:0]
		for _, fd := range tag.scan.Findings {
			classes = append(classes, fd.Class+" "+fd.Location)
		}
		sort.Strings(classes)
		if !slices.Equal(classes, tag.want) {
			t.Fatalf("findings %v, want %v", classes, tag.want)
		}
		var names []string
		for _, d := range tag.scan.Dependencies {
			names = append(names, d.Name+"@"+d.Version)
		}
		if !slices.Equal(names, []string{"kyverno-api@0.0.1-alpha.2", "openreports@0.1.0", "reports-server@0.1.6"}) {
			t.Fatalf("dependencies %v", names)
		}
		// openreports.io is no group of the inventory: its definitions pass.
		for _, d := range tag.scan.Dependencies {
			if d.Name == "openreports" {
				for _, f := range d.Files {
					if f.Class != ClassExtra || len(f.Extra) != 1 {
						t.Fatalf("openreports file %+v", f)
					}
				}
			}
			if d.Name == "reports-server" && !slices.Equal(d.APIServices, []string{"v1.reports.kyverno.io", "v1alpha1.openreports.io", "v1alpha2.wgpolicyk8s.io"}) {
				t.Fatalf("services %v", d.APIServices)
			}
		}
		if len(classOf(tag.scan, ClassExternal)) != 0 {
			t.Fatalf("external: %+v", tag.scan.Findings)
		}
	}
	if a := p.Attestation; a == nil || a.Status != extract.PairNotAttested {
		t.Fatalf("attestation %+v", a)
	}
}

// The loader keeps the member to exact, reviewed https pins.
func TestChartDependenciesLoader(t *testing.T) {
	const (
		sum    = "67451c17e2be1e6f09af447c9f1f7e74d0ee60ef19fa8fee89323675a545e25e"
		reason = `"reason":"the packaged chart ships definitions of the project","evidence":"a reviewer read the packaged chart and every definition in it"`
	)
	pin := func(version, url, digest string) string {
		return fmt.Sprintf(`{"version":%q,"url":%q,"sha256":%q}`, version, url, digest)
	}
	entry := func(chart, name, repo string, pins ...string) string {
		return fmt.Sprintf(`{"chart":%q,"name":%q,"repository":%q,%s,"pins":[%s]}`, chart, name, repo, reason, strings.Join(pins, ","))
	}
	load := func(entries ...string) (Target, error) {
		raw := strings.Replace(string(testTargetsJSON("")), `"exclude":[]`, `"exclude":[],"chartDependencies":[`+strings.Join(entries, ",")+`]`, 1)
		return LoadTarget("target-p.json", []byte(raw))
	}
	const apiRepo, apiURL = "https://kyverno.github.io/api", "https://kyverno.github.io/api/kyverno-api-0.0.1-alpha.2.tgz"
	good := entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1-alpha.2", apiURL, sum))
	tg, err := load(good, entry("charts/kyverno", "reports-server", "https://kyverno.github.io/reports-server/", pin("0.1.6", "https://kyverno.github.io/reports-server/reports-server-0.1.6.tgz", sum)))
	if err != nil || len(tg.ChartDependencies) != 2 || tg.ChartDependencies[1].Repository != "https://kyverno.github.io/reports-server/" || tg.ChartDependencies[0].Pins[0].Version != "0.0.1-alpha.2" {
		t.Fatalf("%v %+v", err, tg.ChartDependencies)
	}
	// Without the member nothing changes.
	if tg, err := LoadTarget("target-p.json", testTargetsJSON("")); err != nil || tg.ChartDependencies != nil {
		t.Fatalf("%v %+v", err, tg.ChartDependencies)
	}
	badSum := strings.Repeat("g", 64)
	cases := map[string]struct {
		entries []string
		want    string
	}{
		"a caret range":           {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("^0.0.1", apiURL, sum))}, "exact version"},
		"a tilde range":           {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("~0.0.1", apiURL, sum))}, "exact version"},
		"a comparison":            {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin(">=0.0.1", apiURL, sum))}, "exact version"},
		"a wildcard":              {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.x", apiURL, sum))}, "exact version"},
		"two parts":               {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.1", apiURL, sum))}, "exact version"},
		"an or":                   {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1 || 0.0.2", apiURL, sum))}, "exact version"},
		"a leading v":             {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("v0.0.1", apiURL, sum))}, "exact version"},
		"build metadata":          {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1+b", apiURL, sum))}, "exact version"},
		"an oci repository":       {[]string{entry("charts/kyverno", "kyverno-api", "oci://ghcr.io/kyverno", pin("0.0.1", "https://ghcr.io/x.tgz", sum))}, "oci://"},
		"an http repository":      {[]string{entry("charts/kyverno", "kyverno-api", "http://kyverno.github.io/api", pin("0.0.1", apiURL, sum))}, "https"},
		"a query":                 {[]string{entry("charts/kyverno", "kyverno-api", apiRepo+"?x=1", pin("0.0.1", apiURL, sum))}, "credentials, a query"},
		"credentials":             {[]string{entry("charts/kyverno", "kyverno-api", "https://u:p@kyverno.github.io/api", pin("0.0.1", apiURL, sum))}, "credentials"},
		"an upper-case host":      {[]string{entry("charts/kyverno", "kyverno-api", "https://Kyverno.github.io/api", pin("0.0.1", apiURL, sum))}, "lower-case host"},
		"a url on another host":   {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", "https://evil.example.org/kyverno-api-0.0.1.tgz", sum))}, "host of the repository"},
		"a url that is not a tgz": {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", "https://kyverno.github.io/api/index.yaml", sum))}, ".tgz"},
		"an http url":             {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", "http://kyverno.github.io/api/a.tgz", sum))}, "https"},
		"a bad digest":            {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", apiURL, badSum))}, "sha256"},
		"an upper-case digest":    {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", apiURL, strings.ToUpper(sum)))}, "sha256"},
		"a short digest":          {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", apiURL, sum[:63]))}, "sha256"},
		"unsorted pins":           {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.2", apiURL, sum), pin("0.0.1", apiURL, sum))}, "not sorted"},
		"a duplicate pin":         {[]string{entry("charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", apiURL, sum), pin("0.0.1", apiURL, sum))}, "twice"},
		"no pin":                  {[]string{entry("charts/kyverno", "kyverno-api", apiRepo)}, "pins are required"},
		"a parent chart":          {[]string{entry("../kyverno", "kyverno-api", apiRepo, pin("0.0.1", apiURL, sum))}, "clean repository directory"},
		"an absolute chart":       {[]string{entry("/charts/kyverno", "kyverno-api", apiRepo, pin("0.0.1", apiURL, sum))}, "clean repository directory"},
		"a dot chart":             {[]string{entry(".", "kyverno-api", apiRepo, pin("0.0.1", apiURL, sum))}, "clean repository directory"},
		"a bad name":              {[]string{entry("charts/kyverno", "kyverno api", apiRepo, pin("0.0.1", apiURL, sum))}, "name"},
		"unsorted entries":        {[]string{entry("charts/kyverno", "z", apiRepo, pin("0.0.1", apiURL, sum)), entry("charts/kyverno", "a", apiRepo, pin("0.0.1", apiURL, sum))}, "not sorted"},
		"a duplicate entry":       {[]string{good, good}, "not sorted"},
		"no reason":               {[]string{`{"chart":"charts/kyverno","name":"a","repository":"` + apiRepo + `","evidence":"a reviewer read the packaged chart and every definition in it","pins":[` + pin("0.0.1", apiURL, sum) + `]}`}, "reason"},
		"an unknown member":       {[]string{strings.Replace(good, `"pins"`, `"x":1,"pins"`, 1)}, "unknown field"},
	}
	for name, tc := range cases {
		if _, err := load(tc.entries...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	many := make([]string, 0, maxChartDeps+1)
	for i := 0; i <= maxChartDeps; i++ {
		many = append(many, entry("charts/kyverno", fmt.Sprintf("a%02d", i), apiRepo, pin("0.0.1", apiURL, sum)))
	}
	if _, err := load(many...); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("many entries: %v", err)
	}
}
