package targetdraft

import (
	"bytes"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

const (
	roGroup = "kueue.x-k8s.io"
	roSlug  = "kueue"
	roRepo  = "kubernetes-sigs/kueue"
)

func roRecords() []customresources.ReservedGroup {
	return []customresources.ReservedGroup{
		{Name: "a.x-k8s.io", Owner: "a", Repository: "https://github.com/sigs/a", Reason: "r"},
		{Name: "b.x-k8s.io", Owner: "b", Repository: "https://github.com/sigs/b", Reason: "r"},
	}
}

func TestOwnsReservedExactRecordOnly(t *testing.T) {
	rec := roRecords()
	if !ownsReserved(rec, "a.x-k8s.io", "a", "sigs/a") {
		t.Fatal("exact owner and repository must be accepted")
	}
	for name, c := range map[string][4]string{
		"carrier slug":          {"a.x-k8s.io", "b", "sigs/a"},
		"other slug":            {"a.x-k8s.io", "A", "sigs/a"},
		"other repository":      {"a.x-k8s.io", "a", "sigs/b"},
		"fork repository":       {"a.x-k8s.io", "a", "fork/a"},
		"case variant":          {"a.x-k8s.io", "a", "Sigs/a"},
		"trailing dot":          {"a.x-k8s.io", "a", "sigs/a."},
		"dot git":               {"a.x-k8s.io", "a", "sigs/a.git"},
		"trailing slash":        {"a.x-k8s.io", "a", "sigs/a/"},
		"host prefixed":         {"a.x-k8s.io", "a", "github.com/sigs/a"},
		"ssh spelling":          {"a.x-k8s.io", "a", "git@github.com:sigs/a"},
		"no record for group":   {"c.x-k8s.io", "a", "sigs/a"},
		"record of other group": {"b.x-k8s.io", "a", "sigs/a"},
		"subgroup of record":    {"x.a.x-k8s.io", "a", "sigs/a"},
		"empty group":           {"", "a", "sigs/a"},
		"empty slug":            {"a.x-k8s.io", "", "sigs/a"},
		"empty repository":      {"a.x-k8s.io", "a", ""},
	} {
		if ownsReserved(rec, c[0], c[1], c[2]) {
			t.Errorf("%s accepted", name)
		}
	}
	if ownsReserved(nil, "a.x-k8s.io", "a", "sigs/a") {
		t.Error("no records accepted")
	}
	// The record's own repository spelling must be the exact URL.
	rec[0].Repository = "https://github.com/Sigs/a"
	if ownsReserved(rec, "a.x-k8s.io", "a", "sigs/a") {
		t.Error("record with a case-variant repository accepted")
	}
	rec[0].Repository = "https://github.com/sigs/a.git"
	if ownsReserved(rec, "a.x-k8s.io", "a", "sigs/a") {
		t.Error("record with a .git repository accepted")
	}
}

// The shipped list: the owner of each reviewed record is accepted for its own
// repository and nobody else is; a group outside the list stays stopped.
func TestReservedStopAgainstShippedRecords(t *testing.T) {
	recs := customresources.ReservedGroups()
	if len(recs) == 0 {
		t.Fatal("no shipped records")
	}
	seen := map[string]bool{}
	for _, r := range recs {
		if seen[r.Name] {
			t.Fatalf("two records for %s: validate must make this impossible", r.Name)
		}
		seen[r.Name] = true
		repo := r.Repository[len("https://github.com/"):]
		if reservedStop(r.Name, r.Owner, repo) {
			t.Errorf("%s: owner with exact repository stopped", r.Name)
		}
		if !reservedStop(r.Name, r.Owner+"-carrier", repo) {
			t.Errorf("%s: carrier slug not stopped", r.Name)
		}
		if !reservedStop(r.Name, r.Owner, repo+"x") || !reservedStop(r.Name, r.Owner, "fork/"+repo) {
			t.Errorf("%s: other repository not stopped", r.Name)
		}
		if !reservedStop("x."+r.Name, r.Owner, repo) {
			t.Errorf("%s: subgroup of a record not stopped", r.Name)
		}
	}
	if !reservedStop("unrecorded.storage.k8s.io", "some-project", "some-org/some-project") {
		t.Error("group without a record not stopped")
	}
	if !reservedStop("policy.networking.k8s.io", roSlug, roRepo) {
		t.Error("unrelated reserved group not stopped")
	}
	if !reservedStop("apps", roSlug, roRepo) || !reservedStop("", roSlug, roRepo) {
		t.Error("Kubernetes API group not stopped")
	}
	if reservedStop("widgets.example.test", "x", "o/x") {
		t.Error("ordinary group stopped")
	}
}

func roFinding(path, group string) *finding {
	return &finding{Path: path, CRDs: []crd{{Group: group, Kind: "K", Versions: []string{"v1:true:true"}}}}
}

func roStops(slug, repo, group string, filtered bool) []Stop {
	const p = "config/crd/x.yaml"
	rules := &Rules{Schema: RulesSchema, InstallPaths: []InstallPathRule{{Path: p, Reason: "r", Evidence: "e"}}}
	if filtered {
		rules.PathFilter = []PathFilterRule{{Glob: p, Reason: "r", Evidence: "e", ExpectFiles: 1}}
	}
	r := classify("v1.0.0", "c", []*finding{roFinding(p, group)}, rules, slug, repo, customresources.DefaultIndex(), nil)
	// A fixture whose only file is filtered has no source: not the subject.
	var out []Stop
	for _, st := range r.stops {
		if st.Code != StopNoCRDSource {
			out = append(out, st)
		}
	}
	return out
}

func roHas(stops []Stop, code string) bool {
	for _, s := range stops {
		if s.Code == code {
			return true
		}
	}
	return false
}

// Read site: the recorded owner is no longer stopped; a carrier, a wrong
// repository, a spelling that is not byte-equal and a group other than the
// record's keep the typed stop.
func TestClassifyReservedGroupReadSite(t *testing.T) {
	if s := roStops(roSlug, roRepo, roGroup, false); len(s) != 0 {
		t.Fatalf("record owner stopped: %+v", s)
	}
	for name, c := range map[string][3]string{
		"carrier":          {"csi-driver-nfs", roRepo, roGroup},
		"other repository": {roSlug, "fork/kueue", roGroup},
		"case variant":     {roSlug, "Kubernetes-sigs/kueue", roGroup},
		"dot git":          {roSlug, roRepo + ".git", roGroup},
		"other group":      {roSlug, roRepo, "other.x-k8s.io"},
		"unrecorded group": {"some-project", "some-org/some-project", "unrecorded.storage.k8s.io"},
		"kubernetes.io":    {roSlug, roRepo, "x.kubernetes.io"},
		"k8s.io":           {roSlug, roRepo, "policy.networking.k8s.io"},
	} {
		if !roHas(roStops(c[0], c[1], c[2], false), StopReservedGroup) {
			t.Errorf("%s: not stopped with %s", name, StopReservedGroup)
		}
	}
}

// Filtered-copy site: the same decision. A carrier's copy stays a legitimate
// copy; the recorded owner may not hide its own group behind a filter; a
// group without a record is unchanged.
func TestClassifyReservedGroupFilteredSite(t *testing.T) {
	if s := roStops("csi-driver-nfs", roRepo, roGroup, true); len(s) != 0 {
		t.Fatalf("carrier copy changed: %+v", s)
	}
	if s := roStops(roSlug, roRepo, "policy.networking.k8s.io", true); len(s) != 0 {
		t.Fatalf("unrelated reserved copy changed: %+v", s)
	}
	if s := roStops(roSlug, "fork/kueue", roGroup, true); len(s) != 0 {
		t.Fatalf("wrong-repository copy changed: %+v", s)
	}
	if !roHas(roStops(roSlug, roRepo, roGroup, true), StopFilterHidesOwned) {
		t.Fatal("recorded owner hiding its own group behind a filter must stop")
	}
}

// End to end: Generate wires the upstream repository through to the decision.
// The shipped kueue record accepts its exact slug and repository; the same
// fixture under another repository string stays a reserved-group stop.
func TestGenerateReservedGroupRecordEndToEnd(t *testing.T) {
	src := ipSource(func(_ string, m *memTree) {
		m.files["api/config/crd/kueue.x-k8s.io_workloads.yaml"] = ipDocs(ipCRD(roGroup, "Workload"))
	})
	in := func(slug, repo string) Input {
		i := ipInput(src, ipRules(t, `[`+ipEntry+`]`))
		i.Slug, i.Name, i.Repo = slug, "Kueue", repo
		return i
	}
	res, err := Generate(in(roSlug, "github.com/"+roRepo))
	if err != nil {
		t.Fatalf("recorded owner: generate: %v", err)
	}
	if res == nil {
		t.Fatal("recorded owner: nil result")
	}
	if !bytes.Contains(res.A, []byte(roGroup)) {
		t.Errorf("emitted target does not name %s", roGroup)
	}
	for _, c := range [][2]string{{roSlug, "github.com/fork/kueue"}, {"carrier", "github.com/" + roRepo}} {
		res, err := Generate(in(c[0], c[1]))
		if res != nil {
			t.Errorf("%v: result returned with a stop", c)
		}
		se := wantStop(t, err, StopReservedGroup)
		for _, st := range se.Stops {
			if st.Code != StopReservedGroup {
				t.Errorf("%v: unrelated stop %+v", c, st)
			}
		}
	}
}
