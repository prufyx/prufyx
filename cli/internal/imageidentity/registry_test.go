// SPDX-License-Identifier: AGPL-3.0-only

package imageidentity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

const sha = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

// want pins, independently of the data file, what each reviewed image means.
// A change to the data that alters any of these is a reviewed change to this
// table too.
type want struct {
	repo, project, component, role string
	tag, version                   string // a tag that must resolve, and its version
	withDigest                     bool   // true: tag@digest keeps the version (opencost only)
}

var wants = []want{
	{"docker.io/prom/alertmanager", "alertmanager", "pkg:oci/prometheus/alertmanager", RoleVersionSource, "v0.34.1", "0.34.1", false},
	{"quay.io/prometheus/alertmanager", "alertmanager", "pkg:oci/prometheus/alertmanager", RoleVersionSource, "v0.34.1", "0.34.1", false},
	{"ghcr.io/cloudnative-pg/cloudnative-pg", "cloudnativepg", "pkg:oci/cloudnative-pg/cloudnative-pg", RoleOperator, "1.30.1", "1.30.1", false},
	{"registry.k8s.io/cluster-api/cluster-api-controller", "cluster-api", "pkg:oci/kubernetes-sigs/cluster-api", RoleVersionSource, "v1.14.2", "1.14.2", false},
	{"registry.k8s.io/cluster-api/kubeadm-bootstrap-controller", "cluster-api", "pkg:oci/kubernetes-sigs/cluster-api", RoleVersionSource, "v1.14.2", "1.14.2", false},
	{"registry.k8s.io/cluster-api/kubeadm-control-plane-controller", "cluster-api", "pkg:oci/kubernetes-sigs/cluster-api", RoleVersionSource, "v1.14.2", "1.14.2", false},
	{"ghcr.io/projectcontour/contour", "contour", "pkg:oci/projectcontour/contour", RoleVersionSource, "v1.33.7", "1.33.7", false},
	{"docker.io/dragonflyoss/manager", "dragonfly", "pkg:oci/dragonflyoss/dragonfly", RoleVersionSource, "v2.5.2", "2.5.2", false},
	{"docker.io/dragonflyoss/scheduler", "dragonfly", "pkg:oci/dragonflyoss/dragonfly", RoleVersionSource, "v2.5.2", "2.5.2", false},
	{"quay.io/coreos/etcd", "etcd", "pkg:oci/etcd-io/etcd", RoleVersionSource, "v3.7.2", "3.7.2", false},
	{"docker.io/grafana/grafana", "grafana", "pkg:oci/grafana/grafana", RoleVersionSource, "13.2.2", "13.2.2", false},
	{"docker.io/goharbor/harbor-core", "harbor", "pkg:oci/goharbor/harbor", RoleVersionSource, "v2.15.2", "2.15.2", false},
	{"docker.io/goharbor/harbor-portal", "harbor", "pkg:oci/goharbor/harbor", RoleVersionSource, "v2.15.2", "2.15.2", false},
	{"docker.io/goharbor/nginx-photon", "harbor", "pkg:oci/goharbor/harbor", RoleVersionSource, "v2.15.2", "2.15.2", false},
	{"registry.k8s.io/kube-state-metrics/kube-state-metrics", "kube-state-metrics", "pkg:oci/kubernetes/kube-state-metrics", RoleVersionSource, "v2.20.0", "2.20.0", false},
	{"docker.io/kubeedge/cloudcore", "kubeedge", "pkg:oci/kubeedge/kubeedge", RoleVersionSource, "v1.23.0", "1.23.0", false},
	{"docker.io/longhornio/longhorn-engine", "longhorn", "pkg:oci/longhornio/longhorn", RoleVersionSource, "v1.13.0", "1.13.0", false},
	{"docker.io/longhornio/longhorn-manager", "longhorn", "pkg:oci/longhornio/longhorn", RoleVersionSource, "v1.13.0", "1.13.0", false},
	{"docker.io/library/mariadb", "mariadb", "pkg:oci/mariadb/server", RoleVersionSource, "12.3.3", "12.3.3", false},
	{"ghcr.io/mariadb-operator/mariadb-operator", "mariadb-operator", "pkg:oci/mariadb-operator/mariadb-operator", RoleOperator, "26.10.1", "26.10.1", false},
	{"docker.io/library/nats", "nats", "pkg:oci/nats-io/nats-server", RoleVersionSource, "2.15.0-alpine", "2.15.0", false},
	{"docker.io/prom/node-exporter", "node-exporter", "pkg:oci/prometheus/node-exporter", RoleVersionSource, "v1.12.1", "1.12.1", false},
	{"quay.io/prometheus/node-exporter", "node-exporter", "pkg:oci/prometheus/node-exporter", RoleVersionSource, "v1.12.1", "1.12.1", false},
	{"ghcr.io/opencost/opencost", "opencost", "pkg:oci/opencost/opencost", RoleVersionSource, "1.121.3", "1.121.3", true},
	{"ghcr.io/opencost/opencost-ui", "opencost", "pkg:oci/opencost/opencost", RoleVersionSource, "1.121.3", "1.121.3", true},
	{"docker.io/rook/ceph", "rook", "pkg:oci/rook/rook", RoleOperator, "v1.20.8", "1.20.8", false},
	{"docker.io/thanosio/thanos", "thanos", "pkg:oci/thanos-io/thanos", RoleVersionSource, "v0.42.4", "0.42.4", false},
	{"quay.io/thanos/thanos", "thanos", "pkg:oci/thanos-io/thanos", RoleVersionSource, "v0.42.4", "0.42.4", false},
	{"docker.io/velero/velero", "velero", "pkg:oci/velero/velero", RoleVersionSource, "v1.18.2", "1.18.2", false},
}

func refForms(repo, tail string) []string {
	forms := []string{repo + tail}
	if rest, ok := strings.CutPrefix(repo, "docker.io/"); ok {
		forms = append(forms, "index.docker.io/"+rest+tail, "registry-1.docker.io/"+rest+tail)
		if strings.HasPrefix(rest, "library/") {
			forms = append(forms, strings.TrimPrefix(rest, "library/")+tail)
		} else {
			forms = append(forms, rest+tail)
		}
	}
	return forms
}

// check returns every way t disagrees with wants (empty means agreement).
func check(t *Table) []string {
	var bad []string
	for _, w := range wants {
		for _, ref := range refForms(w.repo, ":"+w.tag) {
			r := t.Match(ref, testNow)
			if r.Kind != KindMatched || r.Project != w.project || r.Component != w.component || r.Role != w.role || r.Version != w.version || r.Scheme != "tag" {
				bad = append(bad, fmt.Sprintf("positive %s: %+v", ref, r))
			}
		}
		// tag + digest: version only where the record explicitly allows it.
		r := t.Match(w.repo+":"+w.tag+"@"+sha, testNow)
		if w.withDigest != (r.Version != "") {
			bad = append(bad, fmt.Sprintf("tag+digest %s: %+v", w.repo, r))
		}
		// never a version: digest only, no tag, latest, wrong scheme, pre-release.
		for _, ref := range []string{w.repo + "@" + sha, w.repo, w.repo + ":latest", w.repo + ":edge", w.repo + ":1.2", w.repo + ":v1.2.3-rc.1", w.repo + ":1.2.3.4", w.repo + ":v01.2.3", w.repo + ":" + w.tag + "-distro", w.repo + ":dev"} {
			if r := t.Match(ref, testNow); r.Version != "" {
				bad = append(bad, fmt.Sprintf("negative %s gave a version: %+v", ref, r))
			}
		}
		// the opposite prefix convention must not match.
		other := "v" + w.tag
		if strings.HasPrefix(w.tag, "v") {
			other = strings.TrimPrefix(w.tag, "v")
		}
		if r := t.Match(w.repo+":"+other, testNow); r.Version != "" && !strings.HasSuffix(w.tag, "-alpine") {
			bad = append(bad, fmt.Sprintf("wrong v-prefix convention %s:%s gave a version", w.repo, other))
		}
		// similar-looking repositories are other images.
		for _, ref := range []string{w.repo + "x:" + w.tag, w.repo + "/x:" + w.tag, "evil.example/" + w.repo + ":" + w.tag, strings.ToUpper(w.repo) + ":" + w.tag} {
			if r := t.Match(ref, testNow); r.Kind != KindUnknown {
				bad = append(bad, fmt.Sprintf("lookalike %s matched: %+v", ref, r))
			}
		}
		// expired record: nothing is identified.
		if r := t.Match(w.repo+":"+w.tag, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)); r.Kind != KindUnknown || r.Version != "" {
			bad = append(bad, fmt.Sprintf("expired %s: %+v", w.repo, r))
		}
	}
	return bad
}

func load(t *testing.T) *Table {
	t.Helper()
	tab, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func clone(t *testing.T, tab *Table) *Table {
	t.Helper()
	raw, err := json.Marshal(tab)
	if err != nil {
		t.Fatal(err)
	}
	var out Table
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func TestEmbeddedTableIsValidCanonicalAndCoversExactlyTheWantedImages(t *testing.T) {
	tab := load(t)
	raw, err := embedded.ReadFile("data/image-sources.json")
	if err != nil {
		t.Fatal(err)
	}
	canon, err := tab.Marshal()
	if err != nil || !bytes.Equal(canon, raw) {
		t.Fatalf("embedded table is not canonical: %v", err)
	}
	if bad := check(tab); len(bad) > 0 {
		t.Fatal(strings.Join(bad, "\n"))
	}
	have := map[string]bool{}
	for _, r := range tab.Records {
		for _, img := range r.Images {
			have[img.Repo] = true
		}
		if r.OperandRule != OperandRuleNone || r.Evidence.State != StateActive {
			t.Fatalf("%s: operand rule or state", r.Project)
		}
	}
	if len(have) != len(wants) {
		t.Fatalf("table has %d images, expectations pin %d", len(have), len(wants))
	}
	for _, w := range wants {
		if !have[w.repo] {
			t.Fatalf("missing %s", w.repo)
		}
	}
	// the DETECT-1 "yes" tier plus the two MariaDB projects are all present.
	projects := map[string]bool{}
	for _, r := range tab.Records {
		projects[r.Project] = true
	}
	for _, p := range strings.Fields("cloudnativepg contour dragonfly harbor kubeedge longhorn nats opencost rook velero mariadb mariadb-operator") {
		if !projects[p] {
			t.Fatalf("missing project %s", p)
		}
	}
}

func TestNegativeCases(t *testing.T) {
	tab := load(t)
	for _, tc := range []struct {
		name, ref string
		kind      Kind
		version   string
		scheme    string
	}{
		{"operator image gives only its own component", "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.1", KindMatched, "1.30.1", "tag"},
		{"digest-only", "ghcr.io/projectcontour/contour@" + sha, KindMatched, "", "digest"},
		{"untagged is latest", "ghcr.io/projectcontour/contour", KindMatched, "", "unknown"},
		{"tag with digest not trusted", "ghcr.io/projectcontour/contour:v1.33.7@" + sha, KindMatched, "", "digest"},
		{"bad tag", "ghcr.io/projectcontour/contour:main-20261001-abcdef", KindMatched, "", "unknown"},
		{"envoy sidecar is not contour", "docker.io/envoyproxy/envoy:distroless-v1.38.4", KindUnknown, "", "unknown"},
		{"unknown repo", "docker.io/library/redis:7.2.4", KindUnknown, "", "unknown"},
		{"nats without alpine", "nats:2.15.0", KindMatched, "", "unknown"},
		{"nats alpine", "nats:2.15.0-alpine", KindMatched, "2.15.0", "tag"},
		{"mariadb variant tag", "mariadb:12.3.3-noble", KindMatched, "", "unknown"},
		{"mariadb floating tag", "mariadb:lts", KindMatched, "", "unknown"},
		{"harbor chart-style dev tag", "goharbor/harbor-core:dev", KindMatched, "", "unknown"},
		{"other digest algorithm", "ghcr.io/projectcontour/contour@sha512:" + strings.Repeat("0", 128), KindUnknown, "", "unknown"},
		{"short digest", "ghcr.io/projectcontour/contour@sha256:abc", KindUnknown, "", "unknown"},
		{"two digests", "ghcr.io/projectcontour/contour@" + sha + "@" + sha, KindUnknown, "", "unknown"},
		{"empty", "", KindUnknown, "", "unknown"},
		{"space", "ghcr.io/projectcontour/contour:v1.33.7 ", KindUnknown, "", "unknown"},
		{"newline", "ghcr.io/projectcontour/contour:v1.33.7\n", KindUnknown, "", "unknown"},
		{"empty path part", "ghcr.io//projectcontour/contour:v1.33.7", KindUnknown, "", "unknown"},
		{"port host is another registry", "ghcr.io:443/projectcontour/contour:v1.33.7", KindUnknown, "", "unknown"},
		{"private mirror of a known image", "registry.example.com/mirror/projectcontour/contour:v1.33.7", KindUnknown, "", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tab.Match(tc.ref, testNow)
			if r.Kind != tc.kind || r.Version != tc.version || r.Scheme != tc.scheme {
				t.Fatalf("%q: %+v", tc.ref, r)
			}
		})
	}
}

func TestOperatorImageNeverImpliesOperandVersion(t *testing.T) {
	tab := load(t)
	for _, repo := range []string{"ghcr.io/cloudnative-pg/cloudnative-pg", "docker.io/rook/ceph", "ghcr.io/mariadb-operator/mariadb-operator"} {
		r := tab.Match(repo+":v1.2.3", testNow)
		if r.Role != RoleOperator {
			t.Fatalf("%s role %q", repo, r.Role)
		}
	}
	// An operator image identifies the operator's own component; the
	// operand's component (mariadb server) is never derived from it.
	op := tab.Match("ghcr.io/mariadb-operator/mariadb-operator:26.10.1", testNow)
	srv := tab.Match("mariadb:12.3.3", testNow)
	if op.Component == srv.Component || op.Project != "mariadb-operator" || srv.Project != "mariadb" {
		t.Fatalf("operator %+v operand %+v", op, srv)
	}
	// Ceph daemons run from their own image; rook/ceph:vX is never a Ceph version.
	if r := tab.Match("quay.io/ceph/ceph:v19.2.3", testNow); r.Kind != KindUnknown {
		t.Fatalf("ceph image matched: %+v", r)
	}
	// Only the closed operand rule is accepted.
	c := clone(t, tab)
	c.Records[0].OperandRule = "from-spec"
	if err := c.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("operand rule accepted: %v", err)
	}
}

func TestProviderDistributionBuildsAreNeverUpstreamVersions(t *testing.T) {
	tab := load(t)
	for _, ref := range []string{
		"example-artifactregistry.gcr.io/gke-release/gke-release/kube-state-metrics/kube-state-metrics:v1.2.3-gke.0",
		"example-artifactregistry.gcr.io/gke-release/etcd:v3.7.2-gke.1",
		"gcr.io/gke-release/prometheus-to-sd:v0.11.12-gke.9",
		"gke.gcr.io/cluster-proportional-autoscaler:v1.9.0-gke.1",
		"example-docker.pkg.dev/gke-release/gke-release/x:v1.2.3",
	} {
		r := tab.Match(ref, testNow)
		if r.Version != "" || r.Component != "" {
			t.Fatalf("%s: %+v", ref, r)
		}
		if !strings.Contains(ref, "pkg.dev") && r.Kind != KindDistribution {
			t.Fatalf("%s kind %s", ref, r.Kind)
		}
	}
}

func TestObservableComponentsFollowValidity(t *testing.T) {
	tab := load(t)
	got := ObservableComponents(testNow)
	for _, p := range strings.Fields("cloudnativepg contour dragonfly harbor kubeedge longhorn nats opencost rook velero mariadb mariadb-operator etcd grafana thanos") {
		if got[p] == "" {
			t.Fatalf("%s not observable", p)
		}
	}
	for _, p := range []string{"alertmanager", "node-exporter", "cluster-api", "kube-state-metrics"} {
		if _, ok := got[p]; ok {
			t.Fatalf("%s is outside the catalog and must not route checks", p)
		}
	}
	if len(ObservableComponents(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))) != 0 {
		t.Fatal("expired records stayed observable")
	}
	_ = tab
}

func TestValidateRejectsMalformedTables(t *testing.T) {
	base := load(t)
	for name, mut := range map[string]func(*Table){
		"schema":             func(x *Table) { x.Schema = "x" },
		"nil records":        func(x *Table) { x.Records = nil },
		"unsorted records":   func(x *Table) { x.Records[0], x.Records[1] = x.Records[1], x.Records[0] },
		"duplicate repo":     func(x *Table) { x.Records[1].Images[0].Repo = x.Records[0].Images[0].Repo },
		"scheme not closed":  func(x *Table) { x.Records[0].TagScheme = "{version}-{suffix}" },
		"bad role":           func(x *Table) { x.Records[0].Images[0].Role = "sidecar" },
		"bad component":      func(x *Table) { x.Records[0].Component = "pkg:github/a/b" },
		"non-canonical repo": func(x *Table) { x.Records[0].Images[0].Repo = "index.docker.io/prom/alertmanager" },
		"hostless repo":      func(x *Table) { x.Records[0].Images[0].Repo = "prom/alertmanager" },
		"uppercase repo":     func(x *Table) { x.Records[0].Images[0].Repo = "docker.io/Prom/alertmanager" },
		"tagged repo":        func(x *Table) { x.Records[0].Images[0].Repo = "docker.io/prom/alertmanager:v1" },
		"unknown source id":  func(x *Table) { x.Records[0].Images[0].SourceID = "nope" },
		"no sources":         func(x *Table) { x.Records[0].Evidence.Sources = nil },
		"unpinned source url": func(x *Table) {
			x.Records[0].Evidence.Sources[0].URL = strings.Replace(x.Records[0].Evidence.Sources[0].URL, x.Records[0].Evidence.Sources[0].Revision, "main", 1)
		},
		"validity window":      func(x *Table) { x.Records[0].Evidence.ValidUntil = x.Records[0].Evidence.ReviewedAt },
		"bad state":            func(x *Table) { x.Records[0].Evidence.State = "pending" },
		"catalog says member":  func(x *Table) { x.Records[0].Catalog = CatalogMember },
		"catalog says none":    func(x *Table) { x.Records[1].Catalog = CatalogNone },
		"unknown project slug": func(x *Table) { x.Records[1].Project = "not-in-catalog"; x.Records[1].Catalog = CatalogMember },
	} {
		t.Run(name, func(t *testing.T) {
			x := clone(t, base)
			mut(x)
			if err := x.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	if _, err := Parse([]byte(`{"schema":"` + Schema + `","records":[],"extra":1}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field accepted: %v", err)
	}
	if _, err := Parse([]byte(`{"schema":"` + Schema + `","records":[]} {}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing data accepted: %v", err)
	}
	empty, err := Parse([]byte(`{"schema":"` + Schema + `","records":[]}`))
	if err != nil || len(empty.Match("quay.io/coreos/etcd:v3.7.2", testNow).Version) != 0 {
		t.Fatalf("an empty registry must never give a version: %v", err)
	}
}

// TestMutationsAreCaught mutates every record of the real table in every way
// that could loosen it. Each mutant must either fail validation or disagree
// with the independent expectations; a mutant that survives both means a
// weakening could pass review unnoticed.
func TestMutationsAreCaught(t *testing.T) {
	base := load(t)
	type mutation struct {
		name string
		do   func(r *Record)
	}
	muts := []mutation{
		{"repo suffix", func(r *Record) { r.Images[0].Repo += "x" }},
		{"repo registry", func(r *Record) { r.Images[0].Repo = "evil.example/" + strings.SplitN(r.Images[0].Repo, "/", 2)[1] }},
		{"repo case", func(r *Record) { r.Images[0].Repo = strings.ToUpper(r.Images[0].Repo[:1]) + r.Images[0].Repo[1:] }},
		{"scheme v", func(r *Record) { r.TagScheme = SchemeV }},
		{"scheme plain", func(r *Record) { r.TagScheme = SchemePlain }},
		{"scheme alpine", func(r *Record) { r.TagScheme = SchemeAlpine }},
		{"role flip", func(r *Record) {
			for i := range r.Images {
				if r.Images[i].Role == RoleOperator {
					r.Images[i].Role = RoleVersionSource
				} else {
					r.Images[i].Role = RoleOperator
				}
			}
		}},
		{"tag with digest flip", func(r *Record) { r.TagWithDigest = !r.TagWithDigest }},
		{"operand rule", func(r *Record) { r.OperandRule = "from-spec" }},
		{"component", func(r *Record) { r.Component = "pkg:oci/evil/evil" }},
		{"project", func(r *Record) { r.Project += "x" }},
		{"withdrawn", func(r *Record) { r.Evidence.State = StateWithdrawn }},
		{"expired", func(r *Record) { r.Evidence.ValidUntil = "2026-10-06T00:00:01Z" }},
		{"catalog flag", func(r *Record) {
			if r.Catalog == CatalogMember {
				r.Catalog = CatalogNone
			} else {
				r.Catalog = CatalogMember
			}
		}},
	}
	baseJSON, _ := json.Marshal(base)
	for i := range base.Records {
		for _, m := range muts {
			x := clone(t, base)
			m.do(&x.Records[i])
			if same, _ := json.Marshal(x); bytes.Equal(same, baseJSON) {
				continue // the mutation changed nothing for this record
			}
			if x.Validate() != nil {
				continue
			}
			if len(check(x)) == 0 {
				t.Errorf("mutant survived: record %s, %s", base.Records[i].Project, m.name)
			}
		}
	}
	// A record with a whole image dropped is also detected.
	for i := range base.Records {
		if len(base.Records[i].Images) < 2 {
			continue
		}
		x := clone(t, base)
		x.Records[i].Images = x.Records[i].Images[1:]
		if len(check(x)) == 0 {
			t.Errorf("dropping an image of %s went unnoticed", base.Records[i].Project)
		}
	}
}

func TestDigestBindsTheTableBytes(t *testing.T) {
	raw, err := embedded.ReadFile("data/image-sources.json")
	if err != nil {
		t.Fatal(err)
	}
	d := Digest()
	if d == "" || d != DigestOf(raw) || !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		t.Fatalf("digest %q", d)
	}
	changed := append([]byte(nil), raw...)
	changed[len(changed)/2] ^= 1
	if DigestOf(changed) == d {
		t.Fatal("changing one byte of the table must change its digest")
	}
}
