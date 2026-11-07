// SPDX-License-Identifier: AGPL-3.0-only

package ledger_test

import (
	"context"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues/internal/memchart"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues/ledger"
)

func TestKubeVersionLedger(t *testing.T) {
	for _, tc := range []struct {
		name, from, to string
		want           ledger.Reason
		rule           bool
	}{
		{"increase", ">=1.24.0-0", ">=1.25.0-0", "", true},
		{"earlier absent", "", ">=1.25.0-0", "", true},
		{"earlier unsupported", "<1.24.0", ">=1.25.0-0", "", true},
		{"absent", ">=1.24.0-0", "", ledger.KubeVersionAbsent, false},
		{"or", ">=1.24.0-0", ">=1.25.0-0 || <1.20.0", ledger.KubeVersionUnsupported, false},
		{"upper", ">=1.24.0-0", "<1.30.0", ledger.KubeVersionUnsupported, false},
		{"exact", ">=1.24.0-0", "1.25.0", ledger.KubeVersionUnsupported, false},
		{"range", ">=1.24.0-0", ">=1.25.0-0 <1.30.0", ledger.KubeVersionUnsupported, false},
		{"prerelease", ">=1.24.0-0", ">=1.25.0-rc.1", ledger.KubeVersionUnsupported, false},
		{"vendor", ">=1.24.0-0", ">=1.25.0-eks-123", ledger.KubeVersionUnsupported, false},
		{"missing zero", ">=1.24.0-0", ">=1.25.0", ledger.KubeVersionVendorSuffix, false},
		{"unchanged", ">=1.25.0-0", ">=1.25.0-0", "", false},
		{"lower", ">=1.26.0-0", ">=1.25.0-0", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := memchart.New()
			makeChart := func(v, k string) chart {
				c := baseChart(v, "a: 1\n", "")
				if k != "" {
					c["Chart.yaml"] += "kubeVersion: \"" + k + "\"\n"
				}
				return c
			}
			put(r, c0, makeChart("90.0.0", tc.from))
			put(r, c1, makeChart("90.1.0", tc.to))
			tg := kedaTarget(t)
			repo, err := extract.ParseRepo(tg.Repo)
			if err != nil {
				t.Fatal(err)
			}
			pair := extract.VersionPair{Repo: repo, From: "90.0.0", FromTag: "v90.0.0", FromCommit: c0, To: "90.1.0", ToTag: "v90.1.0", ToCommit: c1}
			result, err := helmvalues.New(tg).Extract(context.Background(), r, pair)
			if err != nil {
				t.Fatal(err)
			}
			p := result.Proof.(*helmvalues.PairProof)
			count := 0
			for _, c := range result.Candidates {
				if c.Rule.Operator == "require_component_version" {
					count++
					if c.Rule.Dependency == nil || c.Rule.Dependency.Version != "1.25.0" || len(c.Sources) == 0 {
						t.Fatalf("candidate %+v", c)
					}
				}
			}
			if (tc.rule && count != 1) || (!tc.rule && count != 0) {
				t.Fatalf("got %d kube candidates", count)
			}
			if (p.KubeVersion.Outcome == "rule") != tc.rule {
				t.Fatalf("outcome %q", p.KubeVersion.Outcome)
			}
			var got []ledger.Entry
			for _, e := range ledger.Collect("p", p) {
				if e.Scope == ledger.ScopeKubeVersion {
					got = append(got, e)
				}
			}
			if tc.want == "" && len(got) != 0 || tc.want != "" && (len(got) != 1 || got[0].Reason != tc.want) {
				t.Fatalf("got %+v want %s", got, tc.want)
			}
		})
	}
}

func TestKubeUnclassifiedAndInventory(t *testing.T) {
	good := &helmvalues.PairProof{From: &helmvalues.SideRecord{Tag: "v1", KubeVersion: ">=1.24.0-0"}, To: &helmvalues.SideRecord{Tag: "v2", KubeVersion: ">=1.25.0-0"}, KubeVersion: &helmvalues.KubeRecord{From: helmvalues.KubeMinimum{Shape: "minimum", Constraint: ">=1.24.0-0", Minimum: "1.24.0", PreRelease: true}, To: helmvalues.KubeMinimum{Shape: "minimum", Constraint: ">=1.25.0-0", Minimum: "1.25.0", PreRelease: true}, Outcome: "rule"}}
	for _, mutate := range []func(*helmvalues.PairProof){func(p *helmvalues.PairProof) { p.KubeVersion = nil }, func(p *helmvalues.PairProof) { p.KubeVersion.Outcome = "new outcome secret-canary" }, func(p *helmvalues.PairProof) { p.KubeVersion.To.Shape = "other" }, func(p *helmvalues.PairProof) { p.KubeVersion.To.Minimum = "bad" }, func(p *helmvalues.PairProof) { p.KubeVersion.To.Minimum = "1.26.0" }, func(p *helmvalues.PairProof) { p.KubeVersion.To.Constraint = "mismatch" }, func(p *helmvalues.PairProof) {
		p.KubeVersion.Outcome = "no rule: the later lower bound is not above the earlier one"
	}} {
		p := *good
		k := *good.KubeVersion
		p.KubeVersion = &k
		mutate(&p)
		got := ledger.Collect("p", &p)
		if len(got) != 1 || got[0].Reason != ledger.KubeVersionUnclassified || strings.Contains(got[0].Detail, "canary") {
			t.Fatalf("%+v", got)
		}
	}
	inv := &helmvalues.PairProof{From: &helmvalues.SideRecord{Tag: "inventory", Commit: c0}, To: &helmvalues.SideRecord{Tag: "inventory", Commit: c0}}
	if got := ledger.Collect("p", inv); len(got) != 0 {
		t.Fatalf("inventory %+v", got)
	}
}

func TestKubeMultiPatchDivergence(t *testing.T) {
	const c2 = "0000000000000000000000000000000000a90001"
	const c3 = "0000000000000000000000000000000000a91001"
	r := memchart.New()
	for _, item := range []struct{ commit, version, kube string }{{c0, "90.0.0", ">=1.24.0-0"}, {c2, "90.0.1", ">=1.25.0-0"}, {c1, "90.1.0", ">=1.25.0-0"}, {c3, "90.1.1", ">=1.25.0-0"}} {
		c := baseChart(item.version, "a: 1\n", "")
		c["Chart.yaml"] += "kubeVersion: \"" + item.kube + "\"\n"
		put(r, item.commit, c)
	}
	tg := kedaTarget(t)
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	x := helmvalues.New(tg)
	pairs := x.Pairs(extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{{Name: "v90.0.0", Commit: c0}, {Name: "v90.0.1", Commit: c2}, {Name: "v90.1.0", Commit: c1}, {Name: "v90.1.1", Commit: c3}}})
	if len(pairs) != 1 {
		t.Fatalf("pairs %+v", pairs)
	}
	result, err := x.Extract(context.Background(), r, pairs[0])
	if err != nil {
		t.Fatal(err)
	}
	p := result.Proof.(*helmvalues.PairProof)
	count := 0
	for _, c := range result.Candidates {
		if c.Rule.Operator == "require_component_version" {
			count++
			if c.Rule.Range != nil {
				t.Fatal("divergent rule ranged")
			}
		}
	}
	if count != 1 {
		t.Fatalf("got %d candidates", count)
	}
	found := false
	for _, rp := range p.Lines.Ranges {
		if rp.Kind == "kube-version" {
			found = true
			if rp.Divergence == nil || rp.Divergence.From != "v90.0.1" {
				t.Fatalf("range %+v", rp)
			}
		}
	}
	if !found {
		t.Fatal("missing range proof")
	}
	for _, e := range ledger.Collect("p", p) {
		if e.Scope == ledger.ScopeKubeVersion {
			t.Fatalf("anchor refusal %+v", e)
		}
	}
}
