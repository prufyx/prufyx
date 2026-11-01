// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"context"
	"encoding/json"
	"io/fs"
	"sort"
	"testing"
	"testing/fstest"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// resultGolden is the canonical JSON of a Result with one ledger entry. The
// same literal is pinned in the knowledgegate package
// (TestProofLedgerReadsTheCrdschemaResultShape), whose gate check reads the
// top-level "ledger" array of a pair proof: the two tests together tie the
// extractor's output shape to the gate's reading of it.
const resultGolden = `{"schema":"prufyx.io/crd-schema-removal/v2","from":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","to":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","fields":{"members":[],"complete":false},"enums":{"members":[],"complete":false},"omissions":[{"reason":"MEMBER_CHARSET","subject":"example.io/Widget","count":1}],"ledger":[{"code":"MEMBER_CHARSET","item":"example.io/Widget"}],"exclusions":[]}`

func TestResultGoldenShape(t *testing.T) {
	r := &Result{
		Schema: ResultSchema, From: commitA, To: commitB,
		Fields: constraintengine.SetValue{Members: []string{}}, Enums: constraintengine.SetValue{Members: []string{}},
		Omissions:  []Omission{{Reason: "MEMBER_CHARSET", Subject: "example.io/Widget", Count: 1}},
		Ledger:     []LedgerEntry{{Code: "MEMBER_CHARSET", Item: "example.io/Widget"}},
		Exclusions: []Omission{},
	}
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != resultGolden {
		t.Fatalf("Result JSON changed:\ngot  %s\nwant %s", got, resultGolden)
	}
}

// --- a test-only wiring of Derive into the framework ---
//
// wiredExtractor is the smallest correct wiring: the proof is the Result
// itself (ledger at the top level) and the pair is attested only when the
// Result is attestable. It pins what the real wiring must do.

type wiredExtractor struct {
	c testCase
}

const wiredComponent = "pkg:github/kubernetes/kubernetes"

func (wiredExtractor) ID() string                     { return "crdschema.wiring-test" }
func (wiredExtractor) Version() string                { return "1.0.0" }
func (wiredExtractor) Applies(r extract.RepoRef) bool { return r.Key == repo.Key }
func (wiredExtractor) AttestedFamilies() []string {
	return []string{lineattest.FamilyKubernetesRemovedServedGVK}
}
func (wiredExtractor) AttestedComponent() string { return wiredComponent }
func (wiredExtractor) SourceFiles() (string, fs.FS) {
	return "crdschema", fstest.MapFS{"x.go": {Data: []byte("package x\n")}}
}
func (wiredExtractor) Pairs(ix extract.ReleaseIndex) []extract.VersionPair {
	return []extract.VersionPair{{Repo: ix.Repo, From: "1.0.0", FromTag: "v1.0.0", FromCommit: commitA, To: "2.0.0", ToTag: "v2.0.0", ToCommit: commitB}}
}

func (x wiredExtractor) Extract(ctx context.Context, r extract.PinnedReader, p extract.VersionPair) (extract.Extraction, error) {
	res, err := derive(ctx, r, testTarget, p.FromCommit, p.ToCommit, guardsFor(x.c, defaultGuards()))
	if err != nil {
		return extract.Extraction{}, err
	}
	e := extract.Extraction{Proof: res}
	if !res.Attestable() {
		e.NotAttested = "the pair withheld items"
		return e, nil
	}
	var from []string
	for path := range x.c.from {
		from = append(from, path)
	}
	if len(from) == 0 {
		e.NotAttested = "no source file to cite"
		return e, nil
	}
	sort.Strings(from)
	if _, err := r.Read(p.Repo, p.FromCommit, from[0]); err != nil {
		return extract.Extraction{}, err
	}
	e.Attestations = []extract.AttestationCandidate{{
		Component: wiredComponent, Line: "2.0", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK, RuleIDs: []string{},
		Sources: []extract.SourceRef{{ID: "crd", Repo: p.Repo, Commit: p.FromCommit, Path: from[0]}},
	}}
	return e, nil
}

type wiredTags struct{}

func (wiredTags) Tags(extract.RepoRef) ([]extract.Tag, error) {
	return []extract.Tag{{Name: "v1.0.0", Commit: commitA}, {Name: "v2.0.0", Commit: commitB}}, nil
}

// TestWiredPairIsAttestedOnlyWithoutWithheldItems runs every fixture through
// extract.Run: a fixture with omissions (a non-empty ledger) yields a
// not-attested pair whose proof carries the ledger at the top level, and a
// fixture without them yields an attested pair.
func TestWiredPairIsAttestedOnlyWithoutWithheldItems(t *testing.T) {
	attested, refused := 0, 0
	for _, c := range allCases(t) {
		out, err := extract.Run(context.Background(), wiredExtractor{c}, wiredTags{}, c.reader(), extract.Options{Repo: repo, DerivedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		p := out.Manifest.Pairs[0]
		raw, err := json.Marshal(p.Proof)
		if err != nil {
			t.Fatal(err)
		}
		var proof struct {
			Ledger []LedgerEntry `json:"ledger"`
		}
		if err := json.Unmarshal(raw, &proof); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		withheld := len(c.exp.Omissions) > 0
		if withheld {
			refused++
			if len(proof.Ledger) == 0 || p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
				t.Errorf("%s: withheld items but ledger=%d attestation=%+v", c.name, len(proof.Ledger), p.Attestation)
			}
			continue
		}
		if len(proof.Ledger) != 0 {
			t.Errorf("%s: no omissions but ledger %v", c.name, proof.Ledger)
		}
		if len(c.from) == 0 {
			continue
		}
		attested++
		if p.Attestation == nil || p.Attestation.Status != extract.PairAttested || len(out.Attestations) != 1 {
			t.Errorf("%s: nothing withheld but attestation=%+v", c.name, p.Attestation)
		}
	}
	if attested == 0 || refused == 0 {
		t.Fatalf("fixtures exercised %d attested and %d refused pairs", attested, refused)
	}
}
