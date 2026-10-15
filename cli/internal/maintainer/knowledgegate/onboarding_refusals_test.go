// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// Every case must make the gate refuse the change; each names the check
// (O1 to O8) whose refusal it shows and a part of the reason.
func TestOnboardingRefusals(t *testing.T) {
	ol := DefaultLayout().Onboarding
	headFile := func(f *onboardingFixture, rel string) string {
		return filepath.Join(f.head.Root, filepath.FromSlash(rel))
	}
	// signed signs the fixture as the signing tool would, then edit runs.
	signed := func(edit func(t *testing.T, f *onboardingFixture, rec OnboardingRecord)) func(t *testing.T, f *onboardingFixture) {
		return func(t *testing.T, f *onboardingFixture) {
			rec := f.record(t)
			f.sign(t, rec)
			if edit != nil {
				edit(t, f, rec)
			}
		}
	}
	// resigned edits the record before it is signed.
	resigned := func(edit func(rec *OnboardingRecord)) func(t *testing.T, f *onboardingFixture) {
		return func(t *testing.T, f *onboardingFixture) {
			rec := f.record(t)
			edit(&rec)
			f.sign(t, rec)
		}
	}
	// blind changes the head, then signs what the signer would refuse.
	blind := func(edit func(t *testing.T, f *onboardingFixture)) func(t *testing.T, f *onboardingFixture) {
		return func(t *testing.T, f *onboardingFixture) {
			pre := f.record(t)
			edit(t, f)
			f.refresh()
			rec, _ := f.tryRecord(t)
			if rec.BatchID == "" {
				// The head cannot be read as an onboarding change at all:
				// sign the record of the unedited head.
				rec = pre
			}
			f.sign(t, rec)
		}
	}
	editTarget := func(t *testing.T, f *onboardingFixture, edit func(target map[string]any)) {
		t.Helper()
		path := headFile(f, targetPath(ol, obSlug))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		edit(doc["target"].(map[string]any))
		out, _ := json.MarshalIndent(doc, "", "  ")
		writeFile(t, path, append(out, '\n'))
		f.writeDocs(t)
	}
	setGroups := func(groups ...string) func(t *testing.T, f *onboardingFixture) {
		return func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				for i := range ps {
					if ps[i].Slug == obSlug {
						ps[i].Groups = nil
						for _, g := range groups {
							ps[i].Groups = append(ps[i].Groups, customresources.Group{Name: g, Source: "https://github.com/" + obOwnerRepo + "/blob/" + obTo + "/" + obCRD})
						}
					}
				}
				return ps
			})
			f.draft.Projects[0].Groups = groups
		}
	}

	cases := []struct {
		name  string
		setup func(t *testing.T, f *onboardingFixture)
		opts  func(*Options)
		want  string
	}{
		// O1: the file, the key, the window, single use.
		{"O1 two batch files", signed(func(t *testing.T, f *onboardingFixture, rec OnboardingRecord) {
			rec.BatchID = "ob-20261003-2"
			f.sign(t, rec)
		}), nil, "O1: a change may add one onboarding batch"},
		{"O1 file not named after its id", signed(func(t *testing.T, f *onboardingFixture, rec OnboardingRecord) {
			raw, _ := os.ReadFile(headFile(f, ol.Dir+"/"+rec.BatchID+".json"))
			os.Remove(headFile(f, ol.Dir+"/"+rec.BatchID+".json"))
			f.writeBatch(t, f.head, "ob-20261003-9.json", raw)
		}), nil, "is not named after its batch id"},
		{"O1 unknown member", signed(func(t *testing.T, f *onboardingFixture, rec OnboardingRecord) {
			p := headFile(f, ol.Dir+"/"+rec.BatchID+".json")
			raw, _ := os.ReadFile(p)
			writeFile(t, p, []byte(strings.Replace(string(raw), `"schema":`, `"extra": 1, "schema":`, 1)))
		}), nil, "unknown field"},
		{"O1 wrong key", func(t *testing.T, f *onboardingFixture) {
			rec := f.record(t)
			f.writeBatch(t, f.head, rec.BatchID+".json", newApprovalKey(t).signOnboarding(t, rec))
		}, nil, "signed by a key that is not pinned"},
		{"O1 no pinned key digest", signed(nil), func(o *Options) { o.ApprovalKeysDigest = "none" }, "O1: no owner approval key digest"},
		{"O1 identity not an owner", resigned(func(rec *OnboardingRecord) { rec.Identity = "someone-else" }), nil, "is not an owner"},
		{"O1 expired", signed(nil), func(o *Options) { o.Now = gateNow.Add(MaxOnboardingValidity) }, "expired"},
		{"O1 validity over 72 hours", resigned(func(rec *OnboardingRecord) {
			rec.NotAfter = gateNow.Add(80 * time.Hour).Format("2006-01-02T15:04:05Z")
		}), nil, "at most 72 hours"},
		{"O1 decided in the future", resigned(func(rec *OnboardingRecord) {
			rec.DecidedAt = gateNow.Add(time.Hour).Format("2006-01-02T15:04:05Z")
			rec.NotAfter = gateNow.Add(2 * time.Hour).Format("2006-01-02T15:04:05Z")
		}), nil, "decided in the future"},
		{"O1 replayed batch", signed(func(t *testing.T, f *onboardingFixture, rec OnboardingRecord) {
			raw, _ := os.ReadFile(headFile(f, ol.Dir+"/"+rec.BatchID+".json"))
			f.writeBatch(t, f.base, "ob-20261001-1.json", raw)
			f.writeBatch(t, f.head, "ob-20261001-1.json", raw)
		}), nil, "already in the base"},
		{"O1 an earlier decision after a later one", signed(func(t *testing.T, f *onboardingFixture, rec OnboardingRecord) {
			later := rec
			later.BatchID = "ob-20261003-5"
			later.DecidedAt = f.signedAt.Add(time.Minute).Format("2006-01-02T15:04:05Z")
			raw := f.key.signOnboarding(t, later)
			f.writeBatch(t, f.base, "ob-20261003-5.json", raw)
			f.writeBatch(t, f.head, "ob-20261003-5.json", raw)
		}), nil, "at the same time or later"},

		// O2: the path allow-list and the classification.
		{"O2 code file", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, ol.TargetsDir+"/onboarded.go"), []byte("package crdversions\n"))
		}), nil, "O2: an onboarding change may change only"},
		{"O2 golden file", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, "cli/internal/scanrun/testdata/scan-pass.md"), []byte("moved\n"))
		}), nil, "cli/internal/scanrun/testdata/scan-pass.md"},
		{"O2 test file", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, "cli/internal/extract/crdversions/attestation_test.go"), []byte("package crdversions\n"))
		}), nil, "attestation_test.go"},
		{"O2 approval file", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, "cli/knowledge/approvals/cncf/some-rule.json"), []byte("{}\n"))
		}), nil, "cli/knowledge/approvals/cncf/some-rule.json"},
		{"O2 trust material", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, "cli/knowledge/trust/other.json"), []byte("{}\n"))
		}), nil, "cli/knowledge/trust/other.json"},
		{"O2 a rule changes", blind(func(t *testing.T, f *onboardingFixture) {
			p := readPack(t, f.head, cncfRulesPath)
			e := p.entries[0]
			ruleOf(e)["message"] = "smuggled"
			p.write(t, f.head, cncfRulesPath)
			raw, _ := f.head.Read(cncfRulesPath, MaxFileBytes)
			f.writePack(t, raw)
		}), nil, "O2: an onboarding change may not change rule"},
		{"O2 a target is removed", blind(func(t *testing.T, f *onboardingFixture) {
			os.Remove(headFile(f, ol.TargetsDir+"/"+crdversions.TargetFileName(crdversions.Targets[0].Project)))
		}), nil, "is removed"},
		{"O2 another project's row changes", blind(func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				for i := range ps {
					if ps[i].Slug == otherSlug() {
						ps[i].Groups[0].Source = "https://github.com/" + strings.TrimPrefix(ps[i].Component, "pkg:github/") + "/blob/" + obTo + "/x.yaml"
					}
				}
				return ps
			})
		}), nil, "the table row of " + otherSlug() + " changes"},

		{"O2 another project's row is removed", blind(func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				var out []customresources.Project
				for _, p := range ps {
					if p.Slug != otherSlug() {
						out = append(out, p)
					}
				}
				return out
			})
		}), nil, "the table row of " + otherSlug() + " is removed"},
		{"O3 registryDigest is not the registry of the head table", blind(func(t *testing.T, f *onboardingFixture) {
			raw, _ := f.head.Read(cncfRulesPath, MaxFileBytes)
			var m struct {
				RegistryDigest string `json:"registryDigest"`
			}
			json.Unmarshal(raw, &m)
			f.writePack(t, []byte(strings.Replace(string(raw), m.RegistryDigest, obLedger, 1)))
		}), nil, "O3: the head pack's registryDigest is not the registry"},
		// O3: the states and artifacts.
		{"O3 revision bump other than one", blind(func(t *testing.T, f *onboardingFixture) {
			raw, _ := f.head.Read(cncfRulesPath, MaxFileBytes)
			var m struct {
				Revision string `json:"revision"`
			}
			json.Unmarshal(raw, &m)
			next, _ := nextRevision(m.Revision)
			f.writePack(t, []byte(strings.Replace(string(raw), `"revision": "`+m.Revision+`"`, `"revision": "`+next+`"`, 1)))
		}), nil, "O3: the head pack revision must be the base revision plus one"},
		{"O3 target changed after signing", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			editTarget(t, f, func(tg map[string]any) { tg["name"] = "OpenEBS changed" })
		}), nil, "O3: the target file differs"},
		{"O3 head state differs", resigned(func(rec *OnboardingRecord) { rec.Head.TargetsDigest = obLedger }), nil, "O3: the head state differs"},

		// O4: what the base's loaders read.
		{"O4 reserved group", blind(func(t *testing.T, f *onboardingFixture) {
			setGroups("a.storage.synthetic.k8s.io", obGroup)(t, f)
		}), nil, "O4"},
		{"O4 reserved group with a record", blind(func(t *testing.T, f *onboardingFixture) {
			ol := DefaultLayout().Onboarding
			raw, _ := f.head.Read(ol.TablePath, MaxFileBytes)
			projects, reserved, _ := customresources.LoadTable(raw)
			reserved = append(reserved, customresources.ReservedGroup{Name: "a.storage.synthetic.k8s.io", Owner: obSlug, Repository: "https://" + obRepo, Reason: "a synthetic reserved group record"})
			for i := range projects {
				if projects[i].Slug == obSlug {
					projects[i].Groups = append([]customresources.Group{{Name: "a.storage.synthetic.k8s.io", Source: projects[i].Groups[0].Source}}, projects[i].Groups...)
				}
			}
			table, _ := customresources.CanonicalTable(projects, sortReserved(reserved))
			writeFile(t, headFile(f, ol.TablePath), table)
			f.follow(t)
			f.draft.Projects[0].Groups = []string{"a.storage.synthetic.k8s.io", obGroup}
		}), nil, "reserved"},
		{"O4 shared group", blind(func(t *testing.T, f *onboardingFixture) {
			setGroups("crd.antrea.io")(t, f)
		}), nil, "is shared with"},
		{"O4 exclusion under a test directory", blind(func(t *testing.T, f *onboardingFixture) {
			editTarget(t, f, func(tg map[string]any) {
				tg["exclude"] = []any{map[string]any{"path": "test/crds/", "repo": obRepo, "reason": "end-to-end test manifests", "evidence": "the directory holds only the manifests of the end-to-end tests"}}
			})
		}), nil, "may not exclude files"},
		{"O4 exclusion outside a test directory", blind(func(t *testing.T, f *onboardingFixture) {
			editTarget(t, f, func(tg map[string]any) {
				tg["exclude"] = []any{map[string]any{"path": "hack/crds/", "repo": obRepo, "reason": "helper manifests only", "evidence": "the directory holds helper manifests that are never installed by anyone"}}
			})
		}), nil, "may not exclude files"},
		{"O4 a new target attests", blind(func(t *testing.T, f *onboardingFixture) {
			editTarget(t, f, func(tg map[string]any) { tg["attest"] = true })
		}), nil, "a new target may not attest"},
		{"O4 install channels", blind(func(t *testing.T, f *onboardingFixture) {
			editTarget(t, f, func(tg map[string]any) {
				tg["declaredChannel"] = "standard"
				tg["channels"] = []any{map[string]any{"name": "experimental", "paths": []any{map[string]any{"path": "deploy/experimental", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}}}}
			})
		}), nil, "O4"},
		{"O4 repository other than the landscape's", blind(func(t *testing.T, f *onboardingFixture) {
			os.Remove(headFile(f, targetPath(ol, obSlug)))
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				var out []customresources.Project
				for _, p := range ps {
					if p.Slug != obSlug {
						out = append(out, p)
					}
				}
				return out
			})
			f.onboardRow(t, obSlug, strings.ReplaceAll(strings.ReplaceAll(obTargetJSON, obRepo, obRepo+"-fork"), obComp, obComp+"-fork"), obComp+"-fork", obGroup, obCRD)
		}), nil, "is not the landscape repository"},

		// O5: the registry.
		{"O5 facts of another shape", resigned(func(rec *OnboardingRecord) {
			rec.Projects[0].Facts = []string{"component." + obFact + "_other.custom_resource_versions_set"}
		}), nil, "O5: the facts must be exactly"},
		{"O5 a row for a project the batch does not list", blind(func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				return append(ps, customresources.Project{Slug: "opa", Catalog: customresources.CatalogCNCF, FactProject: "opa", Component: "pkg:github/open-policy-agent/opa", Groups: []customresources.Group{{Name: "policy.synthetic.example", Source: "https://github.com/open-policy-agent/opa/blob/" + obTo + "/x.yaml"}}})
			})
		}), nil, "O5: the head registers the fact component.opa"},

		// O6: the gate's own dry run.
		{"O6 offline fixture source", signed(nil), func(o *Options) { o.Source = o.Source.(*obSource).FixtureReader }, "no upstream source that counts its requests"},
		{"O6 over the REST budget", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) { f.src.perList = OnboardingRESTBudget }), nil, "budget"},
		{"O6 a scan finding the proposal did not see", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeUpstream(t, f.upstream, obTo, "hack/stray-crd.yaml", obCRDDoc("stray.synthetic.example", "v1"))
		}), nil, "the scan finds"},
		{"O6 a newer release than the proposal's pair", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			newer := "00000000000000000000000000000000000a1200"
			writeFile(t, filepath.Join(f.upstream, filepath.FromSlash(obRepo), "tags.json"), []byte(`{"v1.0.0": "`+obFrom+`", "v1.1.0": "`+obTo+`", "v1.2.0": "`+newer+`"}`))
			writeUpstream(t, f.upstream, newer, obCRD, obCRDDoc(obGroup, "v1"))
		}), nil, "not the pair the proposal was made on"},
		{"O6 a group its cited file does not declare", blind(setGroups("other.synthetic.example")), nil, "does not declare it"},
		{"O6 a group cited at another commit", blind(func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				for i := range ps {
					if ps[i].Slug == obSlug {
						ps[i].Groups[0].Source = strings.Replace(ps[i].Groups[0].Source, obTo, obFrom, 1)
					}
				}
				return ps
			})
		}), nil, "it must cite the newest pair's later release"},

		{"O6 a group cited in another repository", blind(func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				for i := range ps {
					if ps[i].Slug == obSlug {
						ps[i].Groups[0].Source = strings.Replace(ps[i].Groups[0].Source, obOwnerRepo, obOwnerRepo+"-other", 1)
					}
				}
				return ps
			})
		}), nil, "not a file of " + obRepo},
		{"O6 a group cited outside a listed path", blind(func(t *testing.T, f *onboardingFixture) {
			writeUpstream(t, f.upstream, obTo, "docs/widgets.yaml", obCRDDoc(obGroup, "v1"))
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				for i := range ps {
					if ps[i].Slug == obSlug {
						ps[i].Groups[0].Source = strings.Replace(ps[i].Groups[0].Source, obCRD, "docs/widgets.yaml", 1)
					}
				}
				return ps
			})
		}), nil, "not under a listed path"},
		{"O4 a fact project used twice", blind(func(t *testing.T, f *onboardingFixture) {
			f.editTable(t, func(ps []customresources.Project) []customresources.Project {
				for i := range ps {
					if ps[i].Slug == obSlug {
						ps[i].FactProject = customresources.Projects()[0].FactProject
					}
				}
				return ps
			})
		}), nil, "O4"},
		// O7: the change set, the sample and the summary.
		{"O7 summary digest", resigned(func(rec *OnboardingRecord) { rec.SummaryDigest = obLedger }), nil, "O7: the summary digest"},
		{"O7 change set digest", resigned(func(rec *OnboardingRecord) { rec.ChangeSetDigest = obLedger }), nil, "O7: the change set"},

		// O8: the kill switch; file modes.
		{"O8 kill switch", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			writeFile(t, headFile(f, "factory/PAUSE"), []byte("stop\n"))
		}), nil, "O8: the kill switch is set"},
		{"O2 executable target file", signed(func(t *testing.T, f *onboardingFixture, _ OnboardingRecord) {
			os.Chmod(headFile(f, targetPath(ol, obSlug)), 0o755)
		}), nil, "executable bit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOnboardingFixture(t)
			tc.setup(t, f)
			r := f.gateWith(t, func(o *Options) {
				if tc.opts != nil {
					tc.opts(o)
				}
			})
			if c, ok := check(r, CheckOnboarding); ok {
				t.Logf("%s: %s", CheckOnboarding, c.Detail)
			}
			requireFail(t, r, tc.want)
			for _, ch := range r.Changes {
				if ch.Member != "" && ch.OK {
					t.Fatalf("member change admitted: %+v", ch)
				}
			}
		})
	}
}

func sortReserved(list []customresources.ReservedGroup) []customresources.ReservedGroup {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j-1].Name > list[j].Name; j-- {
			list[j-1], list[j] = list[j], list[j-1]
		}
	}
	return list
}

var _ = extract.PairDerived

// otherSlug is a project of the repository's table other than the fixture's.
func otherSlug() string {
	for _, p := range customresources.Projects() {
		if p.Slug != obSlug {
			return p.Slug
		}
	}
	panic("no other project")
}
