// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// projectCensus compares the actual output with an independent projection of
// admitted source content. It never rebuilds an expected split or serializes
// the complete source pack as an external envelope.
func projectCensus(base bundle, indexTarget ExternalTarget, targets []ExternalTarget) error {
	index, err := ParseExternalIndex(indexTarget.Bytes)
	if err != nil || indexTarget.Path != ExternalIndexTargetPath {
		return fmt.Errorf("index: %v", err)
	}
	type content map[string][]string
	want := map[string]content{}
	ensure := func(project string) content {
		if want[project] == nil {
			want[project] = content{}
		}
		return want[project]
	}
	canonical := func(value any) string {
		raw, _ := json.Marshal(value)
		var decoded any
		_ = json.Unmarshal(raw, &decoded)
		raw, _ = json.Marshal(decoded)
		return string(raw)
	}
	for _, entry := range base.pack.Entries {
		project := ensure(entry.Project) // crossing-only projects retain a target
		crossing, err := constraintengine.AnyCrossingRule([]json.RawMessage{entry.Rule})
		if err != nil {
			return err
		}
		if !crossing {
			project["entries"] = append(project["entries"], canonical(entry))
		}
	}
	owners := map[string]string{}
	for _, project := range base.knowledgeProjects() {
		owners[subjectComponent(project.Slug, project.RepositoryURL)] = project.Slug
	}
	packRaw, err := json.Marshal(base.pack)
	if err != nil {
		return err
	}
	var source map[string]json.RawMessage
	if err := json.Unmarshal(packRaw, &source); err != nil {
		return err
	}
	for field, raw := range source {
		switch field {
		case "schema", "revision", "policyId", "policyDigest", "landscapeFileDigest", "registryDigest", "entries":
		case "lineAttestations", "pathPolicies", "servedAPIs":
			var records []map[string]json.RawMessage
			if err := json.Unmarshal(raw, &records); err != nil {
				return err
			}
			for _, record := range records {
				var component string
				if err := json.Unmarshal(record["component"], &component); err != nil {
					return err
				}
				owner := owners[component]
				if owner == "" {
					return fmt.Errorf("record owner: %s", component)
				}
				project := ensure(owner)
				project[field] = append(project[field], canonical(record))
			}
		default:
			return fmt.Errorf("unaccounted source section %s", field)
		}
	}
	if len(want) != len(targets) || len(index.Entries()) != len(targets) {
		return fmt.Errorf("project census differs")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		project, ok := ProjectFromTargetPath(target.Path)
		if !ok || seen[project] || want[project] == nil {
			return fmt.Errorf("unexpected project %s", project)
		}
		seen[project] = true
		bundle, err := AdmitExternalProjectTarget(index, project, target.Bytes)
		if err != nil {
			return err
		}
		admission, err := bundle.Admission()
		capability, capErr := externalCapabilityDigest(base)
		if err != nil || capErr != nil || admission.Purpose != "operator_provided" || admission.EngineCapabilityDigest != capability || admission.Revision != "73" {
			return fmt.Errorf("project identity differs")
		}
		var envelope externalBundleDocument
		if err := json.Unmarshal(target.Bytes, &envelope); err != nil {
			return err
		}
		var pack map[string]json.RawMessage
		if err := json.Unmarshal(envelope.Pack, &pack); err != nil {
			return err
		}
		got := content{}
		for field, raw := range pack {
			switch field {
			case "schema", "revision":
			case "policyId", "policyDigest", "landscapeFileDigest", "registryDigest":
				if canonical(raw) != canonical(source[field]) {
					return fmt.Errorf("%s changed", field)
				}
			case "entries", "lineAttestations", "pathPolicies", "servedAPIs":
				var records []json.RawMessage
				if err := json.Unmarshal(raw, &records); err != nil {
					return err
				}
				for _, record := range records {
					got[field] = append(got[field], canonical(record))
				}
			default:
				return fmt.Errorf("unaccounted target section %s", field)
			}
		}
		if !reflect.DeepEqual(got, want[project]) {
			return fmt.Errorf("project %s content differs", project)
		}
	}
	return nil
}

func TestProjectExportPreservesCompleteSourceProjection(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	index, targets, err := BuildEmbeddedExternalTargets("73", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := projectCensus(base, index, targets); err != nil {
		t.Fatal(err)
	}
	max := 0
	maxProject := ""
	for _, target := range targets {
		if len(target.Bytes) > max {
			max = len(target.Bytes)
			maxProject, _ = ProjectFromTargetPath(target.Path)
		}
	}
	t.Logf("single bundle no longer produced; per-project sizes max %d B project=%s index=%d B", max, maxProject, len(index.Bytes))
	if max > MaxExternalTargetBytes {
		t.Fatalf("target cap exceeded: %d", max)
	}
	for _, seed := range []string{"missing project", "tampered record", "omitted rule", "recomputed content hashes"} {
		t.Run(seed, func(t *testing.T) {
			mutated := append([]ExternalTarget(nil), targets...)
			mutatedIndex := index
			if seed == "missing project" {
				mutated = mutated[1:]
			} else {
				changed := false
				for i, target := range mutated {
					var envelope externalBundleDocument
					if err := json.Unmarshal(target.Bytes, &envelope); err != nil {
						t.Fatal(err)
					}
					var pack map[string]json.RawMessage
					if err := json.Unmarshal(envelope.Pack, &pack); err != nil {
						t.Fatal(err)
					}
					field := "entries"
					if seed == "tampered record" {
						field = "lineAttestations"
					}
					var records []json.RawMessage
					if len(pack[field]) == 0 || json.Unmarshal(pack[field], &records) != nil || len(records) == 0 {
						continue
					}
					if seed == "recomputed content hashes" {
						var entry map[string]json.RawMessage
						if err := json.Unmarshal(records[0], &entry); err != nil {
							t.Fatal(err)
						}
						entry["description"] = json.RawMessage(`"seeded wrong description"`)
						records[0], _ = json.Marshal(entry)
						pack[field], _ = json.Marshal(records)
					} else {
						pack[field], _ = json.Marshal(records[1:])
					}
					envelope.Pack, _ = json.Marshal(pack)
					mutated[i].Bytes, _ = json.Marshal(envelope)
					if bytes.Equal(target.Bytes, mutated[i].Bytes) {
						t.Fatal("seed did not apply")
					}
					admitted, err := ParseExternalBundle(mutated[i].Bytes)
					if err != nil {
						t.Fatal(err)
					}
					admission, err := admitted.Admission()
					if err != nil {
						t.Fatal(err)
					}
					var document externalIndexDocument
					if err := json.Unmarshal(index.Bytes, &document); err != nil {
						t.Fatal(err)
					}
					for j := range document.Projects {
						if document.Projects[j].TargetPath == target.Path {
							e := &document.Projects[j]
							e.Digest, e.Length, e.RuleDigest = digest(mutated[i].Bytes), int64(len(mutated[i].Bytes)), admission.RuleDigest
						}
					}
					mutatedIndex.Bytes, _ = json.Marshal(document)
					parsed, err := ParseExternalIndex(mutatedIndex.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					project, _ := ProjectFromTargetPath(target.Path)
					if _, err := AdmitExternalProjectTarget(parsed, project, mutated[i].Bytes); err != nil {
						t.Fatalf("seed must pass ordinary hash admission: %v", err)
					}
					changed = true
					break
				}
				if !changed {
					t.Fatal("seed fixture missing")
				}
			}
			if err := projectCensus(base, mutatedIndex, mutated); err == nil {
				t.Fatal("wrong data passed independent census")
			} else if seed != "missing project" && !strings.Contains(err.Error(), "content differs") {
				t.Fatalf("seed did not reach independent content comparison: %v", err)
			}
		})
	}
}

func embeddedProjectEnvelope(t testing.TB, project, revision string) []byte {
	t.Helper()
	_, targets, err := BuildEmbeddedExternalTargets(revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.Path == ProjectTargetPath(project) {
			return target.Bytes
		}
	}
	t.Fatalf("missing project fixture %s", project)
	return nil
}
